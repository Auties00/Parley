package com.github.auties00.parley.mdns;

import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.NetworkInterfaceAddress;
import com.github.auties00.parley.net.NetworkStack;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadFactory;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/// Resolves the `<uuid>.local` names of remote mDNS ICE candidates with one-shot multicast DNS queries.
///
/// A query asks for `A` and `AAAA` with the unicast-response bit set, from an ephemeral port, so responders answer
/// the resolver directly; it goes to the group of each socket's family, `224.0.0.251` and, when an IPv6 socket could be
/// opened, `[ff02::fb]`. Only names in the format the mDNS ICE draft defines (a version 4 UUID followed by `.local`)
/// are resolved, and a name that answers with more than one address resolves to nothing, as the draft recommends.
///
/// Answers are untrusted: one is accepted only for a name a lookup is waiting for, and only from an on-link source
/// (RFC 6762 section 11), so a host elsewhere cannot plant mappings. Accepted answers are cached for their time to
/// live, at most two minutes, in a cache of at most [#CACHE_CAPACITY] names that evicts the least recently used.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6762.html RFC 6762: Multicast DNS
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03 draft-ietf-mmusic-mdns-ice-candidates-03: Using Multicast DNS to protect privacy when exposing ICE candidates
public final class MdnsResolver implements AutoCloseable {
    /// The most names the cache holds.
    public static final int CACHE_CAPACITY = 256;

    /// The format of the names the resolver accepts.
    private static final Pattern ICE_NAME = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.local$");

    /// How often a query is repeated while the resolver waits, the one-second interval of RFC 6762 section 5.2.
    private static final long REPEAT_NANOS = Duration.ofSeconds(1).toNanos();

    /// How long the interface prefixes of [#open(NetworkStack)] are reused before they are enumerated again.
    private static final long PREFIX_REFRESH_NANOS = Duration.ofSeconds(10).toNanos();

    /// The sources accepted by [#MdnsResolver(MdnsChannel,ThreadFactory)]: addresses that never leave a site, which
    /// is where a responder on the local link answers from.
    private static final Predicate<InetAddress> PRIVATE_SCOPE = address -> address.isLoopbackAddress()
            || address.isLinkLocalAddress() || address.isSiteLocalAddress()
            || (address instanceof Inet6Address && (address.getAddress()[0] & 0xFE) == 0xFC);

    /// The sockets, one per address family.
    private final List<MdnsChannel> channels;

    /// Whether a source address is on a local link.
    private final Predicate<InetAddress> onLink;

    /// The outstanding lookups by name.
    private final Map<String, Lookup> lookups = new ConcurrentHashMap<>();

    /// The cached answers by name, least recently used first; guarded by itself.
    private final LinkedHashMap<String, Cached> cache = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) {
            return size() > CACHE_CAPACITY;
        }
    };

    /// The source of query ids.
    private final SecureRandom random = new SecureRandom();

    /// The answers dropped because no lookup waited for them or their source was not on-link.
    private final java.util.concurrent.atomic.AtomicLong rejectedAnswers = new java.util.concurrent.atomic.AtomicLong();

    /// Whether [#close()] ran.
    private volatile boolean closed;

    /// Creates a resolver over a socket and starts its reading thread; it accepts answers from loopback, link-local,
    /// private (`10/8`, `172.16/12`, `192.168/16`) and unique local (`fc00::/7`) sources.
    ///
    /// @param channel       the socket
    /// @param threadFactory the factory of the reading thread
    public MdnsResolver(MdnsChannel channel, ThreadFactory threadFactory) {
        this(List.of(Objects.requireNonNull(channel, "channel cannot be null")), threadFactory, PRIVATE_SCOPE);
    }

    /// Creates a resolver over several sockets and starts one reading thread for each.
    ///
    /// @param channels      the sockets, not empty; each sends queries to its [MdnsChannel#group()]
    /// @param threadFactory the factory of the reading threads
    /// @param onLink        whether an answer's source address is on a local link
    /// @throws IllegalArgumentException if `channels` is empty
    public MdnsResolver(List<MdnsChannel> channels, ThreadFactory threadFactory, Predicate<InetAddress> onLink) {
        this.channels = List.copyOf(channels);
        this.onLink = Objects.requireNonNull(onLink, "onLink cannot be null");
        if (this.channels.isEmpty()) {
            throw new IllegalArgumentException("a resolver needs a socket");
        }
        for (var channel : this.channels) {
            threadFactory.newThread(() -> readLoop(channel)).start();
        }
    }

    /// {@return a resolver whose sockets are ephemeral UDP ports of `stack`, an IPv4 one and, when it can be bound, an
    /// IPv6 one, accepting answers from the subnets of the stack's interfaces and from link-local sources}
    ///
    /// @param stack the network stack
    /// @throws IOException if the IPv4 socket cannot be bound
    public static MdnsResolver open(NetworkStack stack) throws IOException {
        var channels = new ArrayList<MdnsChannel>(2);
        channels.add(new EndpointChannel(stack.bindUdp(new InetSocketAddress(InetAddress.ofLiteral("0.0.0.0"), 0)),
                MdnsChannel.IPV4_GROUP));
        try {
            channels.add(new EndpointChannel(stack.bindUdp(new InetSocketAddress(InetAddress.ofLiteral("::"), 0)),
                    MdnsChannel.IPV6_GROUP));
        } catch (IOException | RuntimeException _) {
            // No IPv6 on this host: queries go over IPv4 only.
        }
        return new MdnsResolver(channels, stack.threadFactory(), new InterfaceSubnets(stack));
    }

    /// {@return whether `name` has the format of an mDNS ICE candidate name, `<uuid v4>.local`}
    ///
    /// @param name the name, compared case-insensitively
    public static boolean isIceName(String name) {
        return ICE_NAME.matcher(name.toLowerCase(Locale.ROOT)).matches();
    }

    /// Resolves a name, blocking until an answer arrives or the timeout elapses.
    ///
    /// @param name    the name, `<uuid>.local`
    /// @param timeout the longest time to wait
    /// @return the address, or an empty optional when the name is not an ICE name, nobody answered, or the answer
    ///         held more than one address
    /// @throws InterruptedException if the calling thread is interrupted
    public Optional<InetAddress> resolve(String name, Duration timeout) throws InterruptedException {
        Objects.requireNonNull(name, "name cannot be null");
        Objects.requireNonNull(timeout, "timeout cannot be null");
        var key = name.toLowerCase(Locale.ROOT);
        if (closed || !isIceName(key)) {
            return Optional.empty();
        }
        Cached cached;
        synchronized (cache) {
            cached = cache.get(key);
        }
        if (cached != null && cached.expiresAt - System.nanoTime() > 0) {
            return Optional.of(cached.address);
        }
        var lookup = lookups.computeIfAbsent(key, _ -> new Lookup());
        var deadline = System.nanoTime() + timeout.toNanos();
        try {
            while (true) {
                var now = System.nanoTime();
                if (deadline - now <= 0 || closed) {
                    return Optional.empty();
                }
                sendQuery(key);
                var result = lookup.await(Math.min(REPEAT_NANOS, deadline - now));
                if (result != null) {
                    return result.size() == 1 ? Optional.of(result.getFirst()) : Optional.empty();
                }
            }
        } finally {
            lookups.remove(key, lookup);
        }
    }

    /// {@return the number of names cached}
    int cachedNames() {
        synchronized (cache) {
            return cache.size();
        }
    }

    /// {@return the answers dropped because no lookup waited for their name or their source was not on-link}
    long rejectedAnswers() {
        return rejectedAnswers.get();
    }

    /// Sends a one-shot query for `A` and `AAAA` on every socket, ignoring a failure (the next repeat may succeed).
    private void sendQuery(String name) {
        var query = new MdnsMessage(random.nextInt(0x10000), false, List.of(
                new MdnsMessage.Question(name, MdnsMessage.TYPE_A, true),
                new MdnsMessage.Question(name, MdnsMessage.TYPE_AAAA, true)), List.of());
        for (var channel : channels) {
            try {
                channel.send(query.encode(), channel.group());
            } catch (IOException | RuntimeException _) {
                // A lost query is repeated after a second.
            }
        }
    }

    /// Reads responses from one socket until it closes, completing the lookups they answer.
    private void readLoop(MdnsChannel channel) {
        var buffer = ByteBuffer.allocate(MdnsMessage.MAX_LENGTH);
        while (!closed) {
            buffer.clear();
            InetSocketAddress source;
            try {
                source = channel.receive(buffer);
            } catch (IOException exception) {
                return;
            }
            buffer.flip();
            MdnsMessage message;
            try {
                message = MdnsMessage.decode(buffer);
            } catch (MdnsFormatException exception) {
                continue;
            }
            if (!message.response()) {
                continue;
            }
            if (source == null || source.getAddress() == null || !onLink.test(source.getAddress())) {
                rejectedAnswers.incrementAndGet();
                continue;
            }
            var byName = new HashMap<String, List<InetAddress>>();
            var ttls = new HashMap<String, Long>();
            for (var answer : message.answers()) {
                var address = answer.address();
                if (address == null) {
                    continue;
                }
                var name = answer.name().toLowerCase(Locale.ROOT);
                if (!lookups.containsKey(name)) {
                    rejectedAnswers.incrementAndGet();
                    continue;
                }
                byName.computeIfAbsent(name, _ -> new ArrayList<>()).add(address);
                ttls.merge(name, answer.ttl(), Math::min);
            }
            byName.forEach((name, addresses) -> {
                var distinct = addresses.stream().distinct().toList();
                if (distinct.size() == 1) {
                    var ttl = Math.min(ttls.get(name), 120);
                    var entry = new Cached(distinct.getFirst(), System.nanoTime() + Duration.ofSeconds(ttl).toNanos());
                    synchronized (cache) {
                        cache.put(name, entry);
                    }
                }
                var lookup = lookups.get(name);
                if (lookup != null) {
                    lookup.complete(distinct);
                }
            });
        }
    }

    /// Closes the sockets; lookups in progress return an empty optional. Calling it again has no effect.
    @Override
    public void close() {
        closed = true;
        channels.forEach(MdnsChannel::close);
        lookups.values().forEach(lookup -> lookup.complete(List.of()));
    }

    /// A cached answer.
    ///
    /// @param address   the address
    /// @param expiresAt the [System#nanoTime()] the answer expires at
    private record Cached(InetAddress address, long expiresAt) {
    }

    /// An outstanding lookup.
    private static final class Lookup {
        /// The lock guarding [#result].
        private final Object lock = new Object();

        /// The addresses answered, or `null` before an answer; guarded by [#lock].
        private List<InetAddress> result;

        /// Records an answer and wakes the waiting threads.
        void complete(List<InetAddress> addresses) {
            synchronized (lock) {
                if (result == null) {
                    result = List.copyOf(addresses);
                    lock.notifyAll();
                }
            }
        }

        /// {@return the answer, or `null` when `nanos` elapsed first}
        List<InetAddress> await(long nanos) throws InterruptedException {
            var deadline = System.nanoTime() + nanos;
            synchronized (lock) {
                while (result == null) {
                    var left = deadline - System.nanoTime();
                    if (left <= 0) {
                        return null;
                    }
                    java.util.concurrent.TimeUnit.NANOSECONDS.timedWait(lock, left);
                }
                return result;
            }
        }
    }

    /// Whether an address is on the link of a local interface: loopback, link-local, or inside the subnet of one of the
    /// stack's interface addresses, which are enumerated again at most every ten seconds.
    private static final class InterfaceSubnets implements Predicate<InetAddress> {
        /// The stack whose interfaces are read.
        private final NetworkStack stack;

        /// The interface addresses last read; guarded by this object.
        private List<NetworkInterfaceAddress> addresses = List.of();

        /// The [System#nanoTime()] of the last read; guarded by this object.
        private long readAt = Long.MIN_VALUE / 2;

        /// Creates the predicate.
        private InterfaceSubnets(NetworkStack stack) {
            this.stack = stack;
        }

        @Override
        public boolean test(InetAddress source) {
            if (source.isLoopbackAddress() || source.isLinkLocalAddress()) {
                return true;
            }
            for (var local : current()) {
                if (sameSubnet(local.address(), source, local.prefixLength())) {
                    return true;
                }
            }
            return false;
        }

        /// {@return the interface addresses, read again when the last read is older than ten seconds}
        private List<NetworkInterfaceAddress> current() {
            synchronized (this) {
                var now = System.nanoTime();
                if (now - readAt > PREFIX_REFRESH_NANOS) {
                    try {
                        addresses = stack.interfaceAddresses();
                    } catch (IOException _) {
                        addresses = List.of();
                    }
                    readAt = now;
                }
                return addresses;
            }
        }

        /// {@return whether two addresses of the same family share their first `prefixLength` bits}
        private static boolean sameSubnet(InetAddress local, InetAddress source, int prefixLength) {
            if ((local instanceof Inet4Address) != (source instanceof Inet4Address)) {
                return false;
            }
            var first = local.getAddress();
            var second = source.getAddress();
            var whole = prefixLength / 8;
            for (var index = 0; index < whole; index++) {
                if (first[index] != second[index]) {
                    return false;
                }
            }
            var rest = prefixLength % 8;
            if (rest == 0) {
                return true;
            }
            var mask = (0xFF << (8 - rest)) & 0xFF;
            return (first[whole] & mask) == (second[whole] & mask);
        }
    }

    /// A channel over a [DatagramEndpoint] of a [NetworkStack].
    ///
    /// @param endpoint the endpoint
    /// @param group    the group queries go to
    private record EndpointChannel(DatagramEndpoint endpoint, InetSocketAddress group) implements MdnsChannel {
        @Override
        public void send(ByteBuffer message, InetSocketAddress target) throws IOException {
            endpoint.send(message, target);
        }

        @Override
        public InetSocketAddress receive(ByteBuffer destination) throws IOException {
            return endpoint.receive(destination);
        }

        @Override
        public int localPort() {
            return endpoint.localAddress().getPort();
        }

        @Override
        public void close() {
            endpoint.close();
        }
    }
}
