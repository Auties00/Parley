package com.github.auties00.parley.mdns;

import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.NetworkStack;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadFactory;
import java.util.regex.Pattern;

/// Resolves the `<uuid>.local` names of remote mDNS ICE candidates with one-shot multicast DNS queries.
///
/// A query asks for `A` and `AAAA` with the unicast-response bit set, from an ephemeral port, so responders answer
/// the resolver directly. Only names in the format the mDNS ICE draft defines (a version 4 UUID followed by
/// `.local`) are resolved, and a name that answers with more than one address resolves to nothing, as the draft
/// recommends. Answers are cached for their time to live.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6762.html RFC 6762: Multicast DNS
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03 draft-ietf-mmusic-mdns-ice-candidates-03: Using Multicast DNS to protect privacy when exposing ICE candidates
public final class MdnsResolver implements AutoCloseable {
    /// The format of the names the resolver accepts.
    private static final Pattern ICE_NAME = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.local$");

    /// How often a query is repeated while the resolver waits, the one-second interval of RFC 6762 section 5.2.
    private static final long REPEAT_NANOS = Duration.ofSeconds(1).toNanos();

    /// The socket.
    private final MdnsChannel channel;

    /// The outstanding lookups by name.
    private final Map<String, Lookup> lookups = new ConcurrentHashMap<>();

    /// The cached answers by name.
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    /// The source of query ids.
    private final SecureRandom random = new SecureRandom();

    /// Whether [#close()] ran.
    private volatile boolean closed;

    /// Creates a resolver over a socket and starts its reading thread.
    ///
    /// @param channel       the socket
    /// @param threadFactory the factory of the reading thread
    public MdnsResolver(MdnsChannel channel, ThreadFactory threadFactory) {
        this.channel = Objects.requireNonNull(channel, "channel cannot be null");
        threadFactory.newThread(this::readLoop).start();
    }

    /// {@return a resolver whose socket is an ephemeral UDP port of `stack`}
    ///
    /// @param stack the network stack
    /// @throws IOException if the socket cannot be bound
    public static MdnsResolver open(NetworkStack stack) throws IOException {
        var endpoint = stack.bindUdp(new InetSocketAddress(InetAddress.ofLiteral("0.0.0.0"), 0));
        return new MdnsResolver(new EndpointChannel(endpoint), stack.threadFactory());
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
        var cached = cache.get(key);
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

    /// Sends a one-shot query for `A` and `AAAA`, ignoring a failure (the next repeat may succeed).
    private void sendQuery(String name) {
        var query = new MdnsMessage(random.nextInt(0x10000), false, List.of(
                new MdnsMessage.Question(name, MdnsMessage.TYPE_A, true),
                new MdnsMessage.Question(name, MdnsMessage.TYPE_AAAA, true)), List.of());
        try {
            channel.send(query.encode(), MdnsChannel.IPV4_GROUP);
        } catch (IOException | RuntimeException _) {
            // A lost query is repeated after a second.
        }
    }

    /// Reads responses until the socket closes, completing the lookups they answer.
    private void readLoop() {
        var buffer = ByteBuffer.allocate(MdnsMessage.MAX_LENGTH);
        while (!closed) {
            buffer.clear();
            try {
                channel.receive(buffer);
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
            var byName = new java.util.HashMap<String, List<InetAddress>>();
            var ttls = new java.util.HashMap<String, Long>();
            for (var answer : message.answers()) {
                var address = answer.address();
                if (address != null) {
                    byName.computeIfAbsent(answer.name(), _ -> new ArrayList<>()).add(address);
                    ttls.merge(answer.name(), answer.ttl(), Math::min);
                }
            }
            byName.forEach((name, addresses) -> {
                var distinct = addresses.stream().distinct().toList();
                if (distinct.size() == 1) {
                    var ttl = Math.min(ttls.get(name), 120);
                    cache.put(name, new Cached(distinct.getFirst(), System.nanoTime() + Duration.ofSeconds(ttl).toNanos()));
                }
                var lookup = lookups.get(name);
                if (lookup != null) {
                    lookup.complete(distinct);
                }
            });
        }
    }

    /// Closes the socket; lookups in progress return an empty optional. Calling it again has no effect.
    @Override
    public void close() {
        closed = true;
        channel.close();
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

    /// A channel over a [DatagramEndpoint] of a [NetworkStack].
    ///
    /// @param endpoint the endpoint
    private record EndpointChannel(DatagramEndpoint endpoint) implements MdnsChannel {
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
