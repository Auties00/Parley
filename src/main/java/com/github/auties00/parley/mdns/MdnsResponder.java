package com.github.auties00.parley.mdns;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadFactory;

/// Answers multicast DNS queries for the `<uuid>.local` names that hide local host candidate addresses.
///
/// [#register(InetAddress)] generates a fresh name for an address (one name per address, reused when the same
/// address is registered again), announces it once, and from then on answers `A`, `AAAA` and `ANY` queries for it:
/// with a multicast response to a multicast query, a unicast response to a query with the unicast-response bit, and
/// a legacy unicast response (the query id echoed, the question repeated, a ten-second time to live) to a query
/// from a port other than 5353. Names are not probed, as the mDNS ICE draft allows for UUID names.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6762.html RFC 6762: Multicast DNS
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03 draft-ietf-mmusic-mdns-ice-candidates-03: Using Multicast DNS to protect privacy when exposing ICE candidates
public final class MdnsResponder implements AutoCloseable {
    /// The logger of the responder.
    private static final System.Logger LOGGER = System.getLogger(MdnsResponder.class.getName());

    /// The time to live of a multicast answer, the 120 seconds RFC 6762 section 10 recommends for host records.
    static final long TTL = 120;

    /// The time to live of a legacy unicast answer, at most ten seconds per RFC 6762 section 6.7.
    static final long LEGACY_TTL = 10;

    /// The socket.
    private final MdnsChannel channel;

    /// The registered addresses by name.
    private final Map<String, InetAddress> addresses = new ConcurrentHashMap<>();

    /// The registered names by address.
    private final Map<InetAddress, String> names = new ConcurrentHashMap<>();

    /// Whether [#close()] ran.
    private volatile boolean closed;

    /// Creates a responder over a socket bound to port 5353 and starts its reading thread.
    ///
    /// @param channel       the socket
    /// @param threadFactory the factory of the reading thread
    public MdnsResponder(MdnsChannel channel, ThreadFactory threadFactory) {
        this.channel = Objects.requireNonNull(channel, "channel cannot be null");
        threadFactory.newThread(this::readLoop).start();
    }

    /// {@return a responder on the IPv4 multicast DNS group, joined on every multicast-capable interface that is up}
    ///
    /// @implNote This implementation opens the socket with the JDK directly instead of through a
    /// [com.github.auties00.parley.net.NetworkStack]: answering link-local multicast needs port 5353 shared with the
    /// host's own responder and group membership, which the stack SPI does not model, and the traffic never leaves
    /// the local link, so there is nothing to route through a proxy.
    ///
    /// @param threadFactory the factory of the reading thread
    /// @throws IOException if the socket cannot be bound or no interface can join the group
    public static MdnsResponder openMulticast(ThreadFactory threadFactory) throws IOException {
        return new MdnsResponder(MulticastChannel.open(), threadFactory);
    }

    /// Registers an address under a fresh `<uuid>.local` name, or returns the name it already has.
    ///
    /// @param address the address to hide
    /// @return the name
    public String register(InetAddress address) {
        Objects.requireNonNull(address, "address cannot be null");
        var existing = names.get(address);
        if (existing != null) {
            return existing;
        }
        var name = UUID.randomUUID() + ".local";
        var previous = names.putIfAbsent(address, name);
        if (previous != null) {
            return previous;
        }
        addresses.put(name, address);
        announce(name, address);
        return name;
    }

    /// {@return the address registered under `name`, or `null`}
    InetAddress lookup(String name) {
        return addresses.get(name.toLowerCase(java.util.Locale.ROOT));
    }

    /// Sends one unsolicited multicast response for a new name, ignoring a failure.
    private void announce(String name, InetAddress address) {
        var announcement = new MdnsMessage(0, true, List.of(),
                List.of(MdnsMessage.Answer.address(name, address, TTL, true)));
        try {
            channel.send(announcement.encode(), MdnsChannel.IPV4_GROUP);
        } catch (IOException | RuntimeException exception) {
            if (LOGGER.isLoggable(Level.DEBUG)) {
                LOGGER.log(Level.DEBUG, "cannot announce an mDNS name", exception);
            }
        }
    }

    /// Reads queries until the socket closes, answering the ones about registered names.
    private void readLoop() {
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
            try {
                var query = MdnsMessage.decode(buffer);
                if (!query.response()) {
                    answer(query, source);
                }
            } catch (MdnsFormatException | RuntimeException exception) {
                if (LOGGER.isLoggable(Level.TRACE)) {
                    LOGGER.log(Level.TRACE, "ignoring a malformed mDNS message", exception);
                }
            }
        }
    }

    /// Answers the questions of one query about registered names.
    void answer(MdnsMessage query, InetSocketAddress source) {
        var legacy = source.getPort() != 5353;
        var unicast = legacy;
        var answered = new ArrayList<MdnsMessage.Question>();
        var answers = new ArrayList<MdnsMessage.Answer>();
        for (var question : query.questions()) {
            var address = addresses.get(question.name());
            if (address == null) {
                continue;
            }
            var type = address instanceof Inet4Address ? MdnsMessage.TYPE_A : MdnsMessage.TYPE_AAAA;
            if (question.type() != type && question.type() != MdnsMessage.TYPE_ANY) {
                continue;
            }
            answered.add(question);
            answers.add(MdnsMessage.Answer.address(question.name(), address, legacy ? LEGACY_TTL : TTL, !legacy));
            unicast |= question.unicastResponse();
        }
        if (answers.isEmpty()) {
            return;
        }
        var response = legacy
                ? new MdnsMessage(query.id(), true, answered, answers)
                : new MdnsMessage(0, true, List.of(), answers);
        try {
            channel.send(response.encode(), unicast ? source : MdnsChannel.IPV4_GROUP);
        } catch (IOException exception) {
            if (LOGGER.isLoggable(Level.DEBUG)) {
                LOGGER.log(Level.DEBUG, "cannot send an mDNS answer", exception);
            }
        }
    }

    /// Closes the socket and forgets every name. Calling it again has no effect.
    @Override
    public void close() {
        closed = true;
        channel.close();
        addresses.clear();
        names.clear();
    }

    /// The JDK socket bound to port 5353 and joined to `224.0.0.251`.
    ///
    /// @param channel the socket
    private record MulticastChannel(DatagramChannel channel) implements MdnsChannel {
        /// Binds the socket and joins the group on every usable interface.
        static MulticastChannel open() throws IOException {
            var channel = DatagramChannel.open(StandardProtocolFamily.INET);
            try {
                channel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
                channel.bind(new InetSocketAddress(5353));
                channel.setOption(StandardSocketOptions.IP_MULTICAST_TTL, 255);
                var joined = 0;
                for (var networkInterface : NetworkInterface.networkInterfaces().toList()) {
                    if (!networkInterface.isUp() || !networkInterface.supportsMulticast()) {
                        continue;
                    }
                    var hasIpv4 = networkInterface.inetAddresses().anyMatch(Inet4Address.class::isInstance);
                    if (!hasIpv4) {
                        continue;
                    }
                    try {
                        channel.join(IPV4_GROUP.getAddress(), networkInterface);
                        joined++;
                    } catch (IOException | UnsupportedOperationException _) {
                        // Some adapters refuse membership; the others still answer.
                    }
                }
                if (joined == 0) {
                    throw new IOException("no interface could join the mDNS group");
                }
                return new MulticastChannel(channel);
            } catch (IOException | RuntimeException exception) {
                channel.close();
                throw exception;
            }
        }

        @Override
        public void send(ByteBuffer message, InetSocketAddress target) throws IOException {
            channel.send(message, target);
        }

        @Override
        public InetSocketAddress receive(ByteBuffer destination) throws IOException {
            return (InetSocketAddress) channel.receive(destination);
        }

        @Override
        public int localPort() {
            return 5353;
        }

        @Override
        public void close() {
            try {
                channel.close();
            } catch (IOException _) {
                // A failed close leaves nothing to release.
            }
        }
    }
}
