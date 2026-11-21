package com.github.auties00.parley.turn;

import com.github.auties00.parley.stun.StunAddressFamily;
import com.github.auties00.parley.stun.StunAttribute;
import com.github.auties00.parley.stun.StunAttribute.ErrorCode;
import com.github.auties00.parley.stun.StunClass;
import com.github.auties00.parley.stun.StunFormatException;
import com.github.auties00.parley.stun.StunIntegrity;
import com.github.auties00.parley.stun.StunKey;
import com.github.auties00.parley.stun.StunMessage;
import com.github.auties00.parley.stun.StunMethod;
import com.github.auties00.parley.stun.StunPasswordAlgorithm;

import javax.net.ssl.SSLServerSocket;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/// A STUN and TURN server for tests: Binding, and Allocate, Refresh, CreatePermission, ChannelBind, Send and Data
/// indications and ChannelData, over UDP, TCP and TLS (a self-signed certificate for `localhost`, trusted by
/// [TestCertificates#clientContext()]), on the loopback interface.
///
/// It authenticates with the long-term credential mechanism (user [#USERNAME], password [#PASSWORD], realm
/// [#REALM]), optionally requiring the SHA-256 password algorithm, and can be told to answer the next authenticated
/// request with 438 Stale Nonce or to refuse `DONT-FRAGMENT`. Counters let tests observe what clients did. Relayed
/// addresses are on `127.0.0.1`, or `::1` for IPv6 allocations.
public final class TestTurnServer implements AutoCloseable {
    /// The username the server accepts.
    public static final String USERNAME = "parley";

    /// The password the server accepts.
    public static final String PASSWORD = "secret-password";

    /// The realm of the challenges.
    public static final String REALM = "parley.test";

    /// The UDP socket.
    private final DatagramChannel udp;

    /// The TCP listener.
    private final ServerSocketChannel tcp;

    /// The TLS listener.
    private final SSLServerSocket tls;

    /// The allocations by client key.
    private final Map<String, Allocation> allocations = new ConcurrentHashMap<>();

    /// The open stream connections, closed with the server.
    private final List<AutoCloseable> connections = new CopyOnWriteArrayList<>();

    /// The source of nonces.
    private final SecureRandom random = new SecureRandom();

    /// Whether [#close()] ran.
    private final AtomicBoolean closed = new AtomicBoolean();

    /// The current nonce.
    private volatile String nonce;

    /// Whether the SHA-256 password algorithm is required.
    private volatile boolean requireSha256;

    /// Whether the next authenticated request gets 438.
    private final AtomicBoolean staleNonceOnce = new AtomicBoolean();

    /// Whether `DONT-FRAGMENT` is refused with 420.
    private volatile boolean rejectDontFragment;

    /// Whether every message from clients is ignored, as if the server were unreachable.
    private volatile boolean silent;

    /// The server Allocate requests are redirected to with 300 Try Alternate, or `null`.
    private volatile InetSocketAddress redirect;

    /// The last Allocate request answered.
    private volatile StunMessage lastAllocate;

    /// Send indications that carried `DONT-FRAGMENT`.
    private final AtomicInteger dontFragmentIndications = new AtomicInteger();

    /// Counters.
    private final AtomicInteger bindings = new AtomicInteger();

    /// Allocations created.
    private final AtomicInteger allocationCount = new AtomicInteger();

    /// Refreshes with a nonzero lifetime.
    private final AtomicInteger refreshes = new AtomicInteger();

    /// Refreshes with a zero lifetime.
    private final AtomicInteger deallocations = new AtomicInteger();

    /// CreatePermission requests.
    private final AtomicInteger permissionRequests = new AtomicInteger();

    /// ChannelBind requests.
    private final AtomicInteger channelBinds = new AtomicInteger();

    /// Send indications relayed.
    private final AtomicInteger sendIndications = new AtomicInteger();

    /// ChannelData messages relayed.
    private final AtomicInteger channelDataMessages = new AtomicInteger();

    /// 401 challenges sent.
    private final AtomicInteger challenges = new AtomicInteger();

    /// Binds the three listeners and starts their threads.
    private TestTurnServer() throws IOException {
        var loopback = InetAddress.ofLiteral("127.0.0.1");
        udp = DatagramChannel.open();
        udp.bind(new InetSocketAddress(loopback, 0));
        tcp = ServerSocketChannel.open();
        tcp.bind(new InetSocketAddress(loopback, 0));
        tls = (SSLServerSocket) TestCertificates.serverContext().getServerSocketFactory().createServerSocket(0, 50, loopback);
        nonce = newNonce();
        Thread.ofVirtual().name("test-turn-udp").start(this::udpLoop);
        Thread.ofVirtual().name("test-turn-tcp").start(this::tcpAcceptLoop);
        Thread.ofVirtual().name("test-turn-tls").start(this::tlsAcceptLoop);
    }

    /// {@return a started server}
    ///
    /// @throws IOException if a socket cannot be bound
    public static TestTurnServer start() throws IOException {
        return new TestTurnServer();
    }

    /// {@return the UDP address}
    public InetSocketAddress udpAddress() {
        return localAddress(udp);
    }

    /// {@return the TCP address}
    public InetSocketAddress tcpAddress() {
        try {
            return (InetSocketAddress) tcp.getLocalAddress();
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    /// {@return the TLS address}
    public InetSocketAddress tlsAddress() {
        return new InetSocketAddress(tls.getInetAddress(), tls.getLocalPort());
    }

    /// {@return the server as a [TurnServer] over a transport; TLS names `localhost`, which the certificate covers}
    ///
    /// @param transport the transport
    public TurnServer turnServer(TurnTransport transport) {
        return switch (transport) {
            case UDP -> new TurnServer("127.0.0.1", udpAddress().getPort(), TurnTransport.UDP);
            case TCP -> new TurnServer("127.0.0.1", tcpAddress().getPort(), TurnTransport.TCP);
            case TLS -> new TurnServer("localhost", tlsAddress().getPort(), TurnTransport.TLS);
        };
    }

    /// {@return the `turn:` or `turns:` URI of a transport}
    ///
    /// @param transport the transport
    public URI turnUri(TurnTransport transport) {
        return turnServer(transport).toUri();
    }

    /// {@return the `stun:` URI of the UDP listener}
    public URI stunUri() {
        return URI.create("stun:127.0.0.1:" + udpAddress().getPort());
    }

    /// {@return the credentials the server accepts}
    public TurnCredentials credentials() {
        return new TurnCredentials(USERNAME, PASSWORD);
    }

    /// Requires the SHA-256 password algorithm: challenges carry the nonce cookie and `PASSWORD-ALGORITHMS`.
    ///
    /// @param required whether it is required
    public void requireSha256(boolean required) {
        requireSha256 = required;
        nonce = newNonce();
    }

    /// Answers the next authenticated request with 438 Stale Nonce and a fresh nonce.
    public void staleNonceOnce() {
        staleNonceOnce.set(true);
    }

    /// Refuses Allocate requests with `DONT-FRAGMENT` with 420 Unknown Attribute.
    ///
    /// @param reject whether to refuse
    public void rejectDontFragment(boolean reject) {
        rejectDontFragment = reject;
    }

    /// Ignores every message from clients while set, as if the server were unreachable.
    ///
    /// @param silent whether to ignore messages
    public void silent(boolean silent) {
        this.silent = silent;
    }

    /// Answers every Allocate request with 300 Try Alternate naming `alternate`, or stops when `null`.
    ///
    /// @param alternate the server to redirect to
    public void redirectTo(InetSocketAddress alternate) {
        redirect = alternate;
    }

    /// {@return the last Allocate request this server answered, if any}
    public Optional<StunMessage> lastAllocate() {
        return Optional.ofNullable(lastAllocate);
    }

    /// {@return the Send indications that carried `DONT-FRAGMENT`}
    public int dontFragmentIndications() {
        return dontFragmentIndications.get();
    }

    /// {@return the Binding requests answered}
    public int bindings() {
        return bindings.get();
    }

    /// {@return the allocations created}
    public int allocations() {
        return allocationCount.get();
    }

    /// {@return the allocations currently held}
    public int activeAllocations() {
        return allocations.size();
    }

    /// {@return the refreshes with a nonzero lifetime}
    public int refreshes() {
        return refreshes.get();
    }

    /// {@return the zero-lifetime refreshes that deleted an allocation}
    public int deallocations() {
        return deallocations.get();
    }

    /// {@return the CreatePermission requests granted}
    public int permissionRequests() {
        return permissionRequests.get();
    }

    /// {@return the ChannelBind requests granted}
    public int channelBinds() {
        return channelBinds.get();
    }

    /// {@return the Send indications relayed}
    public int sendIndications() {
        return sendIndications.get();
    }

    /// {@return the ChannelData messages relayed from clients}
    public int channelDataMessages() {
        return channelDataMessages.get();
    }

    /// {@return the 401 challenges sent}
    public int challenges() {
        return challenges.get();
    }

    /// {@return the relayed addresses of the current allocations}
    public List<InetSocketAddress> relayedAddresses() {
        return allocations.values().stream().map(allocation -> localAddress(allocation.relay)).toList();
    }

    /// {@return a nonce, with the cookie announcing the password algorithms feature when SHA-256 is required}
    private String newNonce() {
        var bytes = new byte[8];
        random.nextBytes(bytes);
        var value = HexFormat.of().formatHex(bytes);
        return requireSha256 ? StunAttribute.Nonce.COOKIE_PREFIX + "gAAA" + value : value;
    }

    /// Reads UDP datagrams from clients.
    private void udpLoop() {
        var buffer = ByteBuffer.allocate(0x10000);
        while (!closed.get()) {
            buffer.clear();
            InetSocketAddress source;
            try {
                source = (InetSocketAddress) udp.receive(buffer);
            } catch (IOException exception) {
                return;
            }
            buffer.flip();
            var client = new Client("udp:" + source, source, false, message -> udp.send(message, source));
            handle(client, buffer);
        }
    }

    /// Accepts TCP clients.
    private void tcpAcceptLoop() {
        while (!closed.get()) {
            SocketChannel channel;
            try {
                channel = tcp.accept();
            } catch (IOException exception) {
                return;
            }
            connections.add(channel);
            var socket = channel.socket();
            Thread.ofVirtual().start(() -> streamLoop(socket, "tcp:"));
        }
    }

    /// Accepts TLS clients.
    private void tlsAcceptLoop() {
        while (!closed.get()) {
            Socket socket;
            try {
                socket = tls.accept();
            } catch (IOException exception) {
                return;
            }
            connections.add(socket);
            Thread.ofVirtual().start(() -> streamLoop(socket, "tls:"));
        }
    }

    /// Reads framed messages from a stream client.
    private void streamLoop(Socket socket, String prefix) {
        var source = (InetSocketAddress) socket.getRemoteSocketAddress();
        try {
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            var lock = new Object();
            var client = new Client(prefix + source, source, true, message -> {
                synchronized (lock) {
                    var bytes = new byte[message.remaining()];
                    message.get(bytes);
                    output.write(bytes);
                    output.flush();
                }
            });
            var header = new byte[4];
            while (!closed.get()) {
                readFully(input, header, 0, 4);
                var first = header[0] & 0xFF;
                var length = (header[2] & 0xFF) << 8 | (header[3] & 0xFF);
                int frame;
                int message;
                if (first < 0x40) {
                    frame = 20 + length;
                    message = frame;
                } else {
                    message = 4 + length;
                    frame = 4 + ((length + 3) & ~3);
                }
                var bytes = new byte[frame];
                System.arraycopy(header, 0, bytes, 0, 4);
                readFully(input, bytes, 4, frame - 4);
                handle(client, ByteBuffer.wrap(bytes, 0, message));
            }
        } catch (IOException exception) {
            var allocation = allocations.remove(prefix + source);
            if (allocation != null) {
                allocation.close();
            }
        }
    }

    /// Reads exactly `length` bytes.
    private static void readFully(InputStream input, byte[] bytes, int offset, int length) throws IOException {
        var read = 0;
        while (read < length) {
            var count = input.read(bytes, offset + read, length - read);
            if (count < 0) {
                throw new EOFException();
            }
            read += count;
        }
    }

    /// Handles one message from a client.
    private void handle(Client client, ByteBuffer packet) {
        if (silent) {
            return;
        }
        try {
            var first = packet.get(packet.position()) & 0xFF;
            if (first >= 0x40 && first < 0x50) {
                relayChannelData(client, packet);
                return;
            }
            if (!StunMessage.isStun(packet)) {
                return;
            }
            var message = StunMessage.decode(packet);
            if (message.method() == StunMethod.BINDING && message.messageClass() == StunClass.REQUEST) {
                bindings.incrementAndGet();
                var response = message.successResponse(List.of(new StunAttribute.XorMappedAddress(client.address())));
                client.send(response.encode(true));
                return;
            }
            if (message.method() == StunMethod.SEND && message.messageClass() == StunClass.INDICATION) {
                relaySend(client, message);
                return;
            }
            if (message.messageClass() != StunClass.REQUEST) {
                return;
            }
            var key = authenticate(client, message);
            if (key.isEmpty()) {
                return;
            }
            var integrity = message.integrity().orElse(StunIntegrity.HMAC_SHA1);
            var response = switch (message.method()) {
                case ALLOCATE -> allocate(client, message);
                case REFRESH -> refresh(client, message);
                case CREATE_PERMISSION -> createPermission(client, message);
                case CHANNEL_BIND -> channelBind(client, message);
                default -> message.errorResponse(ErrorCode.BAD_REQUEST, "Bad Request", List.of());
            };
            client.send(response.encode(key.get(), integrity, true));
        } catch (StunFormatException exception) {
            // A malformed message is dropped.
        } catch (IOException exception) {
            // The client went away.
        }
    }

    /// {@return the key of an authenticated request, or an empty optional after sending the challenge or error}
    private Optional<StunKey> authenticate(Client client, StunMessage request) throws IOException {
        if (request.integrity().isEmpty()) {
            challenges.incrementAndGet();
            client.send(challenge(request, ErrorCode.UNAUTHENTICATED, "Unauthenticated").encode(true));
            return Optional.empty();
        }
        var username = request.attribute(StunAttribute.Username.class).map(StunAttribute.Username::value);
        var realm = request.attribute(StunAttribute.Realm.class).map(StunAttribute.Realm::value);
        var requestNonce = request.attribute(StunAttribute.Nonce.class).map(StunAttribute.Nonce::value);
        if (username.isEmpty() || realm.isEmpty() || requestNonce.isEmpty()) {
            client.send(request.errorResponse(ErrorCode.BAD_REQUEST, "Bad Request", List.of()).encode(true));
            return Optional.empty();
        }
        if (!requestNonce.get().equals(nonce) || staleNonceOnce.compareAndSet(true, false)) {
            nonce = newNonce();
            client.send(challenge(request, ErrorCode.STALE_NONCE, "Stale Nonce").encode(true));
            return Optional.empty();
        }
        var algorithm = request.attribute(StunAttribute.PasswordAlgorithm.class)
                .flatMap(value -> StunPasswordAlgorithm.ofCode(value.algorithm()))
                .orElse(StunPasswordAlgorithm.MD5);
        if (requireSha256 && (algorithm != StunPasswordAlgorithm.SHA_256 || request.integrity().get() != StunIntegrity.HMAC_SHA256)) {
            client.send(request.errorResponse(ErrorCode.BAD_REQUEST, "Bad Request", List.of()).encode(true));
            return Optional.empty();
        }
        if (!username.get().equals(USERNAME) || !realm.get().equals(REALM)) {
            challenges.incrementAndGet();
            client.send(challenge(request, ErrorCode.UNAUTHENTICATED, "Unauthenticated").encode(true));
            return Optional.empty();
        }
        var key = StunKey.longTerm(USERNAME, REALM, PASSWORD, algorithm);
        if (!request.verifyIntegrity(key)) {
            challenges.incrementAndGet();
            client.send(challenge(request, ErrorCode.UNAUTHENTICATED, "Unauthenticated").encode(true));
            return Optional.empty();
        }
        return Optional.of(key);
    }

    /// {@return a 401 or 438 error response with the realm, nonce and, when SHA-256 is required, the algorithms}
    private StunMessage challenge(StunMessage request, int code, String reason) {
        var attributes = new ArrayList<StunAttribute>();
        attributes.add(new StunAttribute.Realm(REALM));
        attributes.add(new StunAttribute.Nonce(nonce));
        if (requireSha256) {
            attributes.add(new StunAttribute.PasswordAlgorithms(List.of(StunPasswordAlgorithm.SHA_256.code(),
                    StunPasswordAlgorithm.MD5.code())));
        }
        return request.errorResponse(code, reason, attributes);
    }

    /// Handles Allocate.
    private StunMessage allocate(Client client, StunMessage request) throws IOException {
        lastAllocate = request;
        var alternate = redirect;
        if (alternate != null) {
            return request.errorResponse(ErrorCode.TRY_ALTERNATE, "Try Alternate",
                    List.of(new StunAttribute.AlternateServer(alternate)));
        }
        if (allocations.containsKey(client.key())) {
            return request.errorResponse(ErrorCode.ALLOCATION_MISMATCH, "Allocation Mismatch", List.of());
        }
        var transport = request.attribute(StunAttribute.RequestedTransport.class);
        if (transport.isEmpty()) {
            return request.errorResponse(ErrorCode.BAD_REQUEST, "Bad Request", List.of());
        }
        if (transport.get().protocol() != StunAttribute.RequestedTransport.UDP) {
            return request.errorResponse(ErrorCode.UNSUPPORTED_TRANSPORT_PROTOCOL, "Unsupported Transport Protocol", List.of());
        }
        if (rejectDontFragment && request.has(StunAttribute.DontFragment.class)) {
            return request.errorResponse(ErrorCode.UNKNOWN_ATTRIBUTE, "Unknown Attribute",
                    List.of(new StunAttribute.UnknownAttributes(List.of(StunAttribute.DontFragment.TYPE))));
        }
        var family = request.attribute(StunAttribute.RequestedAddressFamily.class)
                .map(StunAttribute.RequestedAddressFamily::family)
                .orElse(StunAddressFamily.IPV4);
        DatagramChannel relay;
        try {
            relay = DatagramChannel.open();
            relay.bind(new InetSocketAddress(InetAddress.ofLiteral(family == StunAddressFamily.IPV6 ? "::1" : "127.0.0.1"), 0));
        } catch (IOException exception) {
            return request.errorResponse(ErrorCode.ADDRESS_FAMILY_NOT_SUPPORTED, "Address Family not Supported", List.of());
        }
        var lifetime = request.attribute(StunAttribute.Lifetime.class)
                .map(StunAttribute.Lifetime::lifetime)
                .map(value -> value.compareTo(Duration.ofHours(1)) > 0 ? Duration.ofHours(1) : value)
                .orElse(Duration.ofMinutes(10));
        var allocation = new Allocation(client, relay);
        allocations.put(client.key(), allocation);
        allocationCount.incrementAndGet();
        Thread.ofVirtual().start(allocation::relayLoop);
        var attributes = new ArrayList<StunAttribute>(List.of(
                new StunAttribute.XorRelayedAddress(localAddress(relay)),
                new StunAttribute.Lifetime(lifetime),
                new StunAttribute.XorMappedAddress(client.address())));
        if (request.attribute(StunAttribute.EvenPort.class).map(StunAttribute.EvenPort::reserveNext).orElse(false)) {
            attributes.add(new StunAttribute.ReservationToken(0x0102030405060708L));
        }
        return request.successResponse(attributes);
    }

    /// Handles Refresh.
    private StunMessage refresh(Client client, StunMessage request) {
        var allocation = allocations.get(client.key());
        if (allocation == null) {
            return request.errorResponse(ErrorCode.ALLOCATION_MISMATCH, "Allocation Mismatch", List.of());
        }
        var lifetime = request.attribute(StunAttribute.Lifetime.class).map(StunAttribute.Lifetime::lifetime).orElse(Duration.ofMinutes(10));
        if (lifetime.isZero()) {
            allocations.remove(client.key());
            allocation.close();
            deallocations.incrementAndGet();
        } else {
            refreshes.incrementAndGet();
        }
        return request.successResponse(List.of(new StunAttribute.Lifetime(lifetime)));
    }

    /// Handles CreatePermission.
    private StunMessage createPermission(Client client, StunMessage request) {
        var allocation = allocations.get(client.key());
        if (allocation == null) {
            return request.errorResponse(ErrorCode.ALLOCATION_MISMATCH, "Allocation Mismatch", List.of());
        }
        var peers = request.attributes(StunAttribute.XorPeerAddress.class);
        if (peers.isEmpty()) {
            return request.errorResponse(ErrorCode.BAD_REQUEST, "Bad Request", List.of());
        }
        peers.forEach(peer -> allocation.permissions.add(peer.address().getAddress()));
        permissionRequests.incrementAndGet();
        return request.successResponse(List.of());
    }

    /// Handles ChannelBind.
    private StunMessage channelBind(Client client, StunMessage request) {
        var allocation = allocations.get(client.key());
        if (allocation == null) {
            return request.errorResponse(ErrorCode.ALLOCATION_MISMATCH, "Allocation Mismatch", List.of());
        }
        var channel = request.attribute(StunAttribute.ChannelNumber.class).map(StunAttribute.ChannelNumber::channel);
        var peer = request.attribute(StunAttribute.XorPeerAddress.class).map(StunAttribute.XorPeerAddress::address);
        if (channel.isEmpty() || peer.isEmpty() || channel.get() < 0x4000 || channel.get() > 0x4FFF) {
            return request.errorResponse(ErrorCode.BAD_REQUEST, "Bad Request", List.of());
        }
        var existing = allocation.peersByChannel.get(channel.get());
        if (existing != null && !existing.equals(peer.get())) {
            return request.errorResponse(ErrorCode.BAD_REQUEST, "Bad Request", List.of());
        }
        allocation.peersByChannel.put(channel.get(), peer.get());
        allocation.channelsByPeer.put(peer.get(), channel.get());
        allocation.permissions.add(peer.get().getAddress());
        channelBinds.incrementAndGet();
        return request.successResponse(List.of());
    }

    /// Relays a Send indication to its peer.
    private void relaySend(Client client, StunMessage indication) throws IOException {
        var allocation = allocations.get(client.key());
        var peer = indication.attribute(StunAttribute.XorPeerAddress.class);
        var data = indication.attribute(StunAttribute.Data.class);
        if (allocation == null || peer.isEmpty() || data.isEmpty() || !allocation.permissions.contains(peer.get().address().getAddress())) {
            return;
        }
        sendIndications.incrementAndGet();
        if (indication.has(StunAttribute.DontFragment.class)) {
            dontFragmentIndications.incrementAndGet();
        }
        allocation.relay.send(data.get().value(), peer.get().address());
    }

    /// Relays a ChannelData message to its peer.
    private void relayChannelData(Client client, ByteBuffer packet) throws IOException {
        var allocation = allocations.get(client.key());
        if (allocation == null || packet.remaining() < 4) {
            return;
        }
        var channel = packet.getShort(packet.position()) & 0xFFFF;
        var length = packet.getShort(packet.position() + 2) & 0xFFFF;
        var peer = allocation.peersByChannel.get(channel);
        if (peer == null || packet.remaining() < 4 + length) {
            return;
        }
        channelDataMessages.incrementAndGet();
        allocation.relay.send(packet.slice(packet.position() + 4, length), peer);
    }

    /// {@return the local address of a datagram channel}
    private static InetSocketAddress localAddress(DatagramChannel channel) {
        try {
            return (InetSocketAddress) channel.getLocalAddress();
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    /// Closes every socket and allocation.
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        allocations.values().forEach(Allocation::close);
        allocations.clear();
        for (var connection : connections) {
            try {
                connection.close();
            } catch (Exception _) {
                // Already gone.
            }
        }
        try {
            udp.close();
            tcp.close();
            tls.close();
        } catch (IOException _) {
            // Already gone.
        }
    }

    /// Sends a message to one client.
    @FunctionalInterface
    private interface Sender {
        /// Sends a message.
        void send(ByteBuffer message) throws IOException;
    }

    /// One client connection.
    ///
    /// @param key     the allocation key, transport and source
    /// @param address the client's address
    /// @param stream  whether the client is on TCP or TLS
    /// @param sender  the sender
    private record Client(String key, InetSocketAddress address, boolean stream, Sender sender) {
        /// Sends a message.
        void send(ByteBuffer message) throws IOException {
            sender.send(message);
        }
    }

    /// One allocation.
    private final class Allocation {
        /// The client.
        private final Client client;

        /// The relayed socket.
        private final DatagramChannel relay;

        /// The permitted peer addresses.
        private final Set<InetAddress> permissions = ConcurrentHashMap.newKeySet();

        /// The peers by channel.
        private final Map<Integer, InetSocketAddress> peersByChannel = new ConcurrentHashMap<>();

        /// The channels by peer.
        private final Map<InetSocketAddress, Integer> channelsByPeer = new ConcurrentHashMap<>();

        /// Creates an allocation.
        Allocation(Client client, DatagramChannel relay) {
            this.client = client;
            this.relay = relay;
        }

        /// Relays datagrams from peers to the client.
        void relayLoop() {
            var buffer = ByteBuffer.allocate(0x10000);
            while (true) {
                buffer.clear();
                InetSocketAddress peer;
                try {
                    peer = (InetSocketAddress) relay.receive(buffer);
                } catch (IOException exception) {
                    return;
                }
                buffer.flip();
                if (!permissions.contains(peer.getAddress())) {
                    continue;
                }
                try {
                    var channel = channelsByPeer.get(peer);
                    if (channel != null) {
                        var length = buffer.remaining();
                        var padded = client.stream() ? (length + 3) & ~3 : length;
                        var message = ByteBuffer.allocate(4 + padded);
                        message.putShort(channel.shortValue()).putShort((short) length).put(buffer);
                        client.send(message.position(4 + padded).flip());
                    } else {
                        var indication = StunMessage.indication(StunMethod.DATA, List.of(
                                new StunAttribute.XorPeerAddress(peer), new StunAttribute.Data(buffer)));
                        client.send(indication.encode(false));
                    }
                } catch (IOException exception) {
                    return;
                }
            }
        }

        /// Closes the relayed socket.
        void close() {
            try {
                relay.close();
            } catch (IOException _) {
                // Already gone.
            }
        }
    }
}
