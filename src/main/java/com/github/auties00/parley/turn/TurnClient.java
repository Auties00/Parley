package com.github.auties00.parley.turn;

import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.net.StreamConnection;
import com.github.auties00.parley.stun.StunAddressFamily;
import com.github.auties00.parley.stun.StunAttribute;
import com.github.auties00.parley.stun.StunAttribute.ErrorCode;
import com.github.auties00.parley.stun.StunAttribute.Nonce;
import com.github.auties00.parley.stun.StunAttribute.PasswordAlgorithms;
import com.github.auties00.parley.stun.StunAttribute.Realm;
import com.github.auties00.parley.stun.StunAttribute.UnknownAttributes;
import com.github.auties00.parley.stun.StunAttribute.XorMappedAddress;
import com.github.auties00.parley.stun.StunClass;
import com.github.auties00.parley.stun.StunClientTransactions;
import com.github.auties00.parley.stun.StunFormatException;
import com.github.auties00.parley.stun.StunIntegrity;
import com.github.auties00.parley.stun.StunKey;
import com.github.auties00.parley.stun.StunMessage;
import com.github.auties00.parley.stun.StunMethod;
import com.github.auties00.parley.stun.StunPasswordAlgorithm;
import com.github.auties00.parley.stun.StunRetransmission;

import java.io.EOFException;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/// A TURN client: one connection to a TURN server, over UDP, TCP or TLS, that holds at most one allocation.
///
/// [#connect(TurnServer,TurnCredentials,NetworkStack,MonotonicClock,Duration)] opens the connection through a
/// [NetworkStack] (so TCP and TLS can go through an application's proxy) and starts the reading thread;
/// [#allocate(TurnAllocationOptions,Duration)] runs the Allocate transaction and returns the [TurnAllocation], which
/// keeps itself alive with Refresh, CreatePermission and ChannelBind until it is closed.
///
/// {@snippet lang = java :
/// var server = TurnServer.parse(URI.create("turns:turn.example.org"));
/// try (var client = TurnClient.connect(server, new TurnCredentials("user", "secret"), Duration.ofSeconds(5))) {
///     var allocation = client.allocate(TurnAllocationOptions.IPV4
///             .receiver((peer, data, arrival) -> handle(peer, data)), Duration.ofSeconds(5));
///     allocation.createPermission(peer.getAddress(), Duration.ofSeconds(5));
///     allocation.send(datagram, peer);
/// }
/// }
///
/// # Redirection
///
/// A 300 Try Alternate answer to the Allocate request moves the client to the server its `ALTERNATE-SERVER` names
/// (over the same transport, with the TLS name of `ALTERNATE-DOMAIN` when present) and the Allocate starts over
/// there with the same credentials and a fresh challenge. Each server is tried once: a redirection back to a server
/// already tried fails the allocation with error 300.
///
/// # Authentication
///
/// Requests use the long-term credential mechanism: the first Allocate goes out unauthenticated, the server's 401
/// challenge supplies `REALM` and `NONCE`, and every later request carries `USERNAME` (or `USERHASH` when the nonce
/// cookie asks for username anonymity), `REALM`, `NONCE` and a message integrity attribute: `MESSAGE-INTEGRITY`, or
/// `MESSAGE-INTEGRITY-SHA256` with `PASSWORD-ALGORITHM` when the server offered `PASSWORD-ALGORITHMS`. A 438 Stale
/// Nonce is retried with the new nonce. Responses that fail integrity are dropped (UDP) or fail the request (TCP,
/// TLS).
///
/// # Transport
///
/// Over UDP requests are retransmitted on the RFC 8489 schedule; over TCP and TLS they are sent once, and every
/// message, ChannelData included, is framed on the stream (ChannelData padded to four bytes).
///
/// # Threading
///
/// The client starts two threads through the stack's [NetworkStack#threadFactory()]: the reading thread, which also
/// delivers relayed data to the allocation's [TurnDataReceiver], and, once allocated, the refresh timer. Blocking
/// methods block only their caller; every method is safe for concurrent use.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc7065.html RFC 7065: Traversal Using Relays around NAT (TURN) Uniform Resource Identifiers
public final class TurnClient implements AutoCloseable {
    /// The logger of the client.
    private static final System.Logger LOGGER = System.getLogger(TurnClient.class.getName());

    /// The largest message the reading thread accepts.
    private static final int MAX_MESSAGE = 0x10000 + 8;

    /// The error codes a response may carry without message integrity: the challenges, the redirect, and the
    /// unknown-attribute report a server sends before authenticating.
    private static final Set<Integer> UNAUTHENTICATED_ERRORS = Set.of(ErrorCode.TRY_ALTERNATE,
            ErrorCode.UNAUTHENTICATED, ErrorCode.UNKNOWN_ATTRIBUTE, ErrorCode.STALE_NONCE);

    /// The server.
    private final TurnServer server;

    /// The credentials.
    private final TurnCredentials credentials;

    /// The stack the connection and threads come from.
    private final NetworkStack stack;

    /// The clock of round-trip times and refresh deadlines.
    private final MonotonicClock clock;

    /// The refresh intervals.
    private final TurnTimers timers;

    /// The connection to the current server; replaced when the server redirects the Allocate.
    private volatile Link link;

    /// The outstanding transactions.
    private final StunClientTransactions transactions;

    /// The lock that guards the authentication state and [#allocation].
    private final Object lock = new Object();

    /// The realm of the last challenge, or `null` before one; guarded by [#lock].
    private String realm;

    /// The nonce of the last challenge, or `null` before one; guarded by [#lock].
    private String nonce;

    /// The key requests are signed with, or `null` before a challenge; guarded by [#lock].
    private StunKey key;

    /// The integrity attribute requests carry; guarded by [#lock].
    private StunIntegrity integrity = StunIntegrity.HMAC_SHA1;

    /// The `PASSWORD-ALGORITHMS` the server offered, echoed in requests, or `null`; guarded by [#lock].
    private PasswordAlgorithms offeredAlgorithms;

    /// The negotiated password algorithm; guarded by [#lock].
    private StunPasswordAlgorithm algorithm = StunPasswordAlgorithm.MD5;

    /// Whether requests carry `USERHASH` instead of `USERNAME`; guarded by [#lock].
    private boolean userHash;

    /// The allocation, or `null` before [#allocate(TurnAllocationOptions,Duration)]; guarded by [#lock].
    private TurnAllocation allocation;

    /// Whether [#close()] ran.
    private volatile boolean closed;

    /// Creates a client over an open connection; the reading thread is not started.
    private TurnClient(TurnServer server, TurnCredentials credentials, NetworkStack stack, MonotonicClock clock,
                       TurnTimers timers, Link link) {
        this.server = server;
        this.credentials = credentials;
        this.stack = stack;
        this.clock = clock;
        this.timers = timers;
        this.link = link;
        this.transactions = new StunClientTransactions(clock);
    }

    /// Connects to a TURN server and starts the reading thread.
    ///
    /// Over UDP this resolves the server through the stack and binds a socket on the wildcard address of the
    /// server's family; over TCP and TLS it connects through the stack, handing it the unresolved server address and,
    /// for TLS, the host name the certificate must match. No request is sent yet.
    ///
    /// @param server      the server
    /// @param credentials the long-term credentials
    /// @param stack       the network stack
    /// @param clock       the clock of round-trip times and refresh deadlines
    /// @param timeout     the longest time connecting may take
    /// @return the connected client
    /// @throws IOException if the server cannot be resolved or reached
    public static TurnClient connect(TurnServer server, TurnCredentials credentials, NetworkStack stack,
                                     MonotonicClock clock, Duration timeout) throws IOException {
        return connect(server, credentials, stack, clock, timeout, TurnTimers.DEFAULT);
    }

    /// Connects to a TURN server with the given refresh intervals; see
    /// [#connect(TurnServer,TurnCredentials,NetworkStack,MonotonicClock,Duration)].
    static TurnClient connect(TurnServer server, TurnCredentials credentials, NetworkStack stack,
                              MonotonicClock clock, Duration timeout, TurnTimers timers) throws IOException {
        Objects.requireNonNull(server, "server cannot be null");
        Objects.requireNonNull(credentials, "credentials cannot be null");
        Objects.requireNonNull(stack, "stack cannot be null");
        Objects.requireNonNull(clock, "clock cannot be null");
        Objects.requireNonNull(timeout, "timeout cannot be null");
        Link link = switch (server.transport()) {
            case UDP -> {
                var address = stack.resolve(server.host()).getFirst();
                var wildcard = address instanceof Inet6Address
                        ? InetAddress.ofLiteral("::")
                        : InetAddress.ofLiteral("0.0.0.0");
                var endpoint = stack.bindUdp(new InetSocketAddress(wildcard, 0));
                yield new UdpLink(endpoint, new InetSocketAddress(address, server.port()));
            }
            case TCP -> new StreamLink(stack.connectTcp(server.unresolvedAddress(), timeout));
            case TLS -> new StreamLink(stack.connectTls(server.unresolvedAddress(), server.host(), timeout));
        };
        var client = new TurnClient(server, credentials, stack, clock, timers, link);
        client.startReading(link);
        return client;
    }

    /// Connects to a TURN server through the system network stack, with virtual threads and the system clock; see
    /// [#connect(TurnServer,TurnCredentials,NetworkStack,MonotonicClock,Duration)].
    ///
    /// @param server      the server
    /// @param credentials the long-term credentials
    /// @param timeout     the longest time connecting may take
    /// @return the connected client
    /// @throws IOException if the server cannot be resolved or reached
    public static TurnClient connect(TurnServer server, TurnCredentials credentials, Duration timeout)
            throws IOException {
        return connect(server, credentials, NetworkStack.system(Thread.ofVirtual().name("parley-turn-", 0).factory()),
                MonotonicClock.system(), timeout);
    }

    /// Opens a link to a server address over the transport of [#server].
    private Link open(InetSocketAddress address, String tlsName, Duration timeout) throws IOException {
        return switch (server.transport()) {
            case UDP -> {
                var wildcard = address.getAddress() instanceof Inet6Address
                        ? InetAddress.ofLiteral("::")
                        : InetAddress.ofLiteral("0.0.0.0");
                var endpoint = stack.bindUdp(new InetSocketAddress(wildcard, 0));
                yield new UdpLink(endpoint, address);
            }
            case TCP -> new StreamLink(stack.connectTcp(address, timeout));
            case TLS -> new StreamLink(stack.connectTls(address, tlsName, timeout));
        };
    }

    /// Starts the reading thread of a link.
    private void startReading(Link reading) {
        stack.threadFactory().newThread(() -> readLoop(reading)).start();
    }

    /// Moves the client to the server a 300 Try Alternate named, forgetting the old server's challenge.
    ///
    /// @throws TurnException if the response names no alternate or one already tried
    private void redirect(StunMessage response, java.util.Set<InetSocketAddress> tried, long deadline)
            throws IOException {
        var alternate = response.attribute(StunAttribute.AlternateServer.class)
                .orElseThrow(() -> new TurnException("300 Try Alternate without ALTERNATE-SERVER",
                        ErrorCode.TRY_ALTERNATE))
                .address();
        if (!tried.add(alternate)) {
            throw new TurnException("the TURN server redirected to " + alternate + ", already tried",
                    ErrorCode.TRY_ALTERNATE);
        }
        var tlsName = response.attribute(StunAttribute.AlternateDomain.class)
                .map(StunAttribute.AlternateDomain::value).orElse(server.host());
        var replacement = open(alternate, tlsName, remaining(deadline));
        var previous = link;
        synchronized (lock) {
            realm = null;
            nonce = null;
            key = null;
            integrity = StunIntegrity.HMAC_SHA1;
            offeredAlgorithms = null;
            algorithm = StunPasswordAlgorithm.MD5;
            userHash = false;
            link = replacement;
        }
        startReading(replacement);
        previous.close();
    }

    /// {@return the server this client is connected to}
    public TurnServer server() {
        return server;
    }

    /// {@return the address of the server, resolved}
    public InetSocketAddress serverAddress() {
        return link.remoteAddress();
    }

    /// {@return the local address of the connection to the server}
    public InetSocketAddress localAddress() {
        return link.localAddress();
    }

    /// {@return the allocation, or an empty optional before [#allocate(TurnAllocationOptions,Duration)] succeeded}
    public Optional<TurnAllocation> allocation() {
        synchronized (lock) {
            return Optional.ofNullable(allocation);
        }
    }

    /// Creates the allocation of this client.
    ///
    /// Sends Allocate with `REQUESTED-TRANSPORT` UDP and the options' family, lifetime, `DONT-FRAGMENT`, `EVEN-PORT`
    /// and `RESERVATION-TOKEN`, answers the 401 challenge with the credentials, follows a 300 Try Alternate once per
    /// server, and starts the refresh timer.
    ///
    /// @param options what to ask for
    /// @param timeout the longest time the whole exchange may take
    /// @return the allocation
    /// @throws TurnException         if the server refused the allocation; [TurnException#errorCode()] holds its
    ///                               error code (440 when it does not support the family, 486 when the quota is
    ///                               reached, 508 when it cannot reserve the ports `EVEN-PORT` asked for, 300 when
    ///                               it redirected to a server already tried)
    /// @throws IOException           if the server did not answer or the connection failed
    /// @throws InterruptedException  if the calling thread is interrupted
    /// @throws IllegalStateException if the client already has an allocation or is closed
    public TurnAllocation allocate(TurnAllocationOptions options, Duration timeout) throws IOException, InterruptedException {
        Objects.requireNonNull(options, "options cannot be null");
        Objects.requireNonNull(timeout, "timeout cannot be null");
        synchronized (lock) {
            if (allocation != null) {
                throw new IllegalStateException("the client already has an allocation");
            }
        }
        ensureOpen();
        var deadline = clock.nanos() + timeout.toNanos();
        var current = options;
        var tried = new java.util.HashSet<InetSocketAddress>();
        tried.add(link.remoteAddress());
        while (true) {
            var attributes = new ArrayList<StunAttribute>();
            attributes.add(new StunAttribute.RequestedTransport(StunAttribute.RequestedTransport.UDP));
            if (current.family() == StunAddressFamily.IPV6) {
                attributes.add(new StunAttribute.RequestedAddressFamily(current.family()));
            }
            current.lifetime().ifPresent(lifetime -> attributes.add(new StunAttribute.Lifetime(lifetime)));
            if (current.dontFragment()) {
                attributes.add(new StunAttribute.DontFragment());
            }
            if (current.evenPort()) {
                attributes.add(new StunAttribute.EvenPort(current.reserveNextPort()));
            }
            current.reservationToken().ifPresent(token -> attributes.add(new StunAttribute.ReservationToken(token)));
            var response = transact(StunMethod.ALLOCATE, attributes, remaining(deadline));
            if (response.messageClass() == StunClass.SUCCESS_RESPONSE) {
                var relayed = response.attribute(StunAttribute.XorRelayedAddress.class)
                        .orElseThrow(() -> new TurnException("the Allocate response has no XOR-RELAYED-ADDRESS"))
                        .address();
                var mapped = response.attribute(XorMappedAddress.class).map(XorMappedAddress::address);
                var lifetime = response.attribute(StunAttribute.Lifetime.class)
                        .map(StunAttribute.Lifetime::lifetime)
                        .orElse(Duration.ofMinutes(10));
                var token = response.attribute(StunAttribute.ReservationToken.class)
                        .map(StunAttribute.ReservationToken::token);
                var created = new TurnAllocation(this, relayed, mapped, lifetime, current, timers, clock, token);
                synchronized (lock) {
                    if (closed) {
                        throw new IOException("the TURN client is closed");
                    }
                    allocation = created;
                }
                stack.threadFactory().newThread(created::refreshLoop).start();
                return created;
            }
            var error = response.errorCode().orElseThrow(() -> new TurnException("error response without ERROR-CODE"));
            if (error.code() == ErrorCode.TRY_ALTERNATE) {
                redirect(response, tried, deadline);
                continue;
            }
            if (error.code() == ErrorCode.UNKNOWN_ATTRIBUTE && current.dontFragment()
                    && response.attribute(UnknownAttributes.class)
                    .map(unknown -> unknown.types().contains(StunAttribute.DontFragment.TYPE))
                    .orElse(false)) {
                current = current.withDontFragment(false);
                continue;
            }
            throw new TurnException("Allocate failed: " + error.code() + " " + error.reason(), error.code());
        }
    }

    /// Runs an authenticated request to the server and returns its final response, success or error.
    ///
    /// Answers 401 challenges and 438 stale nonces by retrying with fresh credentials; any other error is returned.
    ///
    /// @throws TurnException if the server rejects the credentials
    StunMessage transact(StunMethod method, List<StunAttribute> attributes, Duration timeout)
            throws IOException, InterruptedException {
        var deadline = clock.nanos() + timeout.toNanos();
        var authenticatedAttempt = false;
        for (var attempt = 0; attempt < 4; attempt++) {
            ensureOpen();
            StunKey signingKey;
            StunIntegrity signingIntegrity;
            var all = new ArrayList<>(attributes);
            synchronized (lock) {
                signingKey = key;
                signingIntegrity = integrity;
                if (signingKey != null) {
                    all.addAll(credentialAttributes());
                }
            }
            var request = StunMessage.request(method, all);
            var encoded = signingKey == null
                    ? request.encode(true)
                    : request.encode(signingKey, signingIntegrity, true);
            var key = signingKey;
            var response = transactions.execute(request, () -> link.send(encoded.duplicate()), schedule(deadline),
                    message -> authentic(message, key)).message();
            if (response.messageClass() != StunClass.ERROR_RESPONSE) {
                return response;
            }
            var error = response.errorCode().orElse(null);
            if (error == null) {
                return response;
            }
            if (error.code() == ErrorCode.UNAUTHENTICATED) {
                if (authenticatedAttempt && !challengeChangesRealm(response)) {
                    throw new TurnException("the TURN server rejected the credentials", ErrorCode.UNAUTHENTICATED);
                }
                acceptChallenge(response);
                authenticatedAttempt = true;
                continue;
            }
            if (error.code() == ErrorCode.STALE_NONCE && response.has(Nonce.class)) {
                acceptChallenge(response);
                authenticatedAttempt = true;
                continue;
            }
            return response;
        }
        throw new TurnException("the TURN server kept challenging the request", ErrorCode.UNAUTHENTICATED);
    }

    /// {@return the credential attributes of a signed request}; the caller holds [#lock].
    private List<StunAttribute> credentialAttributes() {
        var result = new ArrayList<StunAttribute>(5);
        if (userHash) {
            result.add(new StunAttribute.UserHash(StunKey.userHash(credentials.username(), realm)));
        } else {
            result.add(new StunAttribute.Username(StunKey.opaqueString(credentials.username())));
        }
        result.add(new Realm(realm));
        result.add(new Nonce(nonce));
        if (offeredAlgorithms != null) {
            result.add(offeredAlgorithms);
            result.add(StunAttribute.PasswordAlgorithm.of(algorithm));
        }
        return result;
    }

    /// {@return whether a 401 names a realm other than the one the last request was signed for}
    private boolean challengeChangesRealm(StunMessage response) {
        synchronized (lock) {
            return response.attribute(Realm.class).map(value -> !value.value().equals(realm)).orElse(false);
        }
    }

    /// Takes the realm, nonce and password algorithms of a 401 or 438 response and derives the new key.
    ///
    /// @throws TurnException if the challenge lacks a realm or nonce, or the server offers no supported algorithm
    private void acceptChallenge(StunMessage response) throws TurnException {
        var newNonce = response.attribute(Nonce.class)
                .orElseThrow(() -> new TurnException("the challenge has no NONCE", ErrorCode.UNAUTHENTICATED));
        synchronized (lock) {
            var newRealm = response.attribute(Realm.class).map(Realm::value).orElse(realm);
            if (newRealm == null) {
                throw new TurnException("the challenge has no REALM", ErrorCode.UNAUTHENTICATED);
            }
            var offered = response.attribute(PasswordAlgorithms.class);
            if (newNonce.passwordAlgorithmsFeature()) {
                if (offered.isEmpty()) {
                    throw new TurnException("the nonce cookie announces PASSWORD-ALGORITHMS but the challenge has none",
                            ErrorCode.UNAUTHENTICATED);
                }
                algorithm = offered.get().firstSupported()
                        .orElseThrow(() -> new TurnException("the server offers no supported password algorithm",
                                ErrorCode.UNAUTHENTICATED));
                offeredAlgorithms = offered.get();
                integrity = StunIntegrity.HMAC_SHA256;
            } else if (offered.isPresent() && offered.get().firstSupported().isPresent()) {
                algorithm = offered.get().firstSupported().get();
                offeredAlgorithms = offered.get();
                integrity = StunIntegrity.HMAC_SHA256;
            }
            userHash = newNonce.usernameAnonymityFeature();
            realm = newRealm;
            nonce = newNonce.value();
            key = StunKey.longTerm(StunKey.opaqueString(credentials.username()), realm, credentials.password(), algorithm);
        }
    }

    /// {@return whether a response to a request signed with `key` is authentic}
    private static boolean authentic(StunMessage response, StunKey key) {
        if (key == null) {
            return true;
        }
        if (response.integrity().isPresent()) {
            return response.verifyIntegrity(key);
        }
        return response.messageClass() == StunClass.ERROR_RESPONSE
                && response.errorCode().map(error -> UNAUTHENTICATED_ERRORS.contains(error.code())).orElse(false);
    }

    /// {@return the retransmission schedule that fits before `deadline`}
    private StunRetransmission schedule(long deadline) throws TurnException {
        var left = deadline - clock.nanos();
        if (left <= 0) {
            throw new TurnException("the TURN request timed out");
        }
        if (link.isStream()) {
            return StunRetransmission.reliable(Duration.ofNanos(left));
        }
        return StunRetransmission.UDP.truncatedTo(Duration.ofNanos(left));
    }

    /// {@return the time left until `deadline`, at least one nanosecond}
    private Duration remaining(long deadline) {
        return Duration.ofNanos(Math.max(1, deadline - clock.nanos()));
    }

    /// Sends raw bytes to the server: a STUN message or a ChannelData message.
    void sendRaw(ByteBuffer message) throws IOException {
        ensureOpen();
        link.send(message);
    }

    /// {@return whether the connection to the server is a stream}
    boolean isStream() {
        return link.isStream();
    }

    /// Fails unless the client is open.
    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("the TURN client is closed");
        }
    }

    /// Reads messages from one link until it closes; the end of the current link fails the allocation, the end of
    /// a link a redirection replaced does nothing.
    private void readLoop(Link reading) {
        try {
            switch (reading) {
                case UdpLink udp -> readDatagrams(udp);
                case StreamLink stream -> readStream(stream);
            }
        } catch (IOException exception) {
            if (!closed && reading == link && LOGGER.isLoggable(Level.DEBUG)) {
                LOGGER.log(Level.DEBUG, "TURN connection to " + server.host() + " ended", exception);
            }
        } finally {
            if (reading == link) {
                TurnAllocation current;
                synchronized (lock) {
                    current = allocation;
                }
                if (current != null) {
                    current.markFailed();
                }
                transactions.close();
            }
        }
    }

    /// Reads datagrams from the UDP socket.
    private void readDatagrams(UdpLink udp) throws IOException {
        var buffer = ByteBuffer.allocate(MAX_MESSAGE);
        while (!closed && udp == link) {
            buffer.clear();
            InetSocketAddress source;
            try {
                source = udp.endpoint().receive(buffer);
            } catch (java.net.PortUnreachableException exception) {
                // An ICMP error for an earlier datagram; the socket is still usable.
                continue;
            }
            var arrival = clock.nanos();
            if (!source.equals(udp.server())) {
                continue;
            }
            buffer.flip();
            dispatch(buffer, arrival);
        }
    }

    /// Reads framed messages from the stream: STUN messages by their header length, ChannelData padded to four
    /// bytes.
    private void readStream(StreamLink stream) throws IOException {
        var buffer = ByteBuffer.allocate(MAX_MESSAGE * 2);
        while (!closed && stream == link) {
            if (stream.connection().read(buffer) < 0) {
                throw new EOFException("the TURN server closed the connection");
            }
            buffer.flip();
            while (true) {
                if (buffer.remaining() < 4) {
                    break;
                }
                var first = buffer.get(buffer.position()) & 0xFF;
                int frame;
                int message;
                if (first < 0x40) {
                    frame = StunMessage.frameLength(buffer);
                    message = frame;
                } else if (first < 0x80) {
                    frame = ChannelData.streamFrameLength(buffer);
                    message = ChannelData.HEADER_LENGTH + (buffer.getShort(buffer.position() + 2) & 0xFFFF);
                } else {
                    throw new IOException("the TURN server sent an unframed byte 0x" + Integer.toHexString(first));
                }
                if (buffer.remaining() < frame) {
                    break;
                }
                var arrival = clock.nanos();
                dispatch(buffer.slice(buffer.position(), message), arrival);
                buffer.position(buffer.position() + frame);
            }
            buffer.compact();
        }
    }

    /// Routes one message from the server: ChannelData and Data indications to the allocation, responses to their
    /// transactions.
    private void dispatch(ByteBuffer packet, long arrival) {
        TurnAllocation current;
        synchronized (lock) {
            current = allocation;
        }
        if (ChannelData.isChannelData(packet)) {
            if (current != null) {
                current.onChannelData(packet, arrival);
            }
            return;
        }
        if (!StunMessage.isStun(packet)) {
            return;
        }
        StunMessage message;
        try {
            message = StunMessage.decode(packet);
        } catch (StunFormatException exception) {
            return;
        }
        if (message.messageClass().isResponse()) {
            transactions.complete(message);
        } else if (message.messageClass() == StunClass.INDICATION && message.method() == StunMethod.DATA && current != null) {
            current.onDataIndication(message, arrival);
        }
    }

    /// Deletes the allocation, if any, with a zero-lifetime Refresh (waiting at most one second), and closes the
    /// connection, which ends the reading and refresh threads. Calling it again has no effect.
    @Override
    public void close() {
        TurnAllocation current;
        synchronized (lock) {
            if (closed) {
                return;
            }
            current = allocation;
        }
        if (current != null) {
            current.deallocate();
        }
        closed = true;
        transactions.close();
        link.close();
    }

    /// {@return whether [#close()] ran}
    boolean isClosed() {
        return closed;
    }

    /// {@return the maximum datagram a peer can receive through the relay without fragmentation}
    int maxPayloadSize(InetSocketAddress relayed) {
        var serverHeader = (link.remoteAddress().getAddress() instanceof Inet4Address ? 20 : 40) + (link.isStream() ? 20 : 8);
        var peerHeader = (relayed.getAddress() instanceof Inet4Address ? 20 : 40) + 8;
        return Math.min(1500 - serverHeader - ChannelData.HEADER_LENGTH, 1500 - peerHeader);
    }

    /// The connection to the server.
    private sealed interface Link permits UdpLink, StreamLink {
        /// Sends one message.
        void send(ByteBuffer message) throws IOException;

        /// {@return the local address}
        InetSocketAddress localAddress();

        /// {@return the server address}
        InetSocketAddress remoteAddress();

        /// {@return whether the connection is a stream}
        boolean isStream();

        /// Closes the connection.
        void close();
    }

    /// A UDP socket that talks to one server.
    ///
    /// @param endpoint the socket
    /// @param server   the server address, resolved
    private record UdpLink(DatagramEndpoint endpoint, InetSocketAddress server) implements Link {
        @Override
        public void send(ByteBuffer message) throws IOException {
            endpoint.send(message, server);
        }

        @Override
        public InetSocketAddress localAddress() {
            return endpoint.localAddress();
        }

        @Override
        public InetSocketAddress remoteAddress() {
            return server;
        }

        @Override
        public boolean isStream() {
            return false;
        }

        @Override
        public void close() {
            endpoint.close();
        }
    }

    /// A TCP or TLS connection to the server, written under a lock so messages never interleave.
    ///
    /// @param connection the connection
    /// @param writeLock  the lock of writes
    private record StreamLink(StreamConnection connection, Object writeLock) implements Link {
        /// Creates a link over a connection.
        StreamLink(StreamConnection connection) {
            this(connection, new Object());
        }

        @Override
        public void send(ByteBuffer message) throws IOException {
            synchronized (writeLock) {
                while (message.hasRemaining()) {
                    connection.write(message);
                }
            }
        }

        @Override
        public InetSocketAddress localAddress() {
            return connection.localAddress();
        }

        @Override
        public InetSocketAddress remoteAddress() {
            return connection.remoteAddress();
        }

        @Override
        public boolean isStream() {
            return true;
        }

        @Override
        public void close() {
            try {
                connection.close();
            } catch (IOException _) {
                // A failed close leaves nothing to release.
            }
        }
    }
}
