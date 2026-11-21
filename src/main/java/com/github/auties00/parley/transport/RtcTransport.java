package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsDatagramIo;
import com.github.auties00.parley.dtls.DtlsEndpoint;
import com.github.auties00.parley.dtls.DtlsException;
import com.github.auties00.parley.dtls.DtlsSrtpKeys;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.ice.IceAgent;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceCredentials;
import com.github.auties00.parley.ice.IceException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.stun.StunMessage;
import com.github.auties00.srtp.SrtpCryptoSuite;
import com.github.auties00.srtp.SrtpErrorStatus;
import com.github.auties00.srtp.SrtpPacket;
import com.github.auties00.srtp.SrtpTransformer;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/// Carries the SRTP media of one session over a single UDP socket: ICE, DTLS-SRTP or SDES keying, and the protection
/// of every RTP and RTCP packet, with RTP and RTCP multiplexed on one port.
///
/// # Lifecycle
///
/// [#open(InetAddress,ThreadFactory)] binds the socket, generates the local ICE credentials and DTLS certificate, and
/// starts the receive loop, so the local candidates and the certificate fingerprint can go into a session
/// description before the peer's description is known. The transport is then established once, in one of two ways:
///
/// - [#establishWebRtc(IceCredentials,List,DtlsEndpoint.Role,String,Duration)] runs ICE as the controlling agent and
///   then a DTLS-SRTP handshake, the keying of `UDP/TLS/RTP/SAVPF`;
/// - [#establishSdes(InetSocketAddress,SrtpCryptoSuite,byte\[\],byte\[\],byte\[\],byte\[\])] takes keys exchanged
///   in the session descriptions, with no ICE and no DTLS, the keying of `RTP/SAVP`.
///
/// Once established, [#sendRtp(RtpPacket)] and [#sendRtcp(byte\[\],int)] protect and send, and the [Listener]
/// receives what the peer sends. [#close()] stops the transport.
///
/// {@snippet lang = java :
/// var transport = RtcTransport.open(null, Thread.ofVirtual().factory());
/// // put transport.hostCandidates(), transport.localCredentials() and
/// // transport.certificate().fingerprint() into the local description
/// transport.setListener(listener);
/// var profile = transport.establishWebRtc(remoteCredentials, remoteCandidates,
///         DtlsEndpoint.Role.CLIENT, remoteFingerprint, Duration.ofSeconds(10));
/// transport.sendRtp(new RtpPacket(111, true, sequence, timestamp, ssrc, payload));
/// }
///
/// # Receiving
///
/// The receive loop demultiplexes datagrams by their first byte: STUN goes to the ICE agent, DTLS to the handshake,
/// and RTP and RTCP are unprotected and handed to the [Listener]; anything else, a malformed datagram, and media that
/// arrives before the transport is established are dropped. RTP packets are delivered in arrival order, without
/// reordering or loss concealment.
///
/// # Failure
///
/// After a WebRTC establishment the transport sends a consent check every five seconds and fails with
/// [Failure#CONSENT_EXPIRED] when the peer has answered none for thirty seconds. A run of {@value #AUTH_FAILURE_LIMIT}
/// consecutive packets that fail SRTP authentication fails it with [Failure#SRTP_AUTHENTICATION], and a DTLS alert
/// from the peer with [Failure#CLOSED_BY_PEER]. A failure closes the transport and is then reported once to
/// [Listener#onFailure(Failure,String)]; [#close()] stops the transport without a report.
///
/// # Threading
///
/// The transport starts two threads through the [ThreadFactory] it is opened with: the receive loop, and after a
/// WebRTC establishment the consent loop. Both end when the transport closes. The establishing methods block the
/// calling thread; every other method may be called from any thread.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
/// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
/// @spec https://www.rfc-editor.org/rfc/rfc3711.html RFC 3711: The Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
/// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
public final class RtcTransport implements AutoCloseable {
    /// The logger of the transport.
    private static final System.Logger LOGGER = System.getLogger(RtcTransport.class.getName());

    /// The number of consecutive incoming packets failing SRTP authentication that fails the transport with
    /// [Failure#SRTP_AUTHENTICATION]; an authenticated packet resets the count.
    public static final int AUTH_FAILURE_LIMIT = 200;

    /// The spare room left after an RTP packet for its SRTP tag.
    private static final int RTP_TAILROOM = 16;

    /// The spare bytes [#sendRtcp(byte\[\],int)] needs after an RTCP packet to append the SRTCP index and
    /// authentication tag in place, the `tailroom` to pass to [com.github.auties00.parley.rtp.RtcpPackets].
    public static final int RTCP_TAILROOM = 20;

    /// The interval of consent checks.
    private static final long CONSENT_INTERVAL_MILLIS = 5_000;

    /// How long consent stays valid without an answer, the 30 seconds of RFC 7675 section 5.1.
    private static final long CONSENT_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(30);

    /// The largest datagram the receive loop accepts.
    private static final int MAX_DATAGRAM = 2048;

    /// The socket.
    private final DatagramSocket socket;

    /// The factory of the receive and consent threads.
    private final ThreadFactory threadFactory;

    /// The local ICE credentials.
    private final IceCredentials localCredentials;

    /// The local DTLS certificate.
    private final DtlsCertificate certificate;

    /// The DTLS datagrams received while the handshake runs.
    private final LinkedBlockingQueue<byte[]> dtlsQueue = new LinkedBlockingQueue<>();

    /// The lock that guards the state below.
    private final Object lock = new Object();

    /// The listener of received media and failures.
    private volatile Listener listener;

    /// The ICE agent, or `null` before a WebRTC establishment.
    private volatile IceAgent iceAgent;

    /// The DTLS endpoint, or `null` before a WebRTC establishment.
    private volatile DtlsEndpoint dtls;

    /// The remote media address, or `null` before establishment.
    private volatile InetSocketAddress remote;

    /// The SRTP protection of outgoing packets, or `null` before establishment.
    private volatile SrtpTransformer outbound;

    /// The SRTP protection of incoming packets, or `null` before establishment.
    private volatile SrtpTransformer inbound;

    /// The number of consecutive incoming packets that failed authentication.
    private int authFailures;

    /// The [System#nanoTime()] of the last authenticated incoming packet, `0` before any.
    private volatile long lastMediaNanos;

    /// Whether the transport stopped.
    private volatile boolean closed;

    /// Creates a transport over a bound socket.
    ///
    /// @param socket        the socket
    /// @param threadFactory the thread factory
    private RtcTransport(DatagramSocket socket, ThreadFactory threadFactory) {
        this.socket = socket;
        this.threadFactory = threadFactory;
        this.localCredentials = IceCredentials.generate();
        this.certificate = DtlsCertificate.generate();
    }

    /// Binds a UDP socket on an ephemeral port and starts the receive loop.
    ///
    /// The new transport has fresh ICE credentials and a fresh DTLS certificate, and no listener.
    ///
    /// @param bindAddress   the local address to bind, or `null` for the wildcard address
    /// @param threadFactory the factory of the transport's threads; each thread it creates is started at once
    /// @return the transport, open and not established
    /// @throws IOException if the socket cannot be bound
    public static RtcTransport open(InetAddress bindAddress, ThreadFactory threadFactory) throws IOException {
        Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
        var socket = new DatagramSocket(new InetSocketAddress(bindAddress, 0));
        var transport = new RtcTransport(socket, threadFactory);
        threadFactory.newThread(transport::receiveLoop).start();
        return transport;
    }

    /// Sets the listener of received media and failures, replacing the previous one.
    ///
    /// Packets that arrive while no listener is set are dropped, so set it before establishing the transport.
    ///
    /// @param listener the listener, or `null` to drop what arrives
    public void setListener(Listener listener) {
        this.listener = listener;
    }

    /// {@return the local ICE credentials, for `a=ice-ufrag` and `a=ice-pwd`}
    ///
    /// They are generated when the transport is opened and never change.
    public IceCredentials localCredentials() {
        return localCredentials;
    }

    /// {@return the local DTLS certificate, whose [DtlsCertificate#fingerprint()] goes into `a=fingerprint`}
    ///
    /// It is generated when the transport is opened and never changes.
    public DtlsCertificate certificate() {
        return certificate;
    }

    /// {@return the local UDP port the socket is bound to}
    public int localPort() {
        return socket.getLocalPort();
    }

    /// {@return the unmodifiable host candidates of the socket: one per address of every network interface that is
    /// up and not a loopback, IPv4 first, link-local and site-local IPv6 addresses excluded}
    ///
    /// When the socket is bound to a specific address, that address is the only candidate. When no interface
    /// qualifies, or they cannot be enumerated, the loopback address is the only candidate, so a local peer can
    /// still connect. Candidates are numbered from foundation `1`, with decreasing local preferences. No server
    /// reflexive or relayed candidate is gathered.
    public List<IceCandidate> hostCandidates() {
        var addresses = new ArrayList<InetAddress>();
        var bound = socket.getLocalAddress();
        if (bound != null && !bound.isAnyLocalAddress()) {
            addresses.add(bound);
        } else {
            try {
                for (var networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                    if (!networkInterface.isUp() || networkInterface.isLoopback()) {
                        continue;
                    }
                    for (var address : Collections.list(networkInterface.getInetAddresses())) {
                        if (address instanceof Inet6Address && (address.isLinkLocalAddress() || address.isSiteLocalAddress())) {
                            continue;
                        }
                        addresses.add(address);
                    }
                }
            } catch (SocketException exception) {
                if (LOGGER.isLoggable(Level.WARNING)) {
                    LOGGER.log(Level.WARNING, "cannot enumerate the network interfaces", exception);
                }
            }
            if (addresses.isEmpty()) {
                addresses.add(InetAddress.getLoopbackAddress());
            }
        }
        addresses.sort((left, right) -> Boolean.compare(left instanceof Inet6Address, right instanceof Inet6Address));
        var result = new ArrayList<IceCandidate>();
        for (var index = 0; index < addresses.size(); index++) {
            var address = addresses.get(index);
            var preference = 65535 - index * 1024 - (address instanceof Inet4Address ? 0 : 512);
            result.add(IceCandidate.host(Integer.toString(index + 1), new InetSocketAddress(address, localPort()),
                    Math.max(0, preference)));
        }
        return List.copyOf(result);
    }

    /// Establishes the media path with ICE and a DTLS-SRTP handshake, and returns the negotiated SRTP profile.
    ///
    /// Runs the connectivity checks as the controlling agent, nominating aggressively, against the UDP candidates of
    /// component `1` in `remoteCandidates` whose address resolves; then runs the DTLS handshake in `role` over the
    /// selected pair, checking the peer's certificate against `remoteFingerprint`, and keys SRTP from it, offering
    /// every [SrtpProfile]. Blocks until both complete, then starts the consent loop.
    ///
    /// @param remoteCredentials the peer's `a=ice-ufrag` and `a=ice-pwd`
    /// @param remoteCandidates  the peer's candidates, in priority order
    /// @param role              the DTLS role of this endpoint, from the `a=setup` negotiation
    /// @param remoteFingerprint the peer's `a=fingerprint` value
    /// @param timeout           the longest time the checks and the handshake may take together
    /// @return the negotiated SRTP profile
    /// @throws IceException          if no candidate is usable or no pair is selected in time
    /// @throws DtlsException         if the handshake fails or does not complete in time
    /// @throws InterruptedException  if the calling thread is interrupted
    /// @throws IllegalStateException if the transport is closed, or already established or being established
    /// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
    /// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
    public SrtpProfile establishWebRtc(IceCredentials remoteCredentials,
                                       List<IceCandidate> remoteCandidates, DtlsEndpoint.Role role,
                                       String remoteFingerprint, Duration timeout)
            throws IceException, DtlsException, InterruptedException {
        ensureFresh();
        var deadline = System.nanoTime() + timeout.toNanos();
        var agent = new IceAgent(this.localCredentials, remoteCredentials, true, this::sendTo);
        iceAgent = agent;
        var targets = new ArrayList<InetSocketAddress>();
        for (var candidate : remoteCandidates) {
            if (candidate.component() != 1 || !candidate.transport().equals("udp")) {
                continue;
            }
            var address = candidate.address();
            if (!address.isUnresolved()) {
                targets.add(address);
            }
        }
        var selected = agent.nominate(targets, Duration.ofNanos(Math.max(1, deadline - System.nanoTime())));
        remote = selected;
        if (LOGGER.isLoggable(Level.DEBUG)) {
            LOGGER.log(Level.DEBUG, "ICE selected {0}", selected);
        }
        var endpoint = new DtlsEndpoint(role, certificate, remoteFingerprint, List.of(SrtpProfile.values()), new DtlsDatagramIo() {
            @Override
            public void send(byte[] datagram) throws IOException {
                sendTo(datagram, selected);
            }

            @Override
            public byte[] receive(long timeoutNanos) throws InterruptedException {
                return dtlsQueue.poll(timeoutNanos, TimeUnit.NANOSECONDS);
            }
        });
        dtls = endpoint;
        var keys = endpoint.handshake(Duration.ofNanos(Math.max(1, deadline - System.nanoTime())));
        installKeys(keys);
        threadFactory.newThread(this::consentLoop).start();
        return keys.profile();
    }

    /// Establishes the media path with SDES keys, with no ICE and no DTLS; returns at once.
    ///
    /// Packets go to `remoteAddress`; when an authenticated packet arrives from another address, the transport sends
    /// to that address instead (symmetric RTP), which lets media cross a NAT. No consent check runs.
    ///
    /// @param remoteAddress the peer's media address, from its `c=` and `m=` lines
    /// @param suite         the crypto suite both sides chose
    /// @param localKey      the master key of the media this endpoint sends
    /// @param localSalt     the master salt of the media this endpoint sends
    /// @param remoteKey     the master key of the media the peer sends
    /// @param remoteSalt    the master salt of the media the peer sends
    /// @throws IllegalStateException if the transport is closed or already established
    /// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
    public void establishSdes(InetSocketAddress remoteAddress, SrtpCryptoSuite suite, byte[] localKey,
                              byte[] localSalt, byte[] remoteKey, byte[] remoteSalt) {
        ensureFresh();
        remote = Objects.requireNonNull(remoteAddress, "remoteAddress cannot be null");
        synchronized (lock) {
            outbound = new SrtpTransformer(localKey, localSalt, suite);
            inbound = new SrtpTransformer(remoteKey, remoteSalt, suite);
        }
    }

    /// Protects and sends an RTP packet to the remote media address.
    ///
    /// Packets must be sent one at a time: the SRTP context is not safe for concurrent protection.
    ///
    /// @param packet the packet
    /// @throws IOException           if protection or the send fails
    /// @throws IllegalStateException if the transport is closed or not established
    public void sendRtp(RtpPacket packet) throws IOException {
        var transformer = requireOutbound();
        var buffer = packet.encode(RTP_TAILROOM);
        var srtp = new SrtpPacket(buffer, 0, packet.length());
        var status = transformer.protectRtp(srtp);
        if (status != SrtpErrorStatus.OK) {
            throw new IOException("SRTP protection failed: " + status);
        }
        sendTo(Arrays.copyOf(buffer, srtp.length()), remote);
    }

    /// Protects a compound RTCP packet in place and sends it to the remote media address.
    ///
    /// The buffer is modified: the payload is encrypted and the SRTCP index and tag are written after it.
    ///
    /// @param buffer the packet followed by at least [#RTCP_TAILROOM] spare bytes
    /// @param length the packet length, without the spare bytes
    /// @throws IOException           if protection or the send fails
    /// @throws IllegalStateException if the transport is closed or not established
    public void sendRtcp(byte[] buffer, int length) throws IOException {
        var transformer = requireOutbound();
        var srtcp = new SrtpPacket(buffer, 0, length);
        var status = transformer.protectRtcp(srtcp);
        if (status != SrtpErrorStatus.OK) {
            throw new IOException("SRTCP protection failed: " + status);
        }
        sendTo(Arrays.copyOf(buffer, srtcp.length()), remote);
    }

    /// {@return the [System#nanoTime()] at which the last authenticated RTP or RTCP packet arrived, or `0` before
    /// any}
    public long lastMediaNanos() {
        return lastMediaNanos;
    }

    /// {@return the remote media address, or `null` before establishment}
    ///
    /// After an SDES establishment it follows the source of the last authenticated packet.
    public InetSocketAddress remoteAddress() {
        return remote;
    }

    /// Stops the transport: sends a DTLS `close_notify` when DTLS was used, closes the socket, which ends the receive
    /// and consent loops, and releases the SRTP contexts.
    ///
    /// Calling this method again has no effect. A thread blocked in an establishing method fails with an exception,
    /// at the latest when its timeout elapses.
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        var endpoint = dtls;
        if (endpoint != null) {
            endpoint.close();
        }
        socket.close();
        synchronized (lock) {
            if (outbound != null) {
                outbound.close();
            }
            if (inbound != null) {
                inbound.close();
            }
        }
    }

    /// Fails when the transport is closed or already keyed.
    ///
    /// @throws IllegalStateException if the transport cannot be established
    private void ensureFresh() {
        if (closed) {
            throw new IllegalStateException("transport is closed");
        }
        if (outbound != null || iceAgent != null) {
            throw new IllegalStateException("transport is already established");
        }
    }

    /// Installs the SRTP keys of a DTLS handshake.
    ///
    /// @param keys the keys
    private void installKeys(DtlsSrtpKeys keys) {
        var suite = keys.profile().suite();
        synchronized (lock) {
            outbound = new SrtpTransformer(keys.localKey(), keys.localSalt(), suite);
            inbound = new SrtpTransformer(keys.remoteKey(), keys.remoteSalt(), suite);
        }
    }

    /// {@return the outbound protection}
    ///
    /// @throws IllegalStateException if the transport is closed or not established
    private SrtpTransformer requireOutbound() {
        var transformer = outbound;
        if (transformer == null || closed) {
            throw new IllegalStateException(closed ? "transport is closed" : "transport is not established");
        }
        return transformer;
    }

    /// Sends a datagram.
    ///
    /// @param data   the datagram
    /// @param target the destination
    /// @throws IOException if the socket fails
    private void sendTo(byte[] data, InetSocketAddress target) throws IOException {
        socket.send(new DatagramPacket(data, data.length, target));
    }

    /// Receives and demultiplexes datagrams until the transport stops.
    private void receiveLoop() {
        var buffer = new byte[MAX_DATAGRAM];
        var packet = new DatagramPacket(buffer, buffer.length);
        while (!closed) {
            try {
                packet.setLength(buffer.length);
                socket.receive(packet);
            } catch (IOException exception) {
                if (!closed && LOGGER.isLoggable(Level.DEBUG)) {
                    LOGGER.log(Level.DEBUG, "RTC socket receive failed", exception);
                }
                return;
            }
            var source = (InetSocketAddress) packet.getSocketAddress();
            var length = packet.getLength();
            try {
                dispatch(buffer, length, source);
            } catch (RuntimeException exception) {
                if (LOGGER.isLoggable(Level.DEBUG)) {
                    LOGGER.log(Level.DEBUG, "dropped a malformed datagram", exception);
                }
            }
        }
    }

    /// Routes one received datagram by its first byte (RFC 7983).
    ///
    /// @param buffer the receive buffer
    /// @param length the datagram length
    /// @param source the datagram source
    private void dispatch(byte[] buffer, int length, InetSocketAddress source) {
        if (length == 0) {
            return;
        }
        var first = buffer[0] & 0xFF;
        if (first <= 3) {
            var agent = iceAgent;
            if (agent != null && StunMessage.isStun(buffer, 0, length)) {
                agent.handle(StunMessage.decode(buffer, 0, length), source);
            }
        } else if (first >= 20 && first <= 63) {
            var datagram = Arrays.copyOf(buffer, length);
            var endpoint = dtls;
            if (outbound == null) {
                dtlsQueue.offer(datagram);
            } else if (endpoint != null && endpoint.handleAfterHandshake(datagram) == DtlsEndpoint.AfterHandshake.CLOSED) {
                fail(Failure.CLOSED_BY_PEER, "the peer closed the DTLS association");
            }
        } else if (first >= 128 && first <= 191) {
            handleMedia(Arrays.copyOf(buffer, length), source);
        }
    }

    /// Unprotects one RTP or RTCP packet and hands it to the listener.
    ///
    /// @param data   the protected packet
    /// @param source its source
    private void handleMedia(byte[] data, InetSocketAddress source) {
        var transformer = inbound;
        if (transformer == null) {
            return;
        }
        var rtcp = RtpPacket.isRtcp(data, 0, data.length);
        var packet = new SrtpPacket(data, 0, data.length);
        var status = rtcp ? transformer.unprotectRtcp(packet) : transformer.unprotectRtp(packet);
        if (status != SrtpErrorStatus.OK) {
            if (status == SrtpErrorStatus.AUTH_FAIL || status == SrtpErrorStatus.FAIL) {
                int failures;
                synchronized (lock) {
                    failures = ++authFailures;
                }
                if (failures >= AUTH_FAILURE_LIMIT) {
                    fail(Failure.SRTP_AUTHENTICATION, failures + " consecutive packets failed SRTP authentication");
                }
            }
            return;
        }
        synchronized (lock) {
            authFailures = 0;
        }
        lastMediaNanos = System.nanoTime();
        if (iceAgent == null && !source.equals(remote)) {
            remote = source;
        }
        var current = listener;
        if (current == null) {
            return;
        }
        if (rtcp) {
            current.onRtcp(Arrays.copyOf(data, packet.length()));
        } else {
            current.onRtp(RtpPacket.decode(data, 0, packet.length()));
        }
    }

    /// Sends consent checks until the transport stops, failing it when consent expires.
    private void consentLoop() {
        while (!closed) {
            try {
                Thread.sleep(CONSENT_INTERVAL_MILLIS);
            } catch (InterruptedException exception) {
                return;
            }
            var agent = iceAgent;
            if (agent == null || closed) {
                return;
            }
            agent.refreshConsent();
            if (System.nanoTime() - agent.lastConsentNanos() > CONSENT_TIMEOUT_NANOS) {
                fail(Failure.CONSENT_EXPIRED, "the peer answered no consent check for 30 seconds");
                return;
            }
        }
    }

    /// Reports a failure once and stops the transport.
    ///
    /// @param failure the failure
    /// @param message the detail message
    private void fail(Failure failure, String message) {
        if (closed) {
            return;
        }
        if (LOGGER.isLoggable(Level.WARNING)) {
            LOGGER.log(Level.WARNING, "RTC transport failed: {0}: {1}", failure, message);
        }
        var current = listener;
        close();
        if (current != null) {
            current.onFailure(failure, message);
        }
    }

    /// The reasons a transport fails after establishment, as [Listener#onFailure(Failure,String)] reports them.
    public enum Failure {
        /// The peer answered no consent check for thirty seconds; only after a WebRTC establishment.
        CONSENT_EXPIRED,

        /// [RtcTransport#AUTH_FAILURE_LIMIT] consecutive incoming packets failed SRTP authentication.
        SRTP_AUTHENTICATION,

        /// The peer sent a DTLS alert after the handshake; only after a WebRTC establishment.
        CLOSED_BY_PEER
    }

    /// Receives the media and the failures of a transport.
    ///
    /// Callbacks run on the transport's receive thread, or on its consent thread for a consent failure, one at a time
    /// per thread. A slow callback delays every datagram behind it, so a callback should hand heavy work to another
    /// thread; a callback that throws loses only the packet it was handling.
    public interface Listener {
        /// Handles an unprotected RTP packet.
        ///
        /// @param packet the packet, which the listener owns
        void onRtp(RtpPacket packet);

        /// Handles an unprotected compound RTCP packet.
        ///
        /// @param packet the compound packet, exactly its bytes, which the listener owns
        void onRtcp(byte[] packet);

        /// Handles the failure of the transport, reported once; the transport is already closed.
        ///
        /// @param failure the reason
        /// @param message a detail message for logs
        void onFailure(Failure failure, String message);
    }
}
