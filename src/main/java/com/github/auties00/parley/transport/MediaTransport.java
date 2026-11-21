package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsConfig;
import com.github.auties00.parley.dtls.DtlsException;
import com.github.auties00.parley.dtls.DtlsFingerprint;
import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.dtls.DtlsVersion;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.ice.HostCandidatePolicy;
import com.github.auties00.parley.ice.IceAgent;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceEvent;
import com.github.auties00.parley.ice.IceException;
import com.github.auties00.parley.ice.IceParameters;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.ice.IceServer;
import com.github.auties00.parley.ice.IceTransportPolicy;
import com.github.auties00.parley.ice.IceTransportState;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.srtp.SrtpCryptoSuite;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/// Carries the SRTP media of one session over one datagram path, without the W3C object model: ICE (controlling or
/// controlled) or a fixed UDP address, DTLS-SRTP or SDES keying, RTP and RTCP multiplexed on one port, and failure
/// reporting.
///
/// A transport is built in one of two modes, then established once:
///
/// | Mode | Built with | Established with |
/// |---|---|---|
/// | ICE | [Builder#build()] | [#establishDtlsSrtp(IceParameters,List,DtlsRole,List,Duration)] (`UDP/TLS/RTP/SAVPF`), [#establishSdes(IceParameters,List,SrtpCryptoSuite,byte\[\],byte\[\],byte\[\],byte\[\],Duration)] |
/// | UDP | [Builder#buildUdp(InetSocketAddress)] | [#establishDtlsSrtp(InetSocketAddress,DtlsRole,List,Duration)], [#establishSdes(InetSocketAddress,SrtpCryptoSuite,byte\[\],byte\[\],byte\[\],byte\[\])] (`RTP/SAVP`) |
///
/// {@snippet lang = java :
/// var transport = MediaTransport.builder()
///         .iceRole(IceRole.CONTROLLING)
///         .eventListener(event -> log(event))
///         .build();
/// // signal transport.iceAgent().orElseThrow().localParameters(), its candidates and transport.fingerprints()
/// transport.setRtpReceiver((packet, arrival) -> handleRtp(packet));
/// var profile = transport.establishDtlsSrtp(remoteIce, remoteCandidates, DtlsRole.CLIENT, remoteFingerprints,
///         Duration.ofSeconds(10));
/// transport.sendRtp(rtpBuffer);
/// }
///
/// # Failure
///
/// After it is established the transport fails, closes itself and reports one [MediaTransportEvent.Failed] when ICE
/// moves to `failed` (consent expired), when [Builder#authenticationFailureLimit(int)] consecutive packets fail SRTP
/// authentication, or when the DTLS association is closed by the peer or fails. [#close()] stops it without a report.
///
/// # Threading
///
/// Events are delivered serially, in order, on one thread from the builder's thread factory. Receivers are called on
/// the path's reader thread. The establishing methods block the calling thread; every other method may be called from
/// any thread.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
/// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
/// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
/// @spec https://www.rfc-editor.org/rfc/rfc4961.html RFC 4961: Symmetric RTP / RTP Control Protocol (RTCP)
public final class MediaTransport implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(MediaTransport.class.getName());

    /// The default number of consecutive packets failing SRTP authentication that fails the transport.
    public static final int DEFAULT_AUTHENTICATION_FAILURE_LIMIT = 200;

    /// The marker that stops the event thread.
    private static final Object STOP = new Object();

    /// A receiver that drops everything.
    private static final PacketReceiver DISCARD = (packet, arrivalNanos) -> {
    };

    /// The settings.
    private final Builder settings;

    /// The certificate.
    private final DtlsCertificate certificate;

    /// The ICE agent in ICE mode, or `null`.
    private final IceAgent iceAgent;

    /// The UDP path in UDP mode, or `null`.
    private final UdpPath udpPath;

    /// The events waiting for the event thread.
    private final LinkedBlockingQueue<Object> events = new LinkedBlockingQueue<>();

    /// Whether an establishing method was called.
    private final AtomicBoolean establishing = new AtomicBoolean();

    /// Whether the transport is closed or failed.
    private final AtomicBoolean closed = new AtomicBoolean();

    /// The DTLS transport, `null` unless DTLS-SRTP keys the transport.
    private volatile DtlsTransport dtls;

    /// The SRTP transport, `null` before establishment.
    private volatile SrtpTransport srtp;

    /// Whether establishment completed.
    private volatile boolean established;

    /// The receiver of RTP.
    private volatile PacketReceiver rtpReceiver = DISCARD;

    /// The receiver of RTCP.
    private volatile PacketReceiver rtcpReceiver = DISCARD;

    /// The clock time of the last authenticated packet, or `Long.MIN_VALUE` before any.
    private volatile long lastMediaNanos = Long.MIN_VALUE;

    /// Creates a transport; the path is already open.
    private MediaTransport(Builder settings, DtlsCertificate certificate, IceAgent iceAgent, UdpPath udpPath) {
        this.settings = settings;
        this.certificate = certificate;
        this.iceAgent = iceAgent;
        this.udpPath = udpPath;
        settings.threadFactory.newThread(this::eventLoop).start();
    }

    /// {@return a builder with the defaults: the system network stack, virtual threads, the controlling ICE role, a
    /// fresh ECDSA certificate, both DTLS versions, every SRTP profile, no cryptex}
    public static Builder builder() {
        return new Builder();
    }

    /// {@return the ICE agent of an ICE-mode transport, for its local parameters and candidates and for trickling
    /// remote candidates; empty in UDP mode}
    public Optional<IceAgent> iceAgent() {
        return Optional.ofNullable(iceAgent);
    }

    /// {@return the local address of a UDP-mode transport, for the `c=` and `m=` lines; empty in ICE mode}
    public Optional<InetSocketAddress> localAddress() {
        return udpPath == null ? Optional.empty() : Optional.of(udpPath.localAddress());
    }

    /// {@return the remote media address of a UDP-mode transport, which follows the peer under symmetric RTP; empty
    /// before establishment and in ICE mode, where the agent's selected pair names it}
    public Optional<InetSocketAddress> remoteAddress() {
        return udpPath == null ? Optional.empty() : Optional.ofNullable(udpPath.remoteAddress());
    }

    /// {@return the DTLS certificate this side presents}
    public DtlsCertificate certificate() {
        return certificate;
    }

    /// {@return the fingerprints of [#certificate()], one `a=fingerprint` line each}
    public List<DtlsFingerprint> fingerprints() {
        return certificate.fingerprints();
    }

    /// {@return the DTLS transport, present once a DTLS-SRTP establishment started}
    public Optional<DtlsTransport> dtls() {
        return Optional.ofNullable(dtls);
    }

    /// {@return the SRTP transport, present once an establishment started}
    public Optional<RtpTransport> rtp() {
        return Optional.ofNullable(srtp);
    }

    /// Establishes the media path with ICE and a DTLS-SRTP handshake; ICE mode only.
    ///
    /// Hands the peer's parameters and candidates to the agent and signals the end of its candidates, waits until ICE
    /// connects, then runs the DTLS handshake in `role` over the selected pair and keys SRTP. The DTLS transport is
    /// created before ICE connects, so a peer that starts its handshake first is not lost.
    ///
    /// @param remoteParameters   the peer's `a=ice-ufrag`, `a=ice-pwd` and `a=ice-lite`
    /// @param remoteCandidates   the peer's candidates, all of them
    /// @param role               the DTLS role, from `a=setup`
    /// @param remoteFingerprints the peer's `a=fingerprint` values
    /// @param timeout            the longest time ICE and the handshake may take together
    /// @return the negotiated SRTP profile
    /// @throws IceException          if ICE fails or does not connect in time
    /// @throws DtlsException         if the handshake fails or does not complete in time
    /// @throws InterruptedException  if the calling thread is interrupted
    /// @throws IllegalStateException if the transport is in UDP mode, closed, or already established or establishing
    public SrtpProfile establishDtlsSrtp(IceParameters remoteParameters, List<IceCandidate> remoteCandidates,
                                        DtlsRole role, List<DtlsFingerprint> remoteFingerprints, Duration timeout)
            throws IceException, DtlsException, InterruptedException {
        Objects.requireNonNull(remoteParameters, "remoteParameters cannot be null");
        Objects.requireNonNull(remoteCandidates, "remoteCandidates cannot be null");
        Objects.requireNonNull(role, "role cannot be null");
        Objects.requireNonNull(remoteFingerprints, "remoteFingerprints cannot be null");
        var deadline = System.nanoTime() + timeout.toNanos();
        startEstablishing(true);
        var dtlsTransport = createDtls(iceAgent);
        iceAgent.setRemoteParameters(remoteParameters);
        for (var candidate : remoteCandidates) {
            iceAgent.addRemoteCandidate(candidate);
        }
        iceAgent.endOfRemoteCandidates();
        iceAgent.awaitConnected(remaining(deadline));
        var keys = dtlsTransport.handshake(role, remoteFingerprints, remaining(deadline));
        markEstablished(Optional.of(keys.profile()));
        return keys.profile();
    }

    /// Establishes the media path with a DTLS-SRTP handshake to a fixed address, without ICE; UDP mode only.
    ///
    /// Only datagrams from `remote` are accepted.
    ///
    /// @param remote             the peer's media address
    /// @param role               the DTLS role
    /// @param remoteFingerprints the peer's `a=fingerprint` values
    /// @param timeout            the longest time the handshake may take
    /// @return the negotiated SRTP profile
    /// @throws DtlsException         if the handshake fails or does not complete in time
    /// @throws InterruptedException  if the calling thread is interrupted
    /// @throws IllegalStateException if the transport is in ICE mode, closed, or already established or establishing
    public SrtpProfile establishDtlsSrtp(InetSocketAddress remote, DtlsRole role,
                                        List<DtlsFingerprint> remoteFingerprints, Duration timeout)
            throws DtlsException, InterruptedException {
        Objects.requireNonNull(remote, "remote cannot be null");
        Objects.requireNonNull(role, "role cannot be null");
        startEstablishing(false);
        udpPath.connect(remote, false, true);
        var dtlsTransport = createDtls(udpPath);
        var keys = dtlsTransport.handshake(role, remoteFingerprints, timeout);
        markEstablished(Optional.of(keys.profile()));
        return keys.profile();
    }

    /// Establishes the media path with SDES keys to a fixed address, without ICE or DTLS; UDP mode only; returns at
    /// once.
    ///
    /// Packets go to `remote`; when an authenticated packet arrives from another address, the transport sends to that
    /// address instead (symmetric RTP), which lets media cross a NAT.
    ///
    /// @param remote     the peer's media address, from its `c=` and `m=` lines
    /// @param suite      the crypto suite both `a=crypto` lines agreed
    /// @param localKey   the master key of the media this side sends
    /// @param localSalt  the master salt of the media this side sends
    /// @param remoteKey  the master key of the media the peer sends
    /// @param remoteSalt the master salt of the media the peer sends
    /// @throws IllegalArgumentException if a key or salt has the wrong length for the suite
    /// @throws IllegalStateException    if the transport is in ICE mode, closed, or already established
    public void establishSdes(InetSocketAddress remote, SrtpCryptoSuite suite, byte[] localKey, byte[] localSalt,
                              byte[] remoteKey, byte[] remoteSalt) {
        Objects.requireNonNull(remote, "remote cannot be null");
        startEstablishing(false);
        udpPath.connect(remote, true, false);
        installSrtp(SrtpTransport.sdes(udpPath, suite, localKey, localSalt, remoteKey, remoteSalt,
                settings.srtpOptions));
        markEstablished(Optional.empty());
    }

    /// Establishes the media path with ICE and SDES keys, without DTLS; ICE mode only.
    ///
    /// @param remoteParameters the peer's ICE parameters
    /// @param remoteCandidates the peer's candidates, all of them
    /// @param suite            the crypto suite both `a=crypto` lines agreed
    /// @param localKey         the master key of the media this side sends
    /// @param localSalt        the master salt of the media this side sends
    /// @param remoteKey        the master key of the media the peer sends
    /// @param remoteSalt       the master salt of the media the peer sends
    /// @param timeout          the longest time ICE may take
    /// @throws IceException             if ICE fails or does not connect in time
    /// @throws InterruptedException     if the calling thread is interrupted
    /// @throws IllegalArgumentException if a key or salt has the wrong length for the suite
    /// @throws IllegalStateException    if the transport is in UDP mode, closed, or already established or
    ///                                  establishing
    public void establishSdes(IceParameters remoteParameters, List<IceCandidate> remoteCandidates,
                              SrtpCryptoSuite suite, byte[] localKey, byte[] localSalt, byte[] remoteKey,
                              byte[] remoteSalt, Duration timeout) throws IceException, InterruptedException {
        Objects.requireNonNull(remoteParameters, "remoteParameters cannot be null");
        startEstablishing(true);
        installSrtp(SrtpTransport.sdes(iceAgent, suite, localKey, localSalt, remoteKey, remoteSalt,
                settings.srtpOptions));
        iceAgent.setRemoteParameters(remoteParameters);
        for (var candidate : remoteCandidates) {
            iceAgent.addRemoteCandidate(candidate);
        }
        iceAgent.endOfRemoteCandidates();
        iceAgent.awaitConnected(timeout);
        markEstablished(Optional.empty());
    }

    /// Protects and sends an RTP packet; see [RtpTransport#sendRtp(ByteBuffer)] for the buffer contract.
    ///
    /// @param plainRtp the packet
    /// @throws IOException           if protection or the path fails
    /// @throws IllegalStateException if the transport is not established or is closed
    public void sendRtp(ByteBuffer plainRtp) throws IOException {
        requireSrtp().sendRtp(plainRtp);
    }

    /// Protects and sends a compound RTCP packet; see [RtpTransport#sendRtcp(ByteBuffer)] for the buffer contract.
    ///
    /// @param plainCompoundRtcp the packet
    /// @throws IOException           if protection or the path fails
    /// @throws IllegalStateException if the transport is not established or is closed
    public void sendRtcp(ByteBuffer plainCompoundRtcp) throws IOException {
        requireSrtp().sendRtcp(plainCompoundRtcp);
    }

    /// Sets the receiver of unprotected RTP packets, replacing the previous one; set it before establishing, since
    /// packets that arrive while none is set are dropped.
    ///
    /// @param receiver the receiver
    public void setRtpReceiver(PacketReceiver receiver) {
        this.rtpReceiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    /// Sets the receiver of unprotected compound RTCP packets, replacing the previous one.
    ///
    /// @param receiver the receiver
    public void setRtcpReceiver(PacketReceiver receiver) {
        this.rtcpReceiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    /// {@return the bytes a buffer needs after its limit to be protected in place, or the largest possible value
    /// before establishment}
    public int protectionOverhead() {
        var current = srtp;
        return current == null ? 20 : current.protectionOverhead();
    }

    /// {@return a snapshot of the counters}
    public MediaTransportStatistics statistics() {
        var currentSrtp = srtp;
        var currentDtls = dtls;
        var last = lastMediaNanos;
        return new MediaTransportStatistics(
                Optional.ofNullable(currentSrtp).map(SrtpTransport::statistics),
                Optional.ofNullable(currentDtls).map(DtlsTransport::statistics),
                last == Long.MIN_VALUE ? OptionalLong.empty() : OptionalLong.of(last));
    }

    /// Stops the transport: closes the DTLS association with `close_notify` when there is one, the SRTP contexts and
    /// the path, which ends its threads. Calling this method again has no effect; a thread blocked in an establishing
    /// method fails, at the latest when its timeout elapses.
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        shutDown();
        events.add(STOP);
    }

    /// Closes every layer.
    private void shutDown() {
        var currentDtls = dtls;
        if (currentDtls != null) {
            currentDtls.close();
        }
        var currentSrtp = srtp;
        if (currentSrtp != null) {
            currentSrtp.close();
        }
        if (iceAgent != null) {
            try {
                iceAgent.close();
            } catch (RuntimeException exception) {
                if (LOGGER.isLoggable(Level.DEBUG)) {
                    LOGGER.log(Level.DEBUG, "closing the ICE agent failed", exception);
                }
            }
        }
        if (udpPath != null) {
            udpPath.close();
        }
    }

    /// Claims the one establishment, checking the mode.
    private void startEstablishing(boolean ice) {
        if (ice != (iceAgent != null)) {
            throw new IllegalStateException(ice ? "the transport was built in UDP mode" : "the transport was built in ICE mode");
        }
        if (closed.get()) {
            throw new IllegalStateException("the transport is closed");
        }
        if (!establishing.compareAndSet(false, true)) {
            throw new IllegalStateException("the transport is already established or establishing");
        }
    }

    /// Creates the DTLS transport over a path and the SRTP transport over it.
    private DtlsTransport createDtls(DatagramTransport path) {
        var config = new DtlsConfig(List.of(certificate), settings.srtpProfiles, settings.dtlsVersions,
                settings.initialRetransmit, settings.clock, settings.threadFactory, settings.cookieExchange);
        var transport = DtlsTransport.over(path, config);
        transport.setStateListener(this::onDtlsState);
        dtls = transport;
        installSrtp(SrtpTransport.dtlsSrtp(transport, settings.srtpOptions));
        return transport;
    }

    /// Wires the SRTP transport's receivers and failure listener.
    private void installSrtp(SrtpTransport transport) {
        transport.setRtpReceiver((packet, arrival) -> onMedia(packet, arrival, false));
        transport.setRtcpReceiver((packet, arrival) -> onMedia(packet, arrival, true));
        transport.setFailureListener(consecutive -> {
            if (established && consecutive >= settings.authenticationFailureLimit) {
                fail(new MediaTransportFailure.SrtpAuthentication(consecutive));
            }
        });
        srtp = transport;
    }

    /// Delivers an authenticated packet and confirms its source to a latching path.
    private void onMedia(ByteBuffer packet, long arrival, boolean rtcp) {
        lastMediaNanos = arrival;
        if (udpPath != null) {
            udpPath.confirmSource();
        }
        (rtcp ? rtcpReceiver : rtpReceiver).receive(packet, arrival);
    }

    /// Marks the transport established and reports it.
    private void markEstablished(Optional<SrtpProfile> profile) {
        established = true;
        events.add(new MediaTransportEvent.Established(profile));
    }

    /// Forwards an ICE event and fails on ICE failure after establishment.
    private void onIceEvent(IceEvent event) {
        events.add(new MediaTransportEvent.Ice(event));
        if (event instanceof IceEvent.StateChanged(var state) && state == IceTransportState.FAILED && established) {
            fail(new MediaTransportFailure.ConsentExpired());
        }
    }

    /// Forwards a DTLS state change and fails when the association ends after establishment.
    private void onDtlsState(DtlsState state) {
        events.add(new MediaTransportEvent.DtlsStateChanged(state));
        if (!established || closed.get()) {
            return;
        }
        switch (state) {
            case CLOSED -> fail(new MediaTransportFailure.DtlsClosedByPeer());
            case FAILED -> fail(new MediaTransportFailure.DtlsFailed(Optional.empty()));
            default -> {
            }
        }
    }

    /// Fails the transport once: closes it and reports the failure as the last event.
    private void fail(MediaTransportFailure failure) {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        if (LOGGER.isLoggable(Level.WARNING)) {
            LOGGER.log(Level.WARNING, "media transport failed: {0}", failure.message());
        }
        shutDown();
        events.add(new MediaTransportEvent.Failed(failure));
        events.add(STOP);
    }

    /// {@return the SRTP transport}
    ///
    /// @throws IllegalStateException if the transport is not established or is closed
    private SrtpTransport requireSrtp() {
        var current = srtp;
        if (current == null || closed.get()) {
            throw new IllegalStateException(closed.get() ? "the transport is closed" : "the transport is not established");
        }
        return current;
    }

    /// Delivers events to the listener, serially, until the transport stops.
    private void eventLoop() {
        try {
            while (true) {
                var event = events.take();
                if (event == STOP) {
                    return;
                }
                try {
                    settings.eventListener.accept((MediaTransportEvent) event);
                } catch (RuntimeException exception) {
                    if (LOGGER.isLoggable(Level.WARNING)) {
                        LOGGER.log(Level.WARNING, "a media transport listener failed", exception);
                    }
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    /// {@return the time left before a deadline, at least one nanosecond}
    private static Duration remaining(long deadline) {
        return Duration.ofNanos(Math.max(1, deadline - System.nanoTime()));
    }

    /// Configures and builds a [MediaTransport].
    ///
    /// Every setting has a default; [#build()] opens an ICE-mode transport and starts gathering, [#buildUdp(InetSocketAddress)]
    /// binds a UDP-mode one.
    public static final class Builder {
        /// The thread factory.
        private ThreadFactory threadFactory = Thread.ofVirtual().name("parley-media-", 0).factory();

        /// The network stack, `null` for the system stack.
        private NetworkStack networkStack;

        /// The clock.
        private MonotonicClock clock = MonotonicClock.system();

        /// The certificate, `null` for a generated one.
        private DtlsCertificate certificate;

        /// The DTLS versions.
        private Set<DtlsVersion> dtlsVersions = EnumSet.allOf(DtlsVersion.class);

        /// The SRTP profiles.
        private List<SrtpProfile> srtpProfiles = List.of(SrtpProfile.values());

        /// The SRTP options.
        private SrtpOptions srtpOptions = SrtpOptions.DEFAULT;

        /// The first DTLS retransmission timeout.
        private Duration initialRetransmit = DtlsConfig.DEFAULT_INITIAL_RETRANSMIT;

        /// Whether a DTLS server demands a cookie.
        private boolean cookieExchange = true;

        /// The ICE servers.
        private List<IceServer> iceServers = List.of();

        /// The ICE candidate policy.
        private IceTransportPolicy iceTransportPolicy = IceTransportPolicy.ALL;

        /// The host candidate policy.
        private HostCandidatePolicy hostCandidatePolicy = HostCandidatePolicy.EXPOSE;

        /// The ICE role.
        private IceRole iceRole = IceRole.CONTROLLING;

        /// Whether the agent is lite.
        private boolean iceLite;

        /// The local ICE parameters, `null` for generated ones.
        private IceParameters iceParameters;

        /// The authentication failure limit.
        private int authenticationFailureLimit = DEFAULT_AUTHENTICATION_FAILURE_LIMIT;

        /// The event listener.
        private Consumer<MediaTransportEvent> eventListener = _ -> {
        };

        /// Creates a builder with the defaults.
        private Builder() {
        }

        /// Sets the factory of every thread the transport and its layers start.
        ///
        /// @param threadFactory the factory
        /// @return this builder
        public Builder threadFactory(ThreadFactory threadFactory) {
            this.threadFactory = Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
            return this;
        }

        /// Sets the network stack every socket is opened through; by default the system stack with the builder's
        /// thread factory.
        ///
        /// @param networkStack the stack
        /// @return this builder
        public Builder networkStack(NetworkStack networkStack) {
            this.networkStack = Objects.requireNonNull(networkStack, "networkStack cannot be null");
            return this;
        }

        /// Sets the clock of timers and arrival times.
        ///
        /// @param clock the clock
        /// @return this builder
        public Builder clock(MonotonicClock clock) {
            this.clock = Objects.requireNonNull(clock, "clock cannot be null");
            return this;
        }

        /// Sets the DTLS certificate; by default a fresh ECDSA one is generated at build time.
        ///
        /// @param certificate the certificate
        /// @return this builder
        public Builder certificate(DtlsCertificate certificate) {
            this.certificate = Objects.requireNonNull(certificate, "certificate cannot be null");
            return this;
        }

        /// Sets the DTLS versions to negotiate.
        ///
        /// @param versions the versions, not empty
        /// @return this builder
        public Builder dtlsVersions(Set<DtlsVersion> versions) {
            if (versions.isEmpty()) {
                throw new IllegalArgumentException("versions cannot be empty");
            }
            this.dtlsVersions = Set.copyOf(versions);
            return this;
        }

        /// Sets the SRTP profiles a DTLS-SRTP handshake negotiates, in preference order.
        ///
        /// @param profiles the profiles, not empty
        /// @return this builder
        public Builder srtpProfiles(List<SrtpProfile> profiles) {
            if (profiles.isEmpty()) {
                throw new IllegalArgumentException("profiles cannot be empty");
            }
            this.srtpProfiles = List.copyOf(profiles);
            return this;
        }

        /// Sets the SRTP options, cryptex among them.
        ///
        /// @param options the options
        /// @return this builder
        public Builder srtpOptions(SrtpOptions options) {
            this.srtpOptions = Objects.requireNonNull(options, "options cannot be null");
            return this;
        }

        /// Sets the first DTLS retransmission timeout.
        ///
        /// @param timeout the timeout, positive
        /// @return this builder
        public Builder dtlsInitialRetransmit(Duration timeout) {
            if (timeout.isNegative() || timeout.isZero()) {
                throw new IllegalArgumentException("timeout must be positive");
            }
            this.initialRetransmit = timeout;
            return this;
        }

        /// Sets whether a DTLS server demands a cookie exchange; ICE already proves the peer's address, so turning it
        /// off saves a round trip.
        ///
        /// @param cookieExchange whether to demand a cookie
        /// @return this builder
        public Builder dtlsCookieExchange(boolean cookieExchange) {
            this.cookieExchange = cookieExchange;
            return this;
        }

        /// Sets the STUN and TURN servers of the ICE agent.
        ///
        /// @param servers the servers
        /// @return this builder
        public Builder iceServers(List<IceServer> servers) {
            this.iceServers = List.copyOf(servers);
            return this;
        }

        /// Sets which candidates the ICE agent uses.
        ///
        /// @param policy the policy
        /// @return this builder
        public Builder iceTransportPolicy(IceTransportPolicy policy) {
            this.iceTransportPolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets how host candidates are exposed.
        ///
        /// @param policy the policy
        /// @return this builder
        public Builder hostCandidatePolicy(HostCandidatePolicy policy) {
            this.hostCandidatePolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets the ICE role; the offerer is usually controlling.
        ///
        /// @param role the role
        /// @return this builder
        public Builder iceRole(IceRole role) {
            this.iceRole = Objects.requireNonNull(role, "role cannot be null");
            return this;
        }

        /// Sets whether the ICE agent is a lite agent, which only answers checks.
        ///
        /// @param lite whether the agent is lite
        /// @return this builder
        public Builder iceLite(boolean lite) {
            this.iceLite = lite;
            return this;
        }

        /// Sets the local ICE parameters; by default fresh ones are generated.
        ///
        /// @param parameters the parameters
        /// @return this builder
        public Builder iceParameters(IceParameters parameters) {
            this.iceParameters = Objects.requireNonNull(parameters, "parameters cannot be null");
            return this;
        }

        /// Sets how many consecutive packets failing SRTP authentication fail the transport.
        ///
        /// @param limit the limit, positive
        /// @return this builder
        public Builder authenticationFailureLimit(int limit) {
            if (limit <= 0) {
                throw new IllegalArgumentException("limit must be positive");
            }
            this.authenticationFailureLimit = limit;
            return this;
        }

        /// Sets the listener of events, called serially on one thread.
        ///
        /// @param listener the listener
        /// @return this builder
        public Builder eventListener(Consumer<MediaTransportEvent> listener) {
            this.eventListener = Objects.requireNonNull(listener, "listener cannot be null");
            return this;
        }

        /// Builds an ICE-mode transport and starts gathering candidates; they are reported as
        /// [MediaTransportEvent.Ice] events and listed by the agent.
        ///
        /// @return the transport
        public MediaTransport build() {
            var stack = stack();
            var holder = new MediaTransport[1];
            var agentBuilder = IceAgent.builder()
                    .networkStack(stack)
                    .clock(clock)
                    .iceServers(iceServers)
                    .transportPolicy(iceTransportPolicy)
                    .hostCandidatePolicy(hostCandidatePolicy)
                    .role(iceRole)
                    .lite(iceLite)
                    .eventListener(event -> {
                        var transport = holder[0];
                        if (transport != null) {
                            transport.onIceEvent(event);
                        }
                    });
            if (iceParameters != null) {
                agentBuilder.localParameters(iceParameters);
            }
            var agent = agentBuilder.build();
            var transport = new MediaTransport(this, certificate(), agent, null);
            holder[0] = transport;
            agent.gather();
            return transport;
        }

        /// Binds a UDP-mode transport, with no ICE.
        ///
        /// @param bindAddress the local address to bind; port `0` for an ephemeral one
        /// @return the transport
        /// @throws IOException if the socket cannot be bound
        public MediaTransport buildUdp(InetSocketAddress bindAddress) throws IOException {
            Objects.requireNonNull(bindAddress, "bindAddress cannot be null");
            var endpoint = stack().bindUdp(bindAddress);
            var holder = new MediaTransport[1];
            var path = new UdpPath(endpoint, clock, threadFactory, exception -> {
                var transport = holder[0];
                if (transport != null && transport.established) {
                    transport.fail(new MediaTransportFailure.PathFailed(String.valueOf(exception.getMessage())));
                }
            });
            var transport = new MediaTransport(this, certificate(), null, path);
            holder[0] = transport;
            return transport;
        }

        /// {@return the configured stack or the system one}
        private NetworkStack stack() {
            return networkStack != null ? networkStack : NetworkStack.system(threadFactory);
        }

        /// {@return the configured certificate or a fresh one}
        private DtlsCertificate certificate() {
            return certificate != null ? certificate : DtlsCertificate.generateEcdsa();
        }
    }
}
