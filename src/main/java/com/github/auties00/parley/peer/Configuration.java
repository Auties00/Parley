package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsVersion;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.ice.HostCandidatePolicy;
import com.github.auties00.parley.ice.IceServer;
import com.github.auties00.parley.ice.IceTransportPolicy;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.net.NetworkStack;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadFactory;

/// The configuration of a [PeerConnection], the W3C `RTCConfiguration` with Parley's own settings.
///
/// [PeerConnection#create(Configuration)] takes it, [PeerConnection#getConfiguration()] returns it and
/// [PeerConnection#setConfiguration(Configuration)] changes the ICE servers, the ICE transport policy and, before the
/// first local description, the candidate pool size; every other setting is fixed at construction. Build one with
/// [#builder()], or copy one with changes through [#toBuilder()].
///
/// {@snippet lang = java :
/// var configuration = Configuration.builder()
///         .iceServers(IceServer.of("stun:stun.example.org"))
///         .bundlePolicy(BundlePolicy.MAX_BUNDLE)
///         .build();
/// var pc = PeerConnection.create(configuration);
/// }
///
/// @param iceServers           the STUN and TURN servers
/// @param iceTransportPolicy   which candidates ICE may use
/// @param bundlePolicy         how media sections share transports
/// @param rtcpMuxPolicy        the RTCP multiplexing policy
/// @param certificates         the DTLS certificates; empty to generate one ECDSA P-256 certificate per connection
/// @param iceCandidatePoolSize the candidates to gather before the first local description, `0..255`
/// @param hostCandidatePolicy  whether host candidates expose local addresses, hide them behind mDNS names, or are
///                             left out
/// @param networkStack         the sockets ICE, STUN and TURN use, or an empty optional for the JDK's
/// @param threadFactory        the factory of every thread the connection and its tracks start
/// @param clock                the clock timers, DTMF timing and statistics read
/// @param iceLite              whether the connection is an ICE-lite agent (for a server with a public address)
/// @param dtlsVersions         the DTLS versions offered
/// @param srtpProfiles         the SRTP protection profiles offered, in preference order
/// @param codecs               the codecs the application produces and consumes, audio and video, in preference
///                             order
/// @param headerExtensions     the RTP header extensions offered
/// @param remoteTrackMode      how remote tracks deliver media, unless a transceiver chooses its own
/// @param bitrates             the range congestion control keeps the total send bitrate in
/// @param handshakeTimeout     the longest time ICE connectivity plus the DTLS handshake may take
/// @param tcpCandidates        whether ICE gathers TCP host candidates (RFC 6544) besides UDP ones
/// @param loopbackCandidates   whether ICE gathers host candidates on loopback interfaces, for peers on one host
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public record Configuration(List<IceServer> iceServers, IceTransportPolicy iceTransportPolicy,
                            BundlePolicy bundlePolicy, RtcpMuxPolicy rtcpMuxPolicy,
                            List<DtlsCertificate> certificates, int iceCandidatePoolSize,
                            HostCandidatePolicy hostCandidatePolicy, Optional<NetworkStack> networkStack,
                            ThreadFactory threadFactory, MonotonicClock clock, boolean iceLite,
                            Set<DtlsVersion> dtlsVersions, List<SrtpProfile> srtpProfiles, List<Codec> codecs,
                            List<RtpHeaderExtensionCapability> headerExtensions, RemoteTrackMode remoteTrackMode,
                            Bitrates bitrates, Duration handshakeTimeout, boolean tcpCandidates,
                            boolean loopbackCandidates) {
    /// Creates a configuration, copying its collections.
    ///
    /// @throws IllegalArgumentException if `iceCandidatePoolSize` is outside `0..255`, `dtlsVersions`,
    ///                                  `srtpProfiles` or `codecs` is empty, or `handshakeTimeout` is not positive
    /// @throws InvalidAccessException   if a certificate has expired, as W3C `RTCPeerConnection` construction
    ///                                  requires
    public Configuration {
        iceServers = List.copyOf(iceServers);
        Objects.requireNonNull(iceTransportPolicy, "iceTransportPolicy cannot be null");
        Objects.requireNonNull(bundlePolicy, "bundlePolicy cannot be null");
        Objects.requireNonNull(rtcpMuxPolicy, "rtcpMuxPolicy cannot be null");
        certificates = List.copyOf(certificates);
        Objects.requireNonNull(hostCandidatePolicy, "hostCandidatePolicy cannot be null");
        Objects.requireNonNull(networkStack, "networkStack cannot be null");
        Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
        Objects.requireNonNull(clock, "clock cannot be null");
        dtlsVersions = Set.copyOf(dtlsVersions);
        srtpProfiles = List.copyOf(srtpProfiles);
        codecs = List.copyOf(codecs);
        headerExtensions = List.copyOf(headerExtensions);
        Objects.requireNonNull(remoteTrackMode, "remoteTrackMode cannot be null");
        Objects.requireNonNull(bitrates, "bitrates cannot be null");
        Objects.requireNonNull(handshakeTimeout, "handshakeTimeout cannot be null");
        if (iceCandidatePoolSize < 0 || iceCandidatePoolSize > 255) {
            throw new IllegalArgumentException("iceCandidatePoolSize must be within 0..255");
        }
        if (dtlsVersions.isEmpty() || srtpProfiles.isEmpty() || codecs.isEmpty()) {
            throw new IllegalArgumentException("dtlsVersions, srtpProfiles and codecs cannot be empty");
        }
        if (handshakeTimeout.isNegative() || handshakeTimeout.isZero()) {
            throw new IllegalArgumentException("handshakeTimeout must be positive");
        }
        var now = Instant.now();
        for (var certificate : certificates) {
            if (certificate.isExpired(now)) {
                throw new InvalidAccessException("the certificate expired at " + certificate.expires());
            }
        }
    }

    /// {@return a builder with the default configuration}
    ///
    /// The defaults are those of the W3C `RTCConfiguration` (no ICE servers, every candidate, `balanced` bundling,
    /// one generated certificate, no candidate pool) plus host candidates with their real addresses, virtual threads,
    /// DTLS 1.2 and 1.3, every SRTP profile with AES-GCM first, every codec Parley packetizes, jitter-buffered
    /// remote tracks, [Bitrates#DEFAULT], a 30-second handshake timeout and TCP candidates.
    public static Builder builder() {
        return new Builder();
    }

    /// {@return a builder initialised with this configuration}
    public Builder toBuilder() {
        var builder = new Builder();
        builder.iceServers = iceServers;
        builder.iceTransportPolicy = iceTransportPolicy;
        builder.bundlePolicy = bundlePolicy;
        builder.rtcpMuxPolicy = rtcpMuxPolicy;
        builder.certificates = certificates;
        builder.iceCandidatePoolSize = iceCandidatePoolSize;
        builder.hostCandidatePolicy = hostCandidatePolicy;
        builder.networkStack = networkStack;
        builder.threadFactory = threadFactory;
        builder.clock = clock;
        builder.iceLite = iceLite;
        builder.dtlsVersions = dtlsVersions;
        builder.srtpProfiles = srtpProfiles;
        builder.codecs = codecs;
        builder.headerExtensions = headerExtensions;
        builder.remoteTrackMode = remoteTrackMode;
        builder.bitrates = bitrates;
        builder.handshakeTimeout = handshakeTimeout;
        builder.tcpCandidates = tcpCandidates;
        builder.loopbackCandidates = loopbackCandidates;
        return builder;
    }

    /// Builds [Configuration]s; every setter returns the builder.
    public static final class Builder {
        /// The ICE servers.
        private List<IceServer> iceServers = List.of();
        /// The ICE transport policy.
        private IceTransportPolicy iceTransportPolicy = IceTransportPolicy.ALL;
        /// The bundle policy.
        private BundlePolicy bundlePolicy = BundlePolicy.BALANCED;
        /// The RTCP multiplexing policy.
        private RtcpMuxPolicy rtcpMuxPolicy = RtcpMuxPolicy.REQUIRE;
        /// The certificates.
        private List<DtlsCertificate> certificates = List.of();
        /// The candidate pool size.
        private int iceCandidatePoolSize;
        /// The host candidate policy.
        private HostCandidatePolicy hostCandidatePolicy = HostCandidatePolicy.EXPOSE;
        /// The network stack, or an empty optional for the JDK's.
        private Optional<NetworkStack> networkStack = Optional.empty();
        /// The thread factory.
        private ThreadFactory threadFactory = Thread.ofVirtual().name("parley-", 0).factory();
        /// The clock.
        private MonotonicClock clock = MonotonicClock.system();
        /// Whether the connection is ICE-lite.
        private boolean iceLite;
        /// The DTLS versions.
        private Set<DtlsVersion> dtlsVersions = Set.of(DtlsVersion.DTLS_1_2, DtlsVersion.DTLS_1_3);
        /// The SRTP profiles.
        private List<SrtpProfile> srtpProfiles = List.of(SrtpProfile.AEAD_AES_128_GCM, SrtpProfile.AEAD_AES_256_GCM,
                SrtpProfile.AES128_CM_HMAC_SHA1_80, SrtpProfile.AES128_CM_HMAC_SHA1_32);
        /// The codecs.
        private List<Codec> codecs = CodecCatalog.defaultCodecs();
        /// The header extensions.
        private List<RtpHeaderExtensionCapability> headerExtensions = CodecCatalog.defaultHeaderExtensions();
        /// The remote track mode.
        private RemoteTrackMode remoteTrackMode = RemoteTrackMode.JITTER_BUFFERED;
        /// The bitrate range.
        private Bitrates bitrates = Bitrates.DEFAULT;
        /// The handshake timeout.
        private Duration handshakeTimeout = Duration.ofSeconds(30);
        /// Whether ICE gathers TCP candidates.
        private boolean tcpCandidates = true;
        /// Whether ICE gathers loopback candidates.
        private boolean loopbackCandidates;

        /// Creates a builder with the defaults.
        private Builder() {
        }

        /// Sets the STUN and TURN servers.
        ///
        /// @param servers the servers
        /// @return this builder
        public Builder iceServers(IceServer... servers) {
            return iceServers(List.of(servers));
        }

        /// Sets the STUN and TURN servers.
        ///
        /// @param servers the servers
        /// @return this builder
        public Builder iceServers(List<IceServer> servers) {
            iceServers = List.copyOf(servers);
            return this;
        }

        /// Sets which candidates ICE may use.
        ///
        /// @param policy the policy; `RELAY` uses TURN candidates only
        /// @return this builder
        public Builder iceTransportPolicy(IceTransportPolicy policy) {
            iceTransportPolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets how media sections share transports.
        ///
        /// @param policy the policy
        /// @return this builder
        public Builder bundlePolicy(BundlePolicy policy) {
            bundlePolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets the RTCP multiplexing policy.
        ///
        /// @param policy the policy
        /// @return this builder
        public Builder rtcpMuxPolicy(RtcpMuxPolicy policy) {
            rtcpMuxPolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets the DTLS certificates, which the connection presents and fingerprints in its descriptions.
        ///
        /// @param newCertificates the certificates; empty to generate one
        /// @return this builder
        public Builder certificates(List<DtlsCertificate> newCertificates) {
            certificates = List.copyOf(newCertificates);
            return this;
        }

        /// Sets how many candidates to gather before the first local description.
        ///
        /// @param size the pool size, `0..255`
        /// @return this builder
        public Builder iceCandidatePoolSize(int size) {
            iceCandidatePoolSize = size;
            return this;
        }

        /// Sets whether host candidates expose local addresses.
        ///
        /// @param policy the policy
        /// @return this builder
        public Builder hostCandidatePolicy(HostCandidatePolicy policy) {
            hostCandidatePolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets the network stack every socket of the connection goes through, to route it through a proxy or pick
        /// interfaces.
        ///
        /// @param stack the network stack
        /// @return this builder
        public Builder networkStack(NetworkStack stack) {
            networkStack = Optional.of(stack);
            return this;
        }

        /// Sets the factory of every thread the connection and its tracks start.
        ///
        /// @param factory the factory
        /// @return this builder
        public Builder threadFactory(ThreadFactory factory) {
            threadFactory = Objects.requireNonNull(factory, "factory cannot be null");
            return this;
        }

        /// Sets the clock timers, DTMF timing and statistics read.
        ///
        /// @param newClock the clock
        /// @return this builder
        public Builder clock(MonotonicClock newClock) {
            clock = Objects.requireNonNull(newClock, "newClock cannot be null");
            return this;
        }

        /// Makes the connection an ICE-lite agent, which answers connectivity checks but sends none and gathers
        /// host candidates only; for a server with a public address, such as an SFU.
        ///
        /// @param lite whether the connection is ICE-lite
        /// @return this builder
        public Builder iceLite(boolean lite) {
            iceLite = lite;
            return this;
        }

        /// Sets the DTLS versions offered.
        ///
        /// @param versions the versions, at least one
        /// @return this builder
        public Builder dtlsVersions(Set<DtlsVersion> versions) {
            dtlsVersions = Set.copyOf(versions);
            return this;
        }

        /// Sets the SRTP protection profiles offered, in preference order.
        ///
        /// @param profiles the profiles, at least one
        /// @return this builder
        public Builder srtpProfiles(List<SrtpProfile> profiles) {
            srtpProfiles = List.copyOf(profiles);
            return this;
        }

        /// Sets the codecs the application produces and consumes, in preference order.
        ///
        /// Each must be a format Parley packetizes; retransmission (`video/rtx`), redundancy (`audio/red`,
        /// `video/red`) and FEC (`video/ulpfec`, `video/flexfec-03`) are enabled by listing them.
        ///
        /// @param newCodecs the codecs, at least one
        /// @return this builder
        public Builder codecs(List<Codec> newCodecs) {
            codecs = List.copyOf(newCodecs);
            return this;
        }

        /// Sets the RTP header extensions offered.
        ///
        /// @param extensions the extensions
        /// @return this builder
        public Builder headerExtensions(List<RtpHeaderExtensionCapability> extensions) {
            headerExtensions = List.copyOf(extensions);
            return this;
        }

        /// Sets how remote tracks deliver media, unless a transceiver chooses its own.
        ///
        /// @param mode the mode
        /// @return this builder
        public Builder remoteTrackMode(RemoteTrackMode mode) {
            remoteTrackMode = Objects.requireNonNull(mode, "mode cannot be null");
            return this;
        }

        /// Sets the range congestion control keeps the total send bitrate in, and where it starts.
        ///
        /// @param newBitrates the range
        /// @return this builder
        public Builder bitrates(Bitrates newBitrates) {
            bitrates = Objects.requireNonNull(newBitrates, "newBitrates cannot be null");
            return this;
        }

        /// Sets whether ICE gathers TCP host candidates (passive and active, RFC 6544) besides UDP ones; on by
        /// default.
        ///
        /// @param enabled whether TCP candidates are gathered
        /// @return this builder
        /// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
        public Builder tcpCandidates(boolean enabled) {
            tcpCandidates = enabled;
            return this;
        }

        /// Sets whether ICE gathers host candidates on loopback interfaces; off by default, on for two peers in one
        /// host or one test.
        ///
        /// @param enabled whether loopback candidates are gathered
        /// @return this builder
        public Builder loopbackCandidates(boolean enabled) {
            loopbackCandidates = enabled;
            return this;
        }

        /// Sets the longest time ICE connectivity plus the DTLS handshake of a transport may take.
        ///
        /// @param timeout the timeout, positive
        /// @return this builder
        public Builder handshakeTimeout(Duration timeout) {
            handshakeTimeout = Objects.requireNonNull(timeout, "timeout cannot be null");
            return this;
        }

        /// {@return the configuration}
        ///
        /// @throws IllegalArgumentException as the record constructor does
        /// @throws InvalidAccessException   if a certificate has expired
        public Configuration build() {
            return new Configuration(iceServers, iceTransportPolicy, bundlePolicy, rtcpMuxPolicy, certificates,
                    iceCandidatePoolSize, hostCandidatePolicy, networkStack, threadFactory, clock, iceLite,
                    dtlsVersions, srtpProfiles, codecs, headerExtensions, remoteTrackMode, bitrates, handshakeTimeout,
                    tcpCandidates, loopbackCandidates);
        }
    }
}
