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
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadFactory;

/// The settings shared by [Configuration.Builder] and [PeerConnection.Builder], each method returning the concrete
/// builder.
///
/// The defaults are those of the W3C `RTCConfiguration` (no ICE servers, every candidate, `balanced` bundling, one
/// generated certificate, no candidate pool) plus host candidates with their real addresses, virtual threads, DTLS
/// 1.2 and 1.3, every SRTP profile with AES-GCM first, every codec Parley packetizes, jitter-buffered remote tracks,
/// a send bitrate between 30 kbit/s and 10 Mbit/s starting at 300 kbit/s, and a 30-second DTLS handshake timeout.
///
/// @param <B> the concrete builder type
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public abstract sealed class ConfigurationBuilder<B extends ConfigurationBuilder<B>>
        permits Configuration.Builder, PeerConnection.Builder {
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
    /// The network stack, or `null` for the JDK's.
    private NetworkStack networkStack;
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
    /// The minimum bitrate.
    private long minBitrate = 30_000;
    /// The start bitrate.
    private long startBitrate = 300_000;
    /// The maximum bitrate.
    private long maxBitrate = 10_000_000;
    /// The DTLS handshake timeout.
    private Duration handshakeTimeout = Duration.ofSeconds(30);
    /// Whether ICE gathers TCP candidates.
    private boolean tcpCandidates = true;
    /// Whether ICE gathers loopback candidates.
    private boolean loopbackCandidates;

    /// Creates a builder with the defaults.
    ConfigurationBuilder() {
    }

    /// {@return this builder as its concrete type}
    abstract B self();

    /// Copies every setting of a configuration.
    void copyFrom(Configuration configuration) {
        iceServers = configuration.iceServers();
        iceTransportPolicy = configuration.iceTransportPolicy();
        bundlePolicy = configuration.bundlePolicy();
        rtcpMuxPolicy = configuration.rtcpMuxPolicy();
        certificates = configuration.certificates();
        iceCandidatePoolSize = configuration.iceCandidatePoolSize();
        hostCandidatePolicy = configuration.hostCandidatePolicy();
        networkStack = configuration.networkStack().orElse(null);
        threadFactory = configuration.threadFactory();
        clock = configuration.clock();
        iceLite = configuration.iceLite();
        dtlsVersions = configuration.dtlsVersions();
        srtpProfiles = configuration.srtpProfiles();
        codecs = configuration.codecs();
        headerExtensions = configuration.headerExtensions();
        remoteTrackMode = configuration.remoteTrackMode();
        minBitrate = configuration.minBitrate();
        startBitrate = configuration.startBitrate();
        maxBitrate = configuration.maxBitrate();
        handshakeTimeout = configuration.handshakeTimeout();
        tcpCandidates = configuration.tcpCandidates();
        loopbackCandidates = configuration.loopbackCandidates();
    }

    /// {@return the configuration of the current settings}
    ///
    /// @throws IllegalArgumentException as the [Configuration] constructor does
    Configuration configuration() {
        return new Configuration(iceServers, iceTransportPolicy, bundlePolicy, rtcpMuxPolicy, certificates,
                iceCandidatePoolSize, hostCandidatePolicy, Optional.ofNullable(networkStack), threadFactory, clock,
                iceLite, dtlsVersions, srtpProfiles, codecs, headerExtensions, remoteTrackMode, minBitrate,
                startBitrate, maxBitrate, handshakeTimeout, tcpCandidates, loopbackCandidates);
    }

    /// Sets the STUN and TURN servers.
    ///
    /// @param servers the servers
    /// @return this builder
    public B iceServers(List<IceServer> servers) {
        iceServers = List.copyOf(servers);
        return self();
    }

    /// Sets which candidates ICE may use.
    ///
    /// @param policy the policy; `RELAY` uses TURN candidates only
    /// @return this builder
    public B iceTransportPolicy(IceTransportPolicy policy) {
        iceTransportPolicy = Objects.requireNonNull(policy, "policy cannot be null");
        return self();
    }

    /// Sets how media sections share transports.
    ///
    /// @param policy the policy
    /// @return this builder
    public B bundlePolicy(BundlePolicy policy) {
        bundlePolicy = Objects.requireNonNull(policy, "policy cannot be null");
        return self();
    }

    /// Sets the RTCP multiplexing policy.
    ///
    /// @param policy the policy
    /// @return this builder
    public B rtcpMuxPolicy(RtcpMuxPolicy policy) {
        rtcpMuxPolicy = Objects.requireNonNull(policy, "policy cannot be null");
        return self();
    }

    /// Sets the DTLS certificates, which the connection presents and fingerprints in its descriptions.
    ///
    /// @param newCertificates the certificates; empty to generate one
    /// @return this builder
    public B certificates(List<DtlsCertificate> newCertificates) {
        certificates = List.copyOf(newCertificates);
        return self();
    }

    /// Sets how many candidates to gather before the first local description.
    ///
    /// @param size the pool size, `0..255`
    /// @return this builder
    public B iceCandidatePoolSize(int size) {
        iceCandidatePoolSize = size;
        return self();
    }

    /// Sets whether host candidates expose local addresses.
    ///
    /// @param policy the policy
    /// @return this builder
    public B hostCandidatePolicy(HostCandidatePolicy policy) {
        hostCandidatePolicy = Objects.requireNonNull(policy, "policy cannot be null");
        return self();
    }

    /// Sets the network stack every socket of the connection goes through, to route it through a proxy or pick
    /// interfaces.
    ///
    /// @param stack the network stack
    /// @return this builder
    public B networkStack(NetworkStack stack) {
        networkStack = Objects.requireNonNull(stack, "stack cannot be null");
        return self();
    }

    /// Sets the factory of every thread the connection starts.
    ///
    /// @param factory the factory
    /// @return this builder
    public B threadFactory(ThreadFactory factory) {
        threadFactory = Objects.requireNonNull(factory, "factory cannot be null");
        return self();
    }

    /// Sets the clock timers and statistics read.
    ///
    /// @param newClock the clock
    /// @return this builder
    public B clock(MonotonicClock newClock) {
        clock = Objects.requireNonNull(newClock, "newClock cannot be null");
        return self();
    }

    /// Makes the connection an ICE-lite agent, which answers connectivity checks but sends none and gathers host
    /// candidates only; for a server with a public address, such as an SFU.
    ///
    /// @param lite whether the connection is ICE-lite
    /// @return this builder
    public B iceLite(boolean lite) {
        iceLite = lite;
        return self();
    }

    /// Sets the DTLS versions offered.
    ///
    /// @param versions the versions, at least one
    /// @return this builder
    public B dtlsVersions(Set<DtlsVersion> versions) {
        dtlsVersions = Set.copyOf(versions);
        return self();
    }

    /// Sets the SRTP protection profiles offered, in preference order.
    ///
    /// @param profiles the profiles, at least one
    /// @return this builder
    public B srtpProfiles(List<SrtpProfile> profiles) {
        srtpProfiles = List.copyOf(profiles);
        return self();
    }

    /// Sets the codecs the application produces and consumes, in preference order.
    ///
    /// Each must be a format Parley packetizes; retransmission (`video/rtx`), redundancy (`audio/red`, `video/red`)
    /// and FEC (`video/ulpfec`, `video/flexfec-03`) are enabled by listing them.
    ///
    /// @param newCodecs the codecs, at least one
    /// @return this builder
    public B codecs(List<Codec> newCodecs) {
        codecs = List.copyOf(newCodecs);
        return self();
    }

    /// Sets the RTP header extensions offered.
    ///
    /// @param extensions the extensions
    /// @return this builder
    public B headerExtensions(List<RtpHeaderExtensionCapability> extensions) {
        headerExtensions = List.copyOf(extensions);
        return self();
    }

    /// Sets how remote tracks deliver media.
    ///
    /// @param mode the mode
    /// @return this builder
    public B remoteTrackMode(RemoteTrackMode mode) {
        remoteTrackMode = Objects.requireNonNull(mode, "mode cannot be null");
        return self();
    }

    /// Sets the range congestion control keeps the total send bitrate in, and where it starts.
    ///
    /// @param min   the lowest bitrate, in bits per second
    /// @param start the bitrate before the first estimate
    /// @param max   the highest bitrate
    /// @return this builder
    public B bitrates(long min, long start, long max) {
        minBitrate = min;
        startBitrate = start;
        maxBitrate = max;
        return self();
    }

    /// Sets whether ICE gathers TCP host candidates (passive and active, RFC 6544) besides UDP ones; on by default.
    ///
    /// @param enabled whether TCP candidates are gathered
    /// @return this builder
    /// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
    public B tcpCandidates(boolean enabled) {
        tcpCandidates = enabled;
        return self();
    }

    /// Sets whether ICE gathers host candidates on loopback interfaces; off by default, on for two peers in one host
    /// or one test.
    ///
    /// @param enabled whether loopback candidates are gathered
    /// @return this builder
    public B loopbackCandidates(boolean enabled) {
        loopbackCandidates = enabled;
        return self();
    }

    /// Sets the longest time a DTLS handshake may take.
    ///
    /// @param timeout the timeout, positive
    /// @return this builder
    public B handshakeTimeout(Duration timeout) {
        handshakeTimeout = Objects.requireNonNull(timeout, "timeout cannot be null");
        return self();
    }
}
