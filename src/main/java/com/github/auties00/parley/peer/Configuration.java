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

/// The configuration of a [PeerConnection], the W3C `RTCConfiguration` with Parley's own settings.
///
/// [PeerConnection#getConfiguration()] returns it and [PeerConnection#setConfiguration(Configuration)] changes the ICE
/// servers, the ICE transport policy and, before the first local description, the candidate pool size; every other
/// setting is fixed at construction.
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
/// @param threadFactory        the factory of every thread the connection starts
/// @param clock                the clock timers and statistics read
/// @param iceLite              whether the connection is an ICE-lite agent (for a server with a public address)
/// @param dtlsVersions         the DTLS versions offered
/// @param srtpProfiles         the SRTP protection profiles offered, in preference order
/// @param codecs               the codecs the application produces and consumes, audio and video, in preference
///                             order
/// @param headerExtensions     the RTP header extensions offered
/// @param remoteTrackMode      how remote tracks deliver media
/// @param minBitrate           the lowest send bitrate congestion control goes to, in bits per second
/// @param startBitrate         the send bitrate before the first estimate, in bits per second
/// @param maxBitrate           the highest send bitrate congestion control goes to, in bits per second
/// @param handshakeTimeout     the longest time a DTLS handshake may take
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public record Configuration(List<IceServer> iceServers, IceTransportPolicy iceTransportPolicy,
                            BundlePolicy bundlePolicy, RtcpMuxPolicy rtcpMuxPolicy,
                            List<DtlsCertificate> certificates, int iceCandidatePoolSize,
                            HostCandidatePolicy hostCandidatePolicy, Optional<NetworkStack> networkStack,
                            ThreadFactory threadFactory, MonotonicClock clock, boolean iceLite,
                            Set<DtlsVersion> dtlsVersions, List<SrtpProfile> srtpProfiles, List<Codec> codecs,
                            List<RtpHeaderExtensionCapability> headerExtensions, RemoteTrackMode remoteTrackMode,
                            long minBitrate, long startBitrate, long maxBitrate, Duration handshakeTimeout) {
    /// Creates a configuration, copying its collections.
    ///
    /// @param iceServers           the ICE servers
    /// @param iceTransportPolicy   the ICE transport policy
    /// @param bundlePolicy         the bundle policy
    /// @param rtcpMuxPolicy        the RTCP multiplexing policy
    /// @param certificates         the certificates
    /// @param iceCandidatePoolSize the candidate pool size
    /// @param hostCandidatePolicy  the host candidate policy
    /// @param networkStack         the network stack, or an empty optional
    /// @param threadFactory        the thread factory
    /// @param clock                the clock
    /// @param iceLite              whether the connection is ICE-lite
    /// @param dtlsVersions         the DTLS versions
    /// @param srtpProfiles         the SRTP profiles
    /// @param codecs               the codecs
    /// @param headerExtensions     the header extensions
    /// @param remoteTrackMode      the remote track mode
    /// @param minBitrate           the minimum bitrate
    /// @param startBitrate         the start bitrate
    /// @param maxBitrate           the maximum bitrate
    /// @param handshakeTimeout     the DTLS handshake timeout
    /// @throws IllegalArgumentException if `iceCandidatePoolSize` is outside `0..255`, `dtlsVersions`,
    ///                                  `srtpProfiles` or `codecs` is empty, the bitrates are not positive and
    ///                                  ordered, or `handshakeTimeout` is not positive
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
        Objects.requireNonNull(handshakeTimeout, "handshakeTimeout cannot be null");
        if (iceCandidatePoolSize < 0 || iceCandidatePoolSize > 255) {
            throw new IllegalArgumentException("iceCandidatePoolSize must be within 0..255");
        }
        if (dtlsVersions.isEmpty() || srtpProfiles.isEmpty() || codecs.isEmpty()) {
            throw new IllegalArgumentException("dtlsVersions, srtpProfiles and codecs cannot be empty");
        }
        if (minBitrate <= 0 || startBitrate < minBitrate || maxBitrate < startBitrate) {
            throw new IllegalArgumentException("bitrates must satisfy 0 < min <= start <= max");
        }
        if (handshakeTimeout.isNegative() || handshakeTimeout.isZero()) {
            throw new IllegalArgumentException("handshakeTimeout must be positive");
        }
    }

    /// {@return a builder with the default configuration}
    public static Builder builder() {
        return new Builder();
    }

    /// {@return a builder initialised with this configuration}
    public Builder toBuilder() {
        var builder = new Builder();
        builder.copyFrom(this);
        return builder;
    }

    /// Builds [Configuration]s.
    public static final class Builder extends ConfigurationBuilder<Builder> {
        /// Creates a builder with the defaults.
        Builder() {
        }

        @Override
        Builder self() {
            return this;
        }

        /// {@return the configuration}
        ///
        /// @throws IllegalArgumentException as the record constructor does
        public Configuration build() {
            return configuration();
        }
    }
}
