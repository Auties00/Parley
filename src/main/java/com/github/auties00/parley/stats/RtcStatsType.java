package com.github.auties00.parley.stats;

import java.util.Objects;
import java.util.Optional;

/// The type of a statistics object, the value of the W3C `RTCStatsType` enumeration.
///
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public enum RtcStatsType {
    /// `codec`, a codec in use on a transport: [CodecStats].
    CODEC("codec"),
    /// `inbound-rtp`, a received RTP stream: [InboundRtpStreamStats].
    INBOUND_RTP("inbound-rtp"),
    /// `outbound-rtp`, a sent RTP stream: [OutboundRtpStreamStats].
    OUTBOUND_RTP("outbound-rtp"),
    /// `remote-inbound-rtp`, the remote view of a sent stream: [RemoteInboundRtpStreamStats].
    REMOTE_INBOUND_RTP("remote-inbound-rtp"),
    /// `remote-outbound-rtp`, the remote view of a received stream: [RemoteOutboundRtpStreamStats].
    REMOTE_OUTBOUND_RTP("remote-outbound-rtp"),
    /// `media-source`, a track attached to a sender: [MediaSourceStats].
    MEDIA_SOURCE("media-source"),
    /// `media-playout`, the playout path of received audio: [AudioPlayoutStats].
    MEDIA_PLAYOUT("media-playout"),
    /// `peer-connection`, the peer connection itself: [PeerConnectionStats].
    PEER_CONNECTION("peer-connection"),
    /// `data-channel`, a data channel: [DataChannelStats].
    DATA_CHANNEL("data-channel"),
    /// `transport`, an ICE and DTLS transport: [TransportStats].
    TRANSPORT("transport"),
    /// `candidate-pair`, an ICE candidate pair: [IceCandidatePairStats].
    CANDIDATE_PAIR("candidate-pair"),
    /// `local-candidate`, a local ICE candidate: [IceCandidateStats].
    LOCAL_CANDIDATE("local-candidate"),
    /// `remote-candidate`, a remote ICE candidate: [IceCandidateStats].
    REMOTE_CANDIDATE("remote-candidate"),
    /// `certificate`, a DTLS certificate: [CertificateStats].
    CERTIFICATE("certificate");

    /// The W3C enumeration value.
    private final String value;

    RtcStatsType(String value) {
        this.value = value;
    }

    /// {@return the type whose W3C value is `value`, or an empty optional when `value` names none}
    ///
    /// @param value the W3C value, such as `inbound-rtp`
    public static Optional<RtcStatsType> of(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        for (var type : values()) {
            if (type.value.equals(value)) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }

    /// {@return the W3C enumeration value, such as `inbound-rtp`}
    public String value() {
        return value;
    }
}
