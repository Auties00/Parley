package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;

/// The remote view of a received RTP stream, `remote-outbound-rtp`, from the sender reports of the peer.
///
/// @param id                        the identifier of this object
/// @param timestamp                 when the object was measured
/// @param ssrc                      the synchronization source of the stream, an unsigned 32-bit number
/// @param kind                      the media kind, `audio` or `video`
/// @param transportId               the id of the [TransportStats] the stream flows over
/// @param codecId                   the id of the [CodecStats] of the codec in use, or an empty optional before the first packet
/// @param localId                   the id of the matching [InboundRtpStreamStats]
/// @param packetsSent               the packets the peer reported having sent
/// @param bytesSent                 the payload bytes the peer reported having sent
/// @param remoteTimestamp           the NTP time of the last sender report, in the peer's clock
/// @param reportsSent               the sender reports received
/// @param roundTripTime             the last round-trip time measured through extended reports, in seconds, or an empty optional
/// @param totalRoundTripTime        the sum of the round-trip times measured, in seconds
/// @param roundTripTimeMeasurements the round-trip times measured
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record RemoteOutboundRtpStreamStats(String id, Instant timestamp, long ssrc, String kind, String transportId,
                                           Optional<String> codecId, String localId, long packetsSent, long bytesSent,
                                           Instant remoteTimestamp, long reportsSent, OptionalDouble roundTripTime,
                                           double totalRoundTripTime,
                                           long roundTripTimeMeasurements) implements RtcStats {
    /// Creates the statistics object.
    public RemoteOutboundRtpStreamStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(codecId, "codecId cannot be null");
        Objects.requireNonNull(localId, "localId cannot be null");
        Objects.requireNonNull(remoteTimestamp, "remoteTimestamp cannot be null");
        Objects.requireNonNull(roundTripTime, "roundTripTime cannot be null");
    }

    /// {@return `REMOTE_OUTBOUND_RTP`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.REMOTE_OUTBOUND_RTP;
    }
}
