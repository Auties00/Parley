package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;

/// The remote view of a sent RTP stream, `remote-inbound-rtp`, from the receiver reports of the peer.
///
/// @param id                        the identifier of this object
/// @param timestamp                 when the object was measured
/// @param ssrc                      the synchronization source of the stream, an unsigned 32-bit number
/// @param kind                      the media kind, `audio` or `video`
/// @param transportId               the id of the [TransportStats] the stream flows over
/// @param codecId                   the id of the [CodecStats] of the codec in use, or an empty optional before the first packet
/// @param localId                   the id of the matching [OutboundRtpStreamStats]
/// @param packetsLost               the cumulative packets lost the peer reported
/// @param jitter                    the interarrival jitter the peer reported, in seconds
/// @param fractionLost              the fraction of packets lost since the previous report, `0` to `1`
/// @param roundTripTime             the last round-trip time, in seconds, or an empty optional before the first measurement
/// @param totalRoundTripTime        the sum of the round-trip times measured, in seconds
/// @param roundTripTimeMeasurements the round-trip times measured
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record RemoteInboundRtpStreamStats(String id, Instant timestamp, long ssrc, String kind, String transportId,
                                          Optional<String> codecId, String localId, long packetsLost, double jitter,
                                          double fractionLost, OptionalDouble roundTripTime, double totalRoundTripTime,
                                          long roundTripTimeMeasurements) implements RtcStats {
    /// Creates the statistics object.
    public RemoteInboundRtpStreamStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(codecId, "codecId cannot be null");
        Objects.requireNonNull(localId, "localId cannot be null");
        Objects.requireNonNull(roundTripTime, "roundTripTime cannot be null");
    }

    /// {@return `REMOTE_INBOUND_RTP`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.REMOTE_INBOUND_RTP;
    }
}
