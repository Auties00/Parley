package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// A received RTP stream, `inbound-rtp`, measured by the receiver.
///
/// @param id                           the identifier of this object
/// @param timestamp                    when the object was measured
/// @param ssrc                         the synchronization source of the stream, an unsigned 32-bit number
/// @param kind                         the media kind, `audio` or `video`
/// @param transportId                  the id of the [TransportStats] the stream flows over
/// @param codecId                      the id of the [CodecStats] of the codec in use, or an empty optional before the first packet
/// @param trackIdentifier              the id of the remote track the stream feeds, or an empty optional
/// @param mid                          the identification tag of the media section, or an empty optional
/// @param remoteId                     the id of the matching [RemoteOutboundRtpStreamStats], or an empty optional before the first sender report
/// @param packetsReceived              the RTP packets received, retransmissions excluded
/// @param packetsLost                  the packets expected but not received, as RFC 3550 counts them; may be negative with duplicates
/// @param jitter                       the interarrival jitter, in seconds
/// @param bytesReceived                the payload bytes received, headers and padding excluded
/// @param headerBytesReceived          the RTP header and padding bytes received
/// @param packetsDiscarded             the packets dropped by the jitter buffer for arriving too late or as duplicates
/// @param fecPacketsReceived           the forward error correction packets received
/// @param fecPacketsDiscarded          the forward error correction packets that recovered nothing
/// @param fecBytesReceived             the forward error correction payload bytes received
/// @param retransmittedPacketsReceived the retransmitted packets received
/// @param retransmittedBytesReceived   the retransmitted payload bytes received
/// @param rtxSsrc                      the synchronization source of the retransmission stream, or an empty optional
/// @param fecSsrc                      the synchronization source of the FEC stream, or an empty optional
/// @param nackCount                    the NACK packets sent
/// @param firCount                     the full intra requests sent
/// @param pliCount                     the picture loss indications sent
/// @param framesReceived               the complete frames assembled
/// @param keyFramesReceived            the complete key frames assembled
/// @param framesDropped                the frames dropped before reaching the application
/// @param frameWidth                   the width of the last frame in pixels, when its payload format carries it
/// @param frameHeight                  the height of the last frame in pixels, when its payload format carries it
/// @param framesPerSecond              the frames received in the last second, or an empty optional for audio
/// @param lastPacketReceivedTimestamp  when the last packet arrived, or an empty optional before the first
/// @param estimatedPlayoutTimestamp    the estimated playout time of the last frame, from the sender report clock mapping, or an empty optional
/// @param jitterBufferDelay            the total time frames spent in the jitter buffer, in seconds
/// @param jitterBufferTargetDelay      the sum of the jitter buffer target delays at each emission, in seconds
/// @param jitterBufferMinimumDelay     the sum of the jitter buffer minimum delays at each emission, in seconds
/// @param jitterBufferEmittedCount     the frames (video) or packets (audio) that left the jitter buffer
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record InboundRtpStreamStats(String id, Instant timestamp, long ssrc, String kind, String transportId,
                                    Optional<String> codecId, Optional<String> trackIdentifier, Optional<String> mid,
                                    Optional<String> remoteId, long packetsReceived, long packetsLost, double jitter,
                                    long bytesReceived, long headerBytesReceived, long packetsDiscarded,
                                    long fecPacketsReceived, long fecPacketsDiscarded, long fecBytesReceived,
                                    long retransmittedPacketsReceived, long retransmittedBytesReceived,
                                    OptionalLong rtxSsrc, OptionalLong fecSsrc, long nackCount, long firCount,
                                    long pliCount, long framesReceived, long keyFramesReceived, long framesDropped,
                                    OptionalInt frameWidth, OptionalInt frameHeight, OptionalDouble framesPerSecond,
                                    Optional<Instant> lastPacketReceivedTimestamp,
                                    Optional<Instant> estimatedPlayoutTimestamp, double jitterBufferDelay,
                                    double jitterBufferTargetDelay, double jitterBufferMinimumDelay,
                                    long jitterBufferEmittedCount) implements RtcStats {
    /// Creates the statistics object.
    public InboundRtpStreamStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(codecId, "codecId cannot be null");
        Objects.requireNonNull(trackIdentifier, "trackIdentifier cannot be null");
        Objects.requireNonNull(mid, "mid cannot be null");
        Objects.requireNonNull(remoteId, "remoteId cannot be null");
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        Objects.requireNonNull(fecSsrc, "fecSsrc cannot be null");
        Objects.requireNonNull(frameWidth, "frameWidth cannot be null");
        Objects.requireNonNull(frameHeight, "frameHeight cannot be null");
        Objects.requireNonNull(framesPerSecond, "framesPerSecond cannot be null");
        Objects.requireNonNull(lastPacketReceivedTimestamp, "lastPacketReceivedTimestamp cannot be null");
        Objects.requireNonNull(estimatedPlayoutTimestamp, "estimatedPlayoutTimestamp cannot be null");
    }

    /// {@return `INBOUND_RTP`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.INBOUND_RTP;
    }
}
