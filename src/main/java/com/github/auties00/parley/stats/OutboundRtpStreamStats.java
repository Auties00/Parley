package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// A sent RTP stream, `outbound-rtp`: one per encoding of a sender.
///
/// @param id                       the identifier of this object
/// @param timestamp                when the object was measured
/// @param ssrc                     the synchronization source of the stream, an unsigned 32-bit number
/// @param kind                     the media kind, `audio` or `video`
/// @param transportId              the id of the [TransportStats] the stream flows over
/// @param codecId                  the id of the [CodecStats] of the codec in use, or an empty optional before the first packet
/// @param mid                      the identification tag of the media section, or an empty optional
/// @param mediaSourceId            the id of the [MediaSourceStats] of the attached track, or an empty optional
/// @param remoteId                 the id of the matching [RemoteInboundRtpStreamStats], or an empty optional before the first receiver report
/// @param rid                      the RTP stream id of the encoding, or an empty optional
/// @param encodingIndex            the index of the encoding in the sender's parameters
/// @param packetsSent              the RTP packets sent, retransmissions excluded
/// @param bytesSent                the payload bytes sent, headers and padding excluded
/// @param headerBytesSent          the RTP header and padding bytes sent
/// @param retransmittedPacketsSent the packets retransmitted
/// @param retransmittedBytesSent   the payload bytes retransmitted
/// @param rtxSsrc                  the synchronization source of the retransmission stream, or an empty optional
/// @param targetBitrate            the target bitrate allocated to the encoding, in bits per second, or an empty optional before the first estimate
/// @param totalPacketSendDelay     the total time packets waited in the pacer, in seconds
/// @param framesEncoded            the frames the application wrote
/// @param keyFramesEncoded         the key frames the application wrote
/// @param framesSent               the frames whose packets were all sent
/// @param frameWidth               the width of the last frame in pixels, when the application stated it
/// @param frameHeight              the height of the last frame in pixels, when the application stated it
/// @param framesPerSecond          the frames sent in the last second, or an empty optional for audio
/// @param nackCount                the NACK packets received
/// @param firCount                 the full intra requests received
/// @param pliCount                 the picture loss indications received
/// @param active                   whether the encoding is active
/// @param scalabilityMode          the scalability mode of the encoding, such as `L1T3`, or an empty optional
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record OutboundRtpStreamStats(String id, Instant timestamp, long ssrc, String kind, String transportId,
                                     Optional<String> codecId, Optional<String> mid, Optional<String> mediaSourceId,
                                     Optional<String> remoteId, Optional<String> rid, int encodingIndex,
                                     long packetsSent, long bytesSent, long headerBytesSent,
                                     long retransmittedPacketsSent, long retransmittedBytesSent, OptionalLong rtxSsrc,
                                     OptionalLong targetBitrate, double totalPacketSendDelay, long framesEncoded,
                                     long keyFramesEncoded, long framesSent, OptionalInt frameWidth,
                                     OptionalInt frameHeight, OptionalDouble framesPerSecond, long nackCount,
                                     long firCount, long pliCount, boolean active,
                                     Optional<String> scalabilityMode) implements RtcStats {
    /// Creates the statistics object.
    public OutboundRtpStreamStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(codecId, "codecId cannot be null");
        Objects.requireNonNull(mid, "mid cannot be null");
        Objects.requireNonNull(mediaSourceId, "mediaSourceId cannot be null");
        Objects.requireNonNull(remoteId, "remoteId cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        Objects.requireNonNull(targetBitrate, "targetBitrate cannot be null");
        Objects.requireNonNull(frameWidth, "frameWidth cannot be null");
        Objects.requireNonNull(frameHeight, "frameHeight cannot be null");
        Objects.requireNonNull(framesPerSecond, "framesPerSecond cannot be null");
        Objects.requireNonNull(scalabilityMode, "scalabilityMode cannot be null");
    }

    /// {@return `OUTBOUND_RTP`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.OUTBOUND_RTP;
    }
}
