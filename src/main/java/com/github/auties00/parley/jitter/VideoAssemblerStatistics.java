package com.github.auties00.parley.jitter;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;

/// A snapshot of a [VideoFrameAssembler]'s counters, in the vocabulary of the W3C `RTCInboundRtpStreamStats` where
/// one applies.
///
/// @param packetsReceived           the packets inserted, duplicates included
/// @param packetsDiscarded          the packets dropped: duplicate, malformed, too old, or beyond the packet limit
/// @param packetsRecovered          the packets that arrived after the assembler had asked for them
/// @param packetsLost               the packets the assembler gave up waiting for
/// @param nackCount                 the NACK requests sent, one per packet per request
/// @param keyframeRequests          the keyframe requests sent
/// @param framesReceived            the complete frames assembled
/// @param framesDropped             the complete frames dropped: undecodable, malformed, or older than a released
///                                  one
/// @param keyframesReleased         the keyframes released
/// @param jitterBufferDelay         the sum, over released frames, of the time from their first packet's arrival to
///                                  their release
/// @param jitterBufferEmittedCount  the frames released
/// @param freezeCount               the freezes: gaps between releases longer than three times the average gap, or
///                                  the average plus 150 ms, whichever is larger
/// @param totalFreezesDuration      the total length of the freezes
/// @param frameWidth                the width of the last released frame whose metadata carries its size
/// @param frameHeight               the height of that frame
/// @param framesPerSecond           the frames handed out in the last second, or an empty optional before the first
/// @param estimatedPlayoutTimestamp the capture time, on the sender's clock, of the video showing now: that of the
///                                  last frame handed out advanced by the time since, or an empty optional before a
///                                  frame with a known capture time
/// @param synchronizationDelay      the extra delay the assembler's [SyncGroup] currently adds, zero without one
/// @spec https://www.w3.org/TR/webrtc-stats/#inboundrtpstats-dict* W3C Identifiers for WebRTC's Statistics API: RTCInboundRtpStreamStats
public record VideoAssemblerStatistics(long packetsReceived, long packetsDiscarded, long packetsRecovered,
                                       long packetsLost, long nackCount, long keyframeRequests, long framesReceived,
                                       long framesDropped, long keyframesReleased, Duration jitterBufferDelay,
                                       long jitterBufferEmittedCount, long freezeCount,
                                       Duration totalFreezesDuration, OptionalInt frameWidth,
                                       OptionalInt frameHeight, OptionalDouble framesPerSecond,
                                       Optional<Instant> estimatedPlayoutTimestamp, Duration synchronizationDelay) {
    /// Creates the snapshot.
    public VideoAssemblerStatistics {
        Objects.requireNonNull(jitterBufferDelay, "jitterBufferDelay cannot be null");
        Objects.requireNonNull(totalFreezesDuration, "totalFreezesDuration cannot be null");
        Objects.requireNonNull(frameWidth, "frameWidth cannot be null");
        Objects.requireNonNull(frameHeight, "frameHeight cannot be null");
        Objects.requireNonNull(framesPerSecond, "framesPerSecond cannot be null");
        Objects.requireNonNull(estimatedPlayoutTimestamp, "estimatedPlayoutTimestamp cannot be null");
        Objects.requireNonNull(synchronizationDelay, "synchronizationDelay cannot be null");
    }
}
