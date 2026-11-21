package com.github.auties00.parley.jitter;

import java.time.Duration;

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
/// @spec https://www.w3.org/TR/webrtc-stats/#inboundrtpstats-dict* W3C Identifiers for WebRTC's Statistics API: RTCInboundRtpStreamStats
public record VideoAssemblerStatistics(long packetsReceived, long packetsDiscarded, long packetsRecovered,
                                       long packetsLost, long nackCount, long keyframeRequests, long framesReceived,
                                       long framesDropped, long keyframesReleased, Duration jitterBufferDelay,
                                       long jitterBufferEmittedCount, long freezeCount,
                                       Duration totalFreezesDuration) {
}
