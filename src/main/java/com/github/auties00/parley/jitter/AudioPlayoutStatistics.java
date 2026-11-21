package com.github.auties00.parley.jitter;

import java.time.Duration;

/// A snapshot of an [AudioPlayoutBuffer]'s counters, in the vocabulary of the W3C `RTCInboundRtpStreamStats`.
///
/// Sample counts are in units of the RTP clock rate (for Opus, 48 kHz samples per channel).
///
/// @param packetsReceived                the packets inserted, duplicates included
/// @param packetsLate                    the packets that arrived after their playout instant
/// @param packetsDiscarded               the packets dropped: late, duplicate, malformed, beyond the packet limit, or
///                                       skipped to shrink the delay
/// @param jitter                         the RFC 3550 interarrival jitter estimate
/// @param jitterBufferDelay              the sum, over emitted frames, of the time from arrival to playout
/// @param jitterBufferTargetDelay        the sum, over emitted frames, of the target delay at their playout
/// @param jitterBufferMinimumDelay       the sum, over emitted frames, of the delay the network alone required
/// @param jitterBufferEmittedCount       the frames emitted
/// @param totalSamplesReceived           the samples of the emitted frames plus the concealed ones
/// @param concealedSamples               the samples emitted as [AudioPlayout.Missing] or [AudioPlayout.Silence]
/// @param silentConcealedSamples         the samples emitted as [AudioPlayout.Silence]
/// @param concealmentEvents              the runs of consecutive [AudioPlayout.Missing] outcomes
/// @param insertedSamplesForDeceleration the samples concealed on purpose to grow the delay
/// @param removedSamplesForAcceleration  the samples of frames skipped on purpose to shrink the delay
/// @param targetDelay                    the current target delay
/// @spec https://www.w3.org/TR/webrtc-stats/#inboundrtpstats-dict* W3C Identifiers for WebRTC's Statistics API: RTCInboundRtpStreamStats
public record AudioPlayoutStatistics(long packetsReceived, long packetsLate, long packetsDiscarded, Duration jitter,
                                     Duration jitterBufferDelay, Duration jitterBufferTargetDelay,
                                     Duration jitterBufferMinimumDelay, long jitterBufferEmittedCount,
                                     long totalSamplesReceived, long concealedSamples, long silentConcealedSamples,
                                     long concealmentEvents, long insertedSamplesForDeceleration,
                                     long removedSamplesForAcceleration, Duration targetDelay) {
}
