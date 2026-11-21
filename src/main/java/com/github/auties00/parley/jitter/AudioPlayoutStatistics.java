package com.github.auties00.parley.jitter;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;

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
/// @param clockRate                      the RTP clock rate the sample counts are in, in hertz
/// @param estimatedPlayoutTimestamp      the capture time, on the sender's clock, of the audio playing now: that of
///                                       the last frame handed out advanced by the time since, or an empty optional
///                                       before a frame with a known capture time
/// @param audioLevel                     the level of the last frame handed out, `0` to `1` (linear, from the RFC 6464
///                                       level in -dBov), or an empty optional when the stream carries no level
/// @param totalAudioEnergy               the sum over the frames handed out with a level of the squared level times
///                                       the frame duration in seconds
/// @param synchronizationDelay           the extra delay the buffer's [SyncGroup] currently adds, zero without one
/// @spec https://www.w3.org/TR/webrtc-stats/#inboundrtpstats-dict* W3C Identifiers for WebRTC's Statistics API: RTCInboundRtpStreamStats
public record AudioPlayoutStatistics(long packetsReceived, long packetsLate, long packetsDiscarded, Duration jitter,
                                     Duration jitterBufferDelay, Duration jitterBufferTargetDelay,
                                     Duration jitterBufferMinimumDelay, long jitterBufferEmittedCount,
                                     long totalSamplesReceived, long concealedSamples, long silentConcealedSamples,
                                     long concealmentEvents, long insertedSamplesForDeceleration,
                                     long removedSamplesForAcceleration, Duration targetDelay, int clockRate,
                                     Optional<Instant> estimatedPlayoutTimestamp, OptionalDouble audioLevel,
                                     double totalAudioEnergy, Duration synchronizationDelay) {
    /// Creates the snapshot.
    public AudioPlayoutStatistics {
        Objects.requireNonNull(jitter, "jitter cannot be null");
        Objects.requireNonNull(jitterBufferDelay, "jitterBufferDelay cannot be null");
        Objects.requireNonNull(jitterBufferTargetDelay, "jitterBufferTargetDelay cannot be null");
        Objects.requireNonNull(jitterBufferMinimumDelay, "jitterBufferMinimumDelay cannot be null");
        Objects.requireNonNull(targetDelay, "targetDelay cannot be null");
        Objects.requireNonNull(estimatedPlayoutTimestamp, "estimatedPlayoutTimestamp cannot be null");
        Objects.requireNonNull(audioLevel, "audioLevel cannot be null");
        Objects.requireNonNull(synchronizationDelay, "synchronizationDelay cannot be null");
    }

    /// {@return the playout time of [#totalSamplesReceived()]}
    public Duration totalSamplesDuration() {
        return Duration.ofSeconds(totalSamplesReceived / clockRate,
                (totalSamplesReceived % clockRate) * 1_000_000_000L / clockRate);
    }
}
