package com.github.auties00.parley.stats;

import com.github.auties00.parley.media.MediaKind;

import java.time.Instant;
import java.util.Objects;

/// The playout path of received audio, `media-playout`, measured by the jitter buffer.
///
/// @param id                         the identifier of this object
/// @param timestamp                  when the object was measured
/// @param kind                       the media kind, always [MediaKind#AUDIO]
/// @param synthesizedSamplesDuration the playout time the application had to conceal because no frame was due, in seconds
/// @param synthesizedSamplesEvents   the concealment periods
/// @param totalSamplesDuration       the playout time emitted, in seconds
/// @param totalPlayoutDelay          the sum of the delays between arrival and playout, in seconds
/// @param totalSamplesCount          the frames emitted
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record AudioPlayoutStats(String id, Instant timestamp, MediaKind kind, double synthesizedSamplesDuration,
                                long synthesizedSamplesEvents, double totalSamplesDuration, double totalPlayoutDelay,
                                long totalSamplesCount) implements RtcStats {
    /// Creates the statistics object.
    public AudioPlayoutStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(kind, "kind cannot be null");
    }

    /// {@return `MEDIA_PLAYOUT`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.MEDIA_PLAYOUT;
    }
}
