package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.OptionalDouble;
import java.util.OptionalInt;

/// A track attached to a sender, `media-source` (the W3C `RTCAudioSourceStats` and `RTCVideoSourceStats` in one record).
///
/// @param id              the identifier of this object
/// @param timestamp       when the object was measured
/// @param trackIdentifier the id of the local track
/// @param kind            the media kind, `audio` or `video`
/// @param audioLevel      the audio level of the last frame, `0` to `1`, when the application stated it
/// @param width           the width of the last video frame in pixels, when the application stated it
/// @param height          the height of the last video frame in pixels, when the application stated it
/// @param frames          the frames the application wrote to the track
/// @param framesPerSecond the frames written in the last second, or an empty optional for audio
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record MediaSourceStats(String id, Instant timestamp, String trackIdentifier, String kind,
                               OptionalDouble audioLevel, OptionalInt width, OptionalInt height, long frames,
                               OptionalDouble framesPerSecond) implements RtcStats {
    /// Creates the statistics object.
    public MediaSourceStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(trackIdentifier, "trackIdentifier cannot be null");
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(audioLevel, "audioLevel cannot be null");
        Objects.requireNonNull(width, "width cannot be null");
        Objects.requireNonNull(height, "height cannot be null");
        Objects.requireNonNull(framesPerSecond, "framesPerSecond cannot be null");
    }

    /// {@return `MEDIA_SOURCE`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.MEDIA_SOURCE;
    }
}
