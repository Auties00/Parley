package com.github.auties00.parley.peer;

import java.util.Objects;
import java.util.Optional;

/// An event a [LocalTrack] raises towards the encoder that feeds it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
public sealed interface LocalTrackEvent {
    /// The peer asked for a key frame (a picture loss indication or a full intra request), or a new receiver joined.
    ///
    /// @param rid the RTP stream id of the layer that needs the key frame, or an empty optional without simulcast
    record KeyframeRequested(Optional<String> rid) implements LocalTrackEvent {
        /// Creates the event.
        ///
        /// @param rid the layer, or an empty optional
        public KeyframeRequested {
            Objects.requireNonNull(rid, "rid cannot be null");
        }
    }

    /// The bitrate allocated to an encoding changed; the encoder should aim for it.
    ///
    /// @param rid           the RTP stream id of the layer, or an empty optional without simulcast
    /// @param bitsPerSecond the target, in bits per second, payload and RTP headers included
    record TargetBitrateChanged(Optional<String> rid, long bitsPerSecond) implements LocalTrackEvent {
        /// Creates the event.
        ///
        /// @param rid           the layer, or an empty optional
        /// @param bitsPerSecond the target bitrate
        public TargetBitrateChanged {
            Objects.requireNonNull(rid, "rid cannot be null");
        }
    }

    /// The track ended; no event follows.
    record Ended() implements LocalTrackEvent {
    }
}
