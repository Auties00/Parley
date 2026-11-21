package com.github.auties00.parley.peer;

import java.util.Objects;
import java.util.Optional;

/// An event a [LocalTrack] raises towards the encoder that feeds it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
/// @spec https://www.w3.org/TR/webrtc-encoded-transform/ WebRTC Encoded Transform
public sealed interface LocalTrackEvent {
    /// The peer asked for a key frame (a picture loss indication or a full intra request), a new receiver joined, or
    /// the application called [RtpSender#generateKeyFrame()].
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
    /// A stream keeps only the latest undelivered change of each layer, so a slow reader sees the current target
    /// rather than every intermediate one.
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

    /// The parameters of an encoding the track feeds were negotiated or changed through
    /// [RtpSender#setParameters(RtpSendParameters)]; the encoder should follow them: stop producing an inactive
    /// layer, scale its resolution down by `scaleResolutionDownBy`, cap its frame rate at `maxFramerate`, and use
    /// its scalability mode.
    ///
    /// A stream keeps only the latest undelivered change of each layer.
    ///
    /// @param rid      the RTP stream id of the layer, or an empty optional without simulcast
    /// @param encoding the encoding's parameters
    record EncodingChanged(Optional<String> rid, Encoding encoding) implements LocalTrackEvent {
        /// Creates the event.
        ///
        /// @param rid      the layer, or an empty optional
        /// @param encoding the parameters
        public EncodingChanged {
            Objects.requireNonNull(rid, "rid cannot be null");
            Objects.requireNonNull(encoding, "encoding cannot be null");
        }
    }

    /// The track ended; no event follows.
    record Ended() implements LocalTrackEvent {
    }
}
