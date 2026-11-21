package com.github.auties00.parley.peer;

import java.time.Instant;
import java.util.Objects;
import java.util.OptionalDouble;

/// The last packet from a synchronization source (SSRC) a receiver got packets from in the last ten seconds, the W3C `RTCRtpSynchronizationSource`.
///
/// @param source       the 32-bit source identifier
/// @param timestamp    when the last packet from the source was delivered to the track
/// @param rtpTimestamp the RTP timestamp of that packet
/// @param audioLevel   the audio level of that packet, `0` (silence) to `1` (0 dBov), from the audio level header
///                     extension, or an empty optional for video or when the extension is absent
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc6464.html RFC 6464: A Real-time Transport Protocol (RTP) Header Extension for Client-to-Mixer Audio Level Indication
public record SynchronizationSource(long source, Instant timestamp, long rtpTimestamp, OptionalDouble audioLevel) {
    /// Creates the source.
    ///
    /// @param source       the source identifier
    /// @param timestamp    the delivery time
    /// @param rtpTimestamp the RTP timestamp
    /// @param audioLevel   the audio level, or an empty optional
    public SynchronizationSource {
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(audioLevel, "audioLevel cannot be null");
    }
}
