package com.github.auties00.parley.peer;

/// An event of a [RemoteTrack], the W3C `MediaStreamTrack` `mute`, `unmute` and `ended` events of a track a
/// receiver delivers to.
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public sealed interface RemoteTrackEvent {
    /// The track stopped receiving media: the peer sent an RTCP BYE for its sources, or a negotiation stopped the
    /// peer's sending direction.
    record Muted() implements RemoteTrackEvent {
    }

    /// The track receives media again: an RTP packet arrived while it was muted. A new track starts muted, so the
    /// first packet raises this event.
    record Unmuted() implements RemoteTrackEvent {
    }

    /// The track ended, because its transceiver stopped or the connection closed; no event follows.
    record Ended() implements RemoteTrackEvent {
    }
}
