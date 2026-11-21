package com.github.auties00.parley.ice;

/// The local candidate gathering state of an ICE agent, with the meanings of the W3C `RTCIceGathererState`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public enum IceGatheringState {
    /// Gathering has not started.
    NEW,

    /// Candidates are being gathered.
    GATHERING,

    /// Every candidate has been gathered; this is the end-of-candidates indication of trickle ICE.
    COMPLETE
}
