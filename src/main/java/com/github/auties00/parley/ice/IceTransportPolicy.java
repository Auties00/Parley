package com.github.auties00.parley.ice;

/// Which local candidates an ICE agent uses, as the W3C `RTCIceTransportPolicy`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public enum IceTransportPolicy {
    /// Every candidate: host, server-reflexive and relayed.
    ALL,

    /// Relayed candidates only, so the peer never learns a local or reflexive address; remote `.local` candidates
    /// are ignored.
    RELAY
}
