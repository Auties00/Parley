package com.github.auties00.parley.ice;

/// The connectivity state of an ICE transport, with the meanings of the W3C `RTCIceTransportState`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public enum IceTransportState {
    /// Gathering or waiting for remote candidates; no check has run.
    NEW,

    /// Checks are running and no pair is usable yet.
    CHECKING,

    /// A pair is selected and media can flow; checks may still run.
    CONNECTED,

    /// A pair is nominated, local gathering is complete, the peer signalled the end of its candidates, and no check
    /// is left to run.
    COMPLETED,

    /// The selected pair stopped answering consent checks for a few seconds; it may recover.
    DISCONNECTED,

    /// Every pair failed, or consent on the selected pair expired with no other pair to fall back to. An ICE restart
    /// can recover.
    FAILED,

    /// The transport is closed.
    CLOSED
}
