package com.github.auties00.parley.datachannel;

/// The state of an [SctpTransport], as the W3C `RTCSctpTransportState`.
///
/// @spec https://www.w3.org/TR/webrtc/#dom-rtcsctptransportstate WebRTC: Real-Time Communication in Browsers, RTCSctpTransportState
public enum SctpTransportState {
    /// The association is not established yet.
    CONNECTING,
    /// The association is established; channels can open.
    CONNECTED,
    /// The association was shut down, aborted or never established; the transport is unusable.
    CLOSED
}
