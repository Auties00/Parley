package com.github.auties00.parley.datachannel;

/// The ready state of a [DataChannel], as the W3C `RTCDataChannelState`.
///
/// @spec https://www.w3.org/TR/webrtc/#dom-rtcdatachannelstate WebRTC: Real-Time Communication in Browsers, RTCDataChannelState
public enum DataChannelState {
    /// The channel waits for its SCTP transport to connect; it cannot send yet.
    CONNECTING,
    /// The channel can send and receive.
    OPEN,
    /// The channel's outgoing stream is being reset; it no longer sends, and still delivers what it received.
    CLOSING,
    /// Both directions of the channel's stream were reset, or the transport closed.
    CLOSED
}
