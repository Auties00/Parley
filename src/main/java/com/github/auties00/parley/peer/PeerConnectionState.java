package com.github.auties00.parley.peer;

/// The aggregate ICE and DTLS state of a peer connection, the W3C `RTCPeerConnectionState`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public enum PeerConnectionState {
    /// `new`: no transport has started, or every transport is new or closed.
    NEW("new"),
    /// `connecting`: a transport is checking or handshaking and none has failed.
    CONNECTING("connecting"),
    /// `connected`: every transport is connected or closed.
    CONNECTED("connected"),
    /// `disconnected`: a transport lost connectivity and none has failed.
    DISCONNECTED("disconnected"),
    /// `failed`: a transport failed.
    FAILED("failed"),
    /// `closed`: the connection is closed.
    CLOSED("closed");

    /// The W3C enumeration value.
    private final String value;

    PeerConnectionState(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }
}
