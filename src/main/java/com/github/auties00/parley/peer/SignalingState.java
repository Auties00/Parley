package com.github.auties00.parley.peer;

/// The offer/answer state of a peer connection, the W3C `RTCSignalingState`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public enum SignalingState {
    /// `stable`: no offer/answer exchange is in progress; the initial state.
    STABLE("stable"),
    /// `have-local-offer`: a local offer is applied and awaits an answer.
    HAVE_LOCAL_OFFER("have-local-offer"),
    /// `have-remote-offer`: a remote offer is applied and awaits a local answer.
    HAVE_REMOTE_OFFER("have-remote-offer"),
    /// `have-local-pranswer`: a remote offer was answered with a local provisional answer.
    HAVE_LOCAL_PRANSWER("have-local-pranswer"),
    /// `have-remote-pranswer`: a local offer was answered with a remote provisional answer.
    HAVE_REMOTE_PRANSWER("have-remote-pranswer"),
    /// `closed`: the connection is closed.
    CLOSED("closed");

    /// The W3C enumeration value.
    private final String value;

    SignalingState(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }
}
