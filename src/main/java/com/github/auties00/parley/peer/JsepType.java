package com.github.auties00.parley.peer;

/// The type of a session description, the W3C `RTCSdpType`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public enum JsepType {
    /// `offer`: an offer.
    OFFER("offer"),
    /// `pranswer`: a provisional answer, which a final answer later replaces.
    PRANSWER("pranswer"),
    /// `answer`: a final answer, which completes the exchange.
    ANSWER("answer"),
    /// `rollback`: a request to undo the pending offer; carries no SDP.
    ROLLBACK("rollback");

    /// The W3C enumeration value.
    private final String value;

    JsepType(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }
}
