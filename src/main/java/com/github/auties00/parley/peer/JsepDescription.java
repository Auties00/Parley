package com.github.auties00.parley.peer;

import java.util.Objects;

/// A session description with its type, the W3C `RTCSessionDescription`.
///
/// The SDP text is what the application sends to and receives from its signaling channel; Parley never sends it
/// anywhere itself.
///
/// @param type the description type
/// @param sdp  the SDP text; empty for a rollback
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public record JsepDescription(JsepType type, String sdp) {
    /// Creates a description.
    ///
    /// @param type the description type
    /// @param sdp  the SDP text
    public JsepDescription {
        Objects.requireNonNull(type, "type cannot be null");
        Objects.requireNonNull(sdp, "sdp cannot be null");
    }

    /// {@return an offer carrying `sdp`}
    ///
    /// @param sdp the SDP text
    public static JsepDescription offer(String sdp) {
        return new JsepDescription(JsepType.OFFER, sdp);
    }

    /// {@return a final answer carrying `sdp`}
    ///
    /// @param sdp the SDP text
    public static JsepDescription answer(String sdp) {
        return new JsepDescription(JsepType.ANSWER, sdp);
    }

    /// {@return a provisional answer carrying `sdp`}
    ///
    /// @param sdp the SDP text
    public static JsepDescription pranswer(String sdp) {
        return new JsepDescription(JsepType.PRANSWER, sdp);
    }

    /// {@return a rollback, which carries no SDP}
    public static JsepDescription rollback() {
        return new JsepDescription(JsepType.ROLLBACK, "");
    }
}
