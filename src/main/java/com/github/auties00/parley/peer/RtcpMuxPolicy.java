package com.github.auties00.parley.peer;

/// Whether RTCP may use its own transport, the W3C `RTCRtcpMuxPolicy`; WebRTC allows only `require`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8858.html RFC 8858: Indicating Exclusive Support of RTP and RTP Control Protocol (RTCP) Multiplexing Using the Session Description Protocol (SDP)
public enum RtcpMuxPolicy {
    /// `require`: RTP and RTCP share one transport; a remote description without `a=rtcp-mux` is rejected.
    REQUIRE("require");

    /// The W3C enumeration value.
    private final String value;

    RtcpMuxPolicy(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }
}
