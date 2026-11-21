package com.github.auties00.parley.peer;

/// How the media sections of a peer connection share transports, the W3C `RTCBundlePolicy`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
public enum BundlePolicy {
    /// `balanced`: one transport per media kind until the answer accepts BUNDLE; the first section of each kind gathers candidates.
    BALANCED("balanced"),
    /// `max-compat`: one transport per media section until the answer accepts BUNDLE.
    MAX_COMPAT("max-compat"),
    /// `max-bundle`: one transport for every section; the sections after the first are offered bundle-only, so a peer that does not support BUNDLE negotiates only the first.
    MAX_BUNDLE("max-bundle");

    /// The W3C enumeration value.
    private final String value;

    BundlePolicy(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }
}
