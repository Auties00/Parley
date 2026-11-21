package com.github.auties00.parley.stats;

/// The reason an outbound video encoding is sent below its configured quality, the W3C
/// `RTCQualityLimitationReason`.
///
/// Parley does not encode, so it never sees CPU limitation; the reason is [#BANDWIDTH] while the congestion controller's
/// target for the encoding is below the encoding's bitrate cap, [#NONE] otherwise.
///
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public enum QualityLimitationReason {
    /// `none`: the encoding is not limited.
    NONE("none"),
    /// `cpu`: the encoder is limited by the CPU.
    CPU("cpu"),
    /// `bandwidth`: the encoding is limited by the bandwidth estimate.
    BANDWIDTH("bandwidth"),
    /// `other`: any other limitation.
    OTHER("other");

    /// The W3C enumeration value.
    private final String value;

    QualityLimitationReason(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }
}
