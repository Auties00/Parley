package com.github.auties00.parley.peer;

/// The relative priority of an encoding or a data channel, the W3C `RTCPriorityType`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public enum Priority {
    /// `very-low`: below low.
    VERY_LOW("very-low"),
    /// `low`: the default.
    LOW("low"),
    /// `medium`: above low.
    MEDIUM("medium"),
    /// `high`: the highest.
    HIGH("high");

    /// The W3C enumeration value.
    private final String value;

    Priority(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }

    /// {@return the bitrate weight of this priority relative to `LOW`, as webrtc.org allocates it: 0.5, 1, 2 and 4}
    public double weight() {
        return switch (this) {
            case VERY_LOW -> 0.5;
            case LOW -> 1;
            case MEDIUM -> 2;
            case HIGH -> 4;
        };
    }
}
