package com.github.auties00.parley.media;

/// The relative priority of an encoding or a data channel, the W3C `RTCPriorityType`.
///
/// One type serves both uses: an encoding's priority weighs its share of the bitrate, its network priority selects the
/// DSCP marking of RFC 8837, and a data channel's priority weighs its share of the SCTP association and is announced
/// in its `DATA_CHANNEL_OPEN` message.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.w3.org/TR/webrtc-priority/ WebRTC Priority Control API
/// @spec https://www.rfc-editor.org/rfc/rfc8832.html#section-5.1 RFC 8832: WebRTC Data Channel Establishment Protocol, DATA_CHANNEL_OPEN Message
/// @spec https://www.rfc-editor.org/rfc/rfc8837.html RFC 8837: Differentiated Services Code Point (DSCP) Packet Markings for WebRTC QoS
public enum Priority {
    /// `very-low`, data channel wire value 128.
    VERY_LOW("very-low", 128),
    /// `low`, the default, data channel wire value 256.
    LOW("low", 256),
    /// `medium`, data channel wire value 512.
    MEDIUM("medium", 512),
    /// `high`, data channel wire value 1024.
    HIGH("high", 1024);

    /// The W3C enumeration value.
    private final String value;
    /// The `DATA_CHANNEL_OPEN` priority field.
    private final int wireValue;

    Priority(String value, int wireValue) {
        this.value = value;
        this.wireValue = wireValue;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it, such as `very-low`}
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

    /// {@return the 16-bit value written in the `DATA_CHANNEL_OPEN` priority field and used as the SCTP stream
    /// scheduling weight}
    public int wireValue() {
        return wireValue;
    }

    /// {@return the priority a received `DATA_CHANNEL_OPEN` wire value means: values up to 128 are [#VERY_LOW], up
    /// to 256 [#LOW], up to 512 [#MEDIUM] and anything higher [#HIGH], the ranges of the W3C priority mapping}
    ///
    /// @param wireValue the 16-bit priority field
    public static Priority ofWireValue(int wireValue) {
        if (wireValue <= VERY_LOW.wireValue) {
            return VERY_LOW;
        }
        if (wireValue <= LOW.wireValue) {
            return LOW;
        }
        if (wireValue <= MEDIUM.wireValue) {
            return MEDIUM;
        }
        return HIGH;
    }

    /// {@return the priority whose W3C enumeration value is `value`}
    ///
    /// @param value the enumeration value, such as `medium`
    /// @throws IllegalArgumentException if `value` names no priority
    public static Priority ofValue(String value) {
        for (var priority : values()) {
            if (priority.value.equals(value)) {
                return priority;
            }
        }
        throw new IllegalArgumentException("unknown priority: " + value);
    }
}
