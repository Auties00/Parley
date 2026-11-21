package com.github.auties00.parley.datachannel;

/// The priority of a data channel, which weighs its share of the association when channels compete for the
/// congestion window, and is announced to the peer in the channel's `DATA_CHANNEL_OPEN` message.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8832.html#section-5.1 RFC 8832: WebRTC Data Channel Establishment Protocol, DATA_CHANNEL_OPEN Message
/// @spec https://www.w3.org/TR/webrtc-priority/ WebRTC Priority Control API
public enum DataChannelPriority {
    /// The W3C `very-low` priority, wire value 128.
    VERY_LOW(128),
    /// The W3C `low` priority, wire value 256; the default.
    LOW(256),
    /// The W3C `medium` priority, wire value 512.
    MEDIUM(512),
    /// The W3C `high` priority, wire value 1024.
    HIGH(1024);

    private final int wireValue;

    DataChannelPriority(int wireValue) {
        this.wireValue = wireValue;
    }

    /// {@return the 16-bit value written in the `DATA_CHANNEL_OPEN` priority field and used as the SCTP stream
    /// scheduling weight}
    public int wireValue() {
        return wireValue;
    }

    /// {@return the priority a received wire value means}: values up to 128 are [#VERY_LOW], up to 256 [#LOW], up
    /// to 512 [#MEDIUM] and anything higher [#HIGH], the ranges of the W3C priority mapping
    ///
    /// @param wireValue the 16-bit priority field
    public static DataChannelPriority ofWireValue(int wireValue) {
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
}
