package com.github.auties00.parley.peer;

/// The preferred or negotiated direction of a transceiver, the W3C `RTCRtpTransceiverDirection`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public enum TransceiverDirection {
    /// `sendrecv`: sends and receives.
    SENDRECV("sendrecv"),
    /// `sendonly`: sends only.
    SENDONLY("sendonly"),
    /// `recvonly`: receives only.
    RECVONLY("recvonly"),
    /// `inactive`: neither sends nor receives.
    INACTIVE("inactive"),
    /// `stopped`: stopped for good; its media section is rejected.
    STOPPED("stopped");

    /// The W3C enumeration value.
    private final String value;

    TransceiverDirection(String value) {
        this.value = value;
    }

    /// {@return the W3C enumeration value, as JavaScript writes it}
    public String value() {
        return value;
    }

    /// {@return whether this direction sends media}
    public boolean sends() {
        return this == SENDRECV || this == SENDONLY;
    }

    /// {@return whether this direction receives media}
    public boolean receives() {
        return this == SENDRECV || this == RECVONLY;
    }

    /// {@return the direction that sends when `send` is `true` and receives when `receive` is `true`; never `STOPPED`}
    ///
    /// @param send    whether the direction sends
    /// @param receive whether the direction receives
    public static TransceiverDirection of(boolean send, boolean receive) {
        if (send) {
            return receive ? SENDRECV : SENDONLY;
        }
        return receive ? RECVONLY : INACTIVE;
    }
}
