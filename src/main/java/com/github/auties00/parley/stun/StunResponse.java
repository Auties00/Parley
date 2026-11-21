package com.github.auties00.parley.stun;

import java.time.Duration;
import java.util.Objects;

/// The outcome of a STUN client transaction that got a response.
///
/// @param message       the response, a success or an error, owning its bytes
/// @param roundTripTime the time from the last transmission of the request to the response; when the request was
///                      retransmitted the response may answer an earlier transmission, so the value is a lower bound
/// @param transmissions how many times the request was sent
public record StunResponse(StunMessage message, Duration roundTripTime, int transmissions) {
    /// Creates a response.
    ///
    /// @param message       the response
    /// @param roundTripTime the round-trip time
    /// @param transmissions how many times the request was sent
    public StunResponse {
        Objects.requireNonNull(message, "message cannot be null");
        Objects.requireNonNull(roundTripTime, "roundTripTime cannot be null");
    }

    /// {@return whether the response is a success response}
    public boolean isSuccess() {
        return message.messageClass() == StunClass.SUCCESS_RESPONSE;
    }
}
