package com.github.auties00.parley.payload;

import java.io.IOException;

/// Thrown when an RTP payload, or a group of payloads meant to form one frame, does not follow its payload format:
/// a truncated descriptor, a fragment without its start, a NAL unit type the format forbids.
///
/// Payloads come from the network, so a receiver catches this exception, counts the frame as dropped and goes on.
public final class PayloadFormatException extends IOException {
    /// Creates an exception.
    ///
    /// @param message what is wrong with the payload
    public PayloadFormatException(String message) {
        super(message);
    }

    /// Creates an exception with a cause.
    ///
    /// @param message what is wrong with the payload
    /// @param cause   the failure that revealed it
    public PayloadFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
