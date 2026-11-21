package com.github.auties00.parley.rtp;

import java.io.IOException;

/// Signals that bytes received from the network are not a well-formed RTP packet or RTP header extension element.
///
/// Parley's receive paths count and drop such packets instead of propagating the exception out of a reader thread;
/// it reaches the application only from an explicit parse call.
public final class RtpFormatException extends IOException {
    /// Creates an exception.
    ///
    /// @param message the detail message
    public RtpFormatException(String message) {
        super(message);
    }

    /// Creates an exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the failure that made the bytes unreadable
    public RtpFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
