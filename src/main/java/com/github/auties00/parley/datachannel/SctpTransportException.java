package com.github.auties00.parley.datachannel;

import java.io.IOException;

/// Signals that the SCTP association of an [SctpTransport] failed: it did not establish, it was aborted, or it
/// refused a message or a stream reset.
public final class SctpTransportException extends IOException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public SctpTransportException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the cause, or `null` if it is unknown
    public SctpTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
