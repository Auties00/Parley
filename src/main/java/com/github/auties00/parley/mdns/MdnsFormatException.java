package com.github.auties00.parley.mdns;

import java.io.IOException;

/// Signals that bytes are not a well-formed DNS message.
public final class MdnsFormatException extends IOException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public MdnsFormatException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the cause
    public MdnsFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
