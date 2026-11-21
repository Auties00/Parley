package com.github.auties00.parley.stun;

/// Signals that bytes are not a well-formed STUN message: a bad header, a length that overflows the packet, a
/// malformed attribute value, an unknown method, or a `FINGERPRINT` that does not match.
public final class StunFormatException extends StunException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public StunFormatException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the cause
    public StunFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
