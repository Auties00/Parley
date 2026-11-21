package com.github.auties00.parley.stun;

import java.io.IOException;

/// Signals a STUN failure: a malformed message, a transaction that got no response, or a response whose integrity
/// did not verify.
public sealed class StunException extends IOException permits StunFormatException, StunTimeoutException,
        StunIntegrityException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    StunException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the cause
    StunException(String message, Throwable cause) {
        super(message, cause);
    }
}
