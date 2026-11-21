package com.github.auties00.parley.turn;

import java.io.IOException;
import java.util.OptionalInt;

/// Signals that a TURN request failed: the server answered with an error response, or the allocation it targets no
/// longer exists.
public final class TurnException extends IOException {
    /// The STUN error code of the server's response, or `0` when the failure is not an error response.
    private final int errorCode;

    /// Creates the exception for a failure that is not an error response.
    ///
    /// @param message the detail message
    public TurnException(String message) {
        super(message);
        this.errorCode = 0;
    }

    /// Creates the exception for an error response.
    ///
    /// @param message   the detail message
    /// @param errorCode the error code of the response, `300..699`
    public TurnException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the cause
    public TurnException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = 0;
    }

    /// {@return the STUN error code of the server's error response, or an empty optional when the failure is not an
    /// error response}
    public OptionalInt errorCode() {
        return errorCode == 0 ? OptionalInt.empty() : OptionalInt.of(errorCode);
    }
}
