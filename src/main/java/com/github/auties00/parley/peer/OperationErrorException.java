package com.github.auties00.parley.peer;

/// Signals that an operation failed for a reason other than the arguments or the state, the W3C `OperationError`.
///
/// Thrown, for example, when a remote description cannot be parsed or applied, or a candidate matches no media section.
///
/// It extends [IllegalStateException], so callers that already catch the JDK type for a misuse catch it too.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public final class OperationErrorException extends IllegalStateException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public OperationErrorException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the failure that caused it
    public OperationErrorException(String message, Throwable cause) {
        super(message, cause);
    }
}
