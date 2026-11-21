package com.github.auties00.parley.peer;

/// Signals that the call is not allowed with the given arguments in the current state, the W3C `InvalidAccessError`.
///
/// Thrown, for example, when a remote description lacks a required attribute or does not answer the pending offer, or when `addTrack` is called with a track a sender of the connection already has.
///
/// It extends [IllegalArgumentException], so callers that already catch the JDK type for a misuse catch it too.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public final class InvalidAccessException extends IllegalArgumentException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public InvalidAccessException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the failure that caused it
    public InvalidAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
