package com.github.auties00.parley.peer;

/// Signals that the object is in a state that does not allow the call, the W3C `InvalidStateError`.
///
/// Thrown, for example, by `setRemoteDescription` with an answer while no offer is pending, or by any method of a closed peer connection.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public final class InvalidStateException extends RuntimeException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public InvalidStateException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the failure that caused it
    public InvalidStateException(String message, Throwable cause) {
        super(message, cause);
    }
}
