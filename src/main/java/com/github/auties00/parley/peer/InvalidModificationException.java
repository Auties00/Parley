package com.github.auties00.parley.peer;

/// Signals that the call would change something that cannot be changed, the W3C `InvalidModificationError`.
///
/// Thrown, for example, by `setLocalDescription` with a description edited beyond what RFC 9429 section 5.4 allows, by `setParameters` with a different transaction id or encoding count, and by `setConfiguration` with another bundle policy.
///
/// It extends [IllegalArgumentException], so callers that already catch the JDK type for a misuse catch it too.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public final class InvalidModificationException extends IllegalArgumentException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public InvalidModificationException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the failure that caused it
    public InvalidModificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
