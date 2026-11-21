package com.github.auties00.parley.ice;

import java.io.IOException;

/// Signals that an ICE transport cannot carry data: connectivity checks failed or did not succeed in time, consent
/// expired, or the transport is closed.
///
/// @see IceAgent#awaitConnected(java.time.Duration)
public final class IceException extends IOException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public IceException(String message) {
        super(message);
    }
}
