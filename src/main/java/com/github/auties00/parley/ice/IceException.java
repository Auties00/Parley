package com.github.auties00.parley.ice;

import java.io.IOException;

/// Signals that ICE connectivity checks could not select a candidate pair: no candidate was usable, or none answered
/// before the timeout.
///
/// @see IceAgent#nominate(java.util.List, java.time.Duration)
public final class IceException extends IOException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public IceException(String message) {
        super(message);
    }
}
