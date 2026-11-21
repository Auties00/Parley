package com.github.auties00.parley.rtp.rtcp;

import java.io.IOException;

/// Signals that bytes received from the network are not a well-formed RTCP packet.
///
/// Parley's receive paths count and drop such packets instead of propagating the exception out of a reader thread;
/// it reaches the application only from an explicit parse call.
public final class RtcpFormatException extends IOException {
    /// Creates an exception.
    ///
    /// @param message the detail message
    public RtcpFormatException(String message) {
        super(message);
    }
}
