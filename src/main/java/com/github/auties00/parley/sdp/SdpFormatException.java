package com.github.auties00.parley.sdp;

import java.io.IOException;

/// Thrown when a text is not a session description: a line lacks its `<type>=` prefix or an `m=` line is malformed.
///
/// Session description text is untrusted wire data, so the failure is checked: a caller that applies a peer's
/// description decides what a malformed one means (a peer connection rejects it with the W3C `OperationError`).
///
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
public final class SdpFormatException extends IOException {
    /// Creates the exception.
    ///
    /// @param message what is malformed
    public SdpFormatException(String message) {
        super(message);
    }

    /// Creates the exception with its cause.
    ///
    /// @param message what is malformed
    /// @param cause   the failure of the nested parser
    public SdpFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
