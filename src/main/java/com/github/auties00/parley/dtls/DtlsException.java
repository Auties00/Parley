package com.github.auties00.parley.dtls;

import java.io.IOException;

/// Signals that a DTLS-SRTP handshake failed: the peer sent a fatal alert or a message this endpoint cannot accept,
/// its certificate did not match the advertised fingerprint, no SRTP profile was agreed, the transport failed, or the
/// handshake timed out.
///
/// @see DtlsEndpoint#handshake(java.time.Duration)
public final class DtlsException extends IOException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public DtlsException(String message) {
        super(message);
    }

    /// Creates the exception with a cause.
    ///
    /// @param message the detail message
    /// @param cause   the cause, or `null` if it is unknown
    public DtlsException(String message, Throwable cause) {
        super(message, cause);
    }
}
