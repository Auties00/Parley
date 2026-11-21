package com.github.auties00.parley.dtls;

import java.io.IOException;
import java.util.Optional;

/// Signals that a DTLS association failed: the handshake was rejected by either side, the peer's certificate did not
/// match a signalled fingerprint, no version, cipher suite or SRTP profile was agreed, the lower transport failed, or the
/// handshake timed out.
///
/// When an alert ended the handshake, [#alert()] names it and [#isRemote()] tells whether the peer sent it; when this
/// side detected the failure, it sent that alert to the peer, best effort, before throwing.
///
/// @see DtlsTransport#handshake(DtlsRole, java.util.List, java.time.Duration)
public final class DtlsException extends IOException {
    /// The alert that ended the association, or `null` for none.
    private final DtlsAlert alert;

    /// Whether the peer sent [#alert].
    private final boolean remote;

    /// Creates an exception with no alert.
    ///
    /// @param message the detail message
    public DtlsException(String message) {
        this(null, false, message, null);
    }

    /// Creates an exception with no alert and a cause.
    ///
    /// @param message the detail message
    /// @param cause   the cause, or `null` if it is unknown
    public DtlsException(String message, Throwable cause) {
        this(null, false, message, cause);
    }

    /// Creates an exception for an alert this side sends.
    ///
    /// @param alert   the alert
    /// @param message the detail message
    public DtlsException(DtlsAlert alert, String message) {
        this(alert, false, message, null);
    }

    /// Creates an exception.
    ///
    /// @param alert   the alert, or `null` for none
    /// @param remote  whether the peer sent the alert
    /// @param message the detail message
    /// @param cause   the cause, or `null` if it is unknown
    DtlsException(DtlsAlert alert, boolean remote, String message, Throwable cause) {
        super(message, cause);
        this.alert = alert;
        this.remote = remote;
    }

    /// {@return the alert that ended the association, or an empty optional when no alert was involved, as for a
    /// timeout or a transport failure}
    public Optional<DtlsAlert> alert() {
        return Optional.ofNullable(alert);
    }

    /// {@return whether the peer sent [#alert()]; `false` when this side sent it or no alert was involved}
    public boolean isRemote() {
        return remote;
    }
}
