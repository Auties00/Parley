package com.github.auties00.parley.dtls;

import java.util.Optional;

/// The alert descriptions a DTLS association sends or receives when it fails or closes.
///
/// A [DtlsException] names the alert that ended a handshake through [DtlsException#alert()], whichever side sent it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
public enum DtlsAlert {
    /// `close_notify` (0): the sender closes the association.
    CLOSE_NOTIFY(0),

    /// `unexpected_message` (10): a message arrived out of order.
    UNEXPECTED_MESSAGE(10),

    /// `bad_record_mac` (20): a record failed authentication.
    BAD_RECORD_MAC(20),

    /// `record_overflow` (22): a record exceeded the maximum length.
    RECORD_OVERFLOW(22),

    /// `handshake_failure` (40): no acceptable set of parameters exists.
    HANDSHAKE_FAILURE(40),

    /// `bad_certificate` (42): a certificate is corrupt or does not match the signalled fingerprint.
    BAD_CERTIFICATE(42),

    /// `unsupported_certificate` (43): a certificate has an unsupported type.
    UNSUPPORTED_CERTIFICATE(43),

    /// `certificate_expired` (45): a certificate has expired.
    CERTIFICATE_EXPIRED(45),

    /// `certificate_unknown` (46): a certificate is unacceptable for another reason.
    CERTIFICATE_UNKNOWN(46),

    /// `illegal_parameter` (47): a field is out of range or inconsistent.
    ILLEGAL_PARAMETER(47),

    /// `decode_error` (50): a message could not be decoded.
    DECODE_ERROR(50),

    /// `decrypt_error` (51): a signature or `Finished` value did not verify.
    DECRYPT_ERROR(51),

    /// `protocol_version` (70): no common protocol version exists.
    PROTOCOL_VERSION(70),

    /// `insufficient_security` (71): the peer requires stronger parameters than offered.
    INSUFFICIENT_SECURITY(71),

    /// `internal_error` (80): the sender failed for a reason unrelated to the peer.
    INTERNAL_ERROR(80),

    /// `user_canceled` (90): the sender abandons the handshake.
    USER_CANCELED(90),

    /// `no_renegotiation` (100): the sender refuses a DTLS 1.2 renegotiation, as this library always does.
    NO_RENEGOTIATION(100),

    /// `missing_extension` (109): a required extension is absent.
    MISSING_EXTENSION(109),

    /// `unsupported_extension` (110): an extension appeared where it is not allowed.
    UNSUPPORTED_EXTENSION(110),

    /// `certificate_required` (116): the peer sent no certificate although one is required.
    CERTIFICATE_REQUIRED(116);

    /// The alert description code.
    private final int code;

    /// Creates an alert constant.
    DtlsAlert(int code) {
        this.code = code;
    }

    /// {@return the alert with a description code, or an empty optional for a code this library does not name}
    ///
    /// @param code the description code
    public static Optional<DtlsAlert> ofCode(int code) {
        for (var alert : values()) {
            if (alert.code == code) {
                return Optional.of(alert);
            }
        }
        return Optional.empty();
    }

    /// {@return the alert description code on the wire}
    public int code() {
        return code;
    }
}
