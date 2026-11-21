package com.github.auties00.parley.dtls;

import java.security.SecureRandom;
import java.util.Base64;

/// The value of an `a=tls-id` attribute, which names one DTLS association of a media transport.
///
/// An endpoint keeps its value while the association lives and writes a new one to ask for a new association; a peer
/// that sees the value change must run a new handshake ([DtlsTransport#restart()]), see [DtlsParameters].
///
/// The value is 20 to 255 characters from the letters, digits and `+`, `/`, `-`, `_`.
///
/// @param value the attribute value
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html#section-4 RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
public record DtlsTlsId(String value) {
    /// The source of fresh values.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// Creates a value.
    ///
    /// @param value the attribute value
    /// @throws IllegalArgumentException if the value has the wrong length or a character outside the allowed set
    public DtlsTlsId {
        if (value.length() < 20 || value.length() > 255) {
            throw new IllegalArgumentException("a=tls-id must have 20 to 255 characters, not " + value.length());
        }
        for (var index = 0; index < value.length(); index++) {
            var character = value.charAt(index);
            var allowed = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9') || character == '+' || character == '/'
                    || character == '-' || character == '_';
            if (!allowed) {
                throw new IllegalArgumentException("a=tls-id contains the invalid character '" + character + "'");
            }
        }
    }

    /// {@return a fresh random value of 32 characters, carrying 192 random bits}
    public static DtlsTlsId generate() {
        var bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return new DtlsTlsId(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    /// {@return the value of an `a=tls-id` attribute}
    ///
    /// @param sdpValue the attribute value, surrounding white space ignored
    /// @throws IllegalArgumentException if the value is malformed
    public static DtlsTlsId parse(String sdpValue) {
        return new DtlsTlsId(sdpValue.trim());
    }

    /// {@return the attribute value}
    public String toSdp() {
        return value;
    }
}
