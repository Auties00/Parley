package com.github.auties00.parley.dtls;

import com.github.auties00.srtp.SrtpCryptoSuite;

import java.util.Optional;

/// The SRTP protection profiles a [DtlsTransport] negotiates in the `use_srtp` extension, declared in this library's
/// order of preference.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc7714.html RFC 7714: AES-GCM Authenticated Encryption in the Secure Real-time Transport Protocol (SRTP)
public enum SrtpProfile {
    /// `SRTP_AEAD_AES_128_GCM`, profile `0x0007`: AES-128-GCM with a 12-byte salt (RFC 7714 section 14.2).
    AEAD_AES_128_GCM(0x0007, SrtpCryptoSuite.AEAD_AES_128_GCM, 16, 12),

    /// `SRTP_AEAD_AES_256_GCM`, profile `0x0008`: AES-256-GCM with a 12-byte salt (RFC 7714 section 14.2).
    AEAD_AES_256_GCM(0x0008, SrtpCryptoSuite.AEAD_AES_256_GCM, 32, 12),

    /// `SRTP_AES128_CM_HMAC_SHA1_80`, profile `0x0001`: AES-128 in counter mode with an 80-bit HMAC-SHA1 tag, the
    /// profile every WebRTC endpoint must support.
    AES128_CM_HMAC_SHA1_80(0x0001, SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, 16, 14),

    /// `SRTP_AES128_CM_HMAC_SHA1_32`, profile `0x0002`: AES-128 in counter mode with a 32-bit HMAC-SHA1 tag.
    AES128_CM_HMAC_SHA1_32(0x0002, SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_32, 16, 14);

    /// The profile id of the `use_srtp` extension.
    private final int id;

    /// The SRTP suite of the profile.
    private final SrtpCryptoSuite suite;

    /// The master key length in bytes.
    private final int keyLength;

    /// The master salt length in bytes.
    private final int saltLength;

    /// Creates a profile constant.
    SrtpProfile(int id, SrtpCryptoSuite suite, int keyLength, int saltLength) {
        this.id = id;
        this.suite = suite;
        this.keyLength = keyLength;
        this.saltLength = saltLength;
    }

    /// {@return the profile with a `use_srtp` id, or an empty optional for an id this library does not support}
    ///
    /// @param id the profile id
    public static Optional<SrtpProfile> ofId(int id) {
        for (var profile : values()) {
            if (profile.id == id) {
                return Optional.of(profile);
            }
        }
        return Optional.empty();
    }

    /// {@return the profile id of the `use_srtp` extension}
    public int id() {
        return id;
    }

    /// {@return the SRTP crypto suite that protects the media keyed under this profile}
    public SrtpCryptoSuite suite() {
        return suite;
    }

    /// {@return the master key length, in bytes}
    public int keyLength() {
        return keyLength;
    }

    /// {@return the master salt length, in bytes}
    public int saltLength() {
        return saltLength;
    }
}
