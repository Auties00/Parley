package com.github.auties00.parley.dtls;

import java.util.List;
import java.util.Optional;

/// The cipher suites this library negotiates, in its order of preference within each version.
///
/// The DTLS 1.2 suites are ECDHE key exchanges authenticated by the certificate's key type; the DTLS 1.3 suites name
/// only the record protection and the hash, since the key exchange and the signature are negotiated separately.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5289.html RFC 5289: TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
/// @spec https://www.rfc-editor.org/rfc/rfc7905.html RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4 RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
enum CipherSuite {
    /// `TLS_AES_128_GCM_SHA256`.
    TLS_AES_128_GCM_SHA256(0x1301, DtlsVersion.DTLS_1_3, null, Aead.AES_128_GCM, HashAlgorithm.SHA256),

    /// `TLS_AES_256_GCM_SHA384`.
    TLS_AES_256_GCM_SHA384(0x1302, DtlsVersion.DTLS_1_3, null, Aead.AES_256_GCM, HashAlgorithm.SHA384),

    /// `TLS_CHACHA20_POLY1305_SHA256`.
    TLS_CHACHA20_POLY1305_SHA256(0x1303, DtlsVersion.DTLS_1_3, null, Aead.CHACHA20_POLY1305, HashAlgorithm.SHA256),

    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, the suite every WebRTC endpoint supports.
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B, DtlsVersion.DTLS_1_2, KeyType.EC, Aead.AES_128_GCM, HashAlgorithm.SHA256),

    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C, DtlsVersion.DTLS_1_2, KeyType.EC, Aead.AES_256_GCM, HashAlgorithm.SHA384),

    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA9, DtlsVersion.DTLS_1_2, KeyType.EC, Aead.CHACHA20_POLY1305, HashAlgorithm.SHA256),

    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F, DtlsVersion.DTLS_1_2, KeyType.RSA, Aead.AES_128_GCM, HashAlgorithm.SHA256),

    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030, DtlsVersion.DTLS_1_2, KeyType.RSA, Aead.AES_256_GCM, HashAlgorithm.SHA384),

    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xCCA8, DtlsVersion.DTLS_1_2, KeyType.RSA, Aead.CHACHA20_POLY1305, HashAlgorithm.SHA256);

    /// The `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` value, which a DTLS 1.2 client may send instead of the extension.
    static final int EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;

    /// The IANA code.
    private final int id;

    /// The version the suite belongs to.
    private final DtlsVersion version;

    /// The certificate key type a DTLS 1.2 suite authenticates with, or `null` for a DTLS 1.3 suite.
    private final KeyType keyType;

    /// The record protection.
    private final Aead aead;

    /// The hash of the PRF or key schedule.
    private final HashAlgorithm hash;

    /// Creates a suite constant.
    CipherSuite(int id, DtlsVersion version, KeyType keyType, Aead aead, HashAlgorithm hash) {
        this.id = id;
        this.version = version;
        this.keyType = keyType;
        this.aead = aead;
        this.hash = hash;
    }

    /// {@return the suite with an IANA code, or an empty optional for a code this library does not implement}
    ///
    /// @param id the code
    static Optional<CipherSuite> ofId(int id) {
        for (var suite : values()) {
            if (suite.id == id) {
                return Optional.of(suite);
            }
        }
        return Optional.empty();
    }

    /// {@return the suites of a version, in preference order}
    ///
    /// @param version the version
    static List<CipherSuite> of(DtlsVersion version) {
        return java.util.Arrays.stream(values()).filter(suite -> suite.version == version).toList();
    }

    /// {@return the IANA code}
    int id() {
        return id;
    }

    /// {@return the version the suite belongs to}
    DtlsVersion version() {
        return version;
    }

    /// {@return the certificate key type of a DTLS 1.2 suite}
    Optional<KeyType> keyType() {
        return Optional.ofNullable(keyType);
    }

    /// {@return the record protection}
    Aead aead() {
        return aead;
    }

    /// {@return the hash of the PRF or key schedule}
    HashAlgorithm hash() {
        return hash;
    }
}
