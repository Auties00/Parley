package com.github.auties00.parley.dtls;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/// The signature schemes this library signs and verifies handshake messages with, in its order of preference.
///
/// DTLS 1.3 binds an ECDSA scheme to its curve and allows RSA only with PSS; DTLS 1.2 pairs any ECDSA curve with any
/// hash and also allows PKCS #1 v1.5. The SHA-1 schemes are accepted from DTLS 1.2 peers but never chosen to sign.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
enum SignatureScheme {
    /// `ecdsa_secp256r1_sha256`.
    ECDSA_SECP256R1_SHA256(0x0403, "SHA256withECDSA", KeyType.EC, 256, true, null),

    /// `ecdsa_secp384r1_sha384`.
    ECDSA_SECP384R1_SHA384(0x0503, "SHA384withECDSA", KeyType.EC, 384, true, null),

    /// `ecdsa_secp521r1_sha512`.
    ECDSA_SECP521R1_SHA512(0x0603, "SHA512withECDSA", KeyType.EC, 521, true, null),

    /// `ed25519`.
    ED25519(0x0807, "Ed25519", KeyType.ED25519, 0, true, null),

    /// `rsa_pss_rsae_sha256`.
    RSA_PSS_RSAE_SHA256(0x0804, "RSASSA-PSS", KeyType.RSA, 0, true,
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),

    /// `rsa_pss_rsae_sha384`.
    RSA_PSS_RSAE_SHA384(0x0805, "RSASSA-PSS", KeyType.RSA, 0, true,
            new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)),

    /// `rsa_pss_rsae_sha512`.
    RSA_PSS_RSAE_SHA512(0x0806, "RSASSA-PSS", KeyType.RSA, 0, true,
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)),

    /// `rsa_pkcs1_sha256`, DTLS 1.2 only.
    RSA_PKCS1_SHA256(0x0401, "SHA256withRSA", KeyType.RSA, 0, false, null),

    /// `rsa_pkcs1_sha384`, DTLS 1.2 only.
    RSA_PKCS1_SHA384(0x0501, "SHA384withRSA", KeyType.RSA, 0, false, null),

    /// `rsa_pkcs1_sha512`, DTLS 1.2 only.
    RSA_PKCS1_SHA512(0x0601, "SHA512withRSA", KeyType.RSA, 0, false, null),

    /// `ecdsa_sha1`, accepted from DTLS 1.2 peers only.
    ECDSA_SHA1(0x0203, "SHA1withECDSA", KeyType.EC, 0, false, null),

    /// `rsa_pkcs1_sha1`, accepted from DTLS 1.2 peers only.
    RSA_PKCS1_SHA1(0x0201, "SHA1withRSA", KeyType.RSA, 0, false, null);

    /// The IANA code.
    private final int id;

    /// The JDK signature algorithm.
    private final String algorithm;

    /// The key type.
    private final KeyType keyType;

    /// The curve size DTLS 1.3 binds an ECDSA scheme to, or `0`.
    private final int curveBits;

    /// Whether DTLS 1.3 allows the scheme.
    private final boolean tls13;

    /// The PSS parameters, or `null`.
    private final PSSParameterSpec pss;

    /// Creates a scheme constant.
    SignatureScheme(int id, String algorithm, KeyType keyType, int curveBits, boolean tls13, PSSParameterSpec pss) {
        this.id = id;
        this.algorithm = algorithm;
        this.keyType = keyType;
        this.curveBits = curveBits;
        this.tls13 = tls13;
        this.pss = pss;
    }

    /// {@return the scheme with an IANA code, or an empty optional for one this library does not implement}
    ///
    /// @param id the code
    static Optional<SignatureScheme> ofId(int id) {
        for (var scheme : values()) {
            if (scheme.id == id) {
                return Optional.of(scheme);
            }
        }
        return Optional.empty();
    }

    /// {@return the schemes this library advertises in `signature_algorithms`, in preference order}
    ///
    /// @param includeLegacy whether to include the DTLS 1.2-only schemes
    static List<SignatureScheme> advertised(boolean includeLegacy) {
        return Arrays.stream(values()).filter(scheme -> includeLegacy || scheme.tls13).toList();
    }

    /// {@return the first scheme, in this library's preference, that the peer lists and that signs with `key`}
    ///
    /// @param key         the signing key
    /// @param peerSchemes the codes the peer listed
    /// @param version     the negotiated version
    static Optional<SignatureScheme> choose(PrivateKey key, List<Integer> peerSchemes, DtlsVersion version) {
        for (var scheme : values()) {
            if (scheme == ECDSA_SHA1 || scheme == RSA_PKCS1_SHA1) {
                continue;
            }
            if (peerSchemes.contains(scheme.id) && scheme.accepts(key, version)) {
                return Optional.of(scheme);
            }
        }
        return Optional.empty();
    }

    /// {@return the IANA code}
    int id() {
        return id;
    }

    /// {@return whether the scheme may be used with a key in a version}
    ///
    /// @param key     the key
    /// @param version the version
    boolean accepts(Key key, DtlsVersion version) {
        if (version == DtlsVersion.DTLS_1_3 && !tls13) {
            return false;
        }
        var type = key instanceof PublicKey publicKey ? KeyType.of(publicKey) : keyTypeOf(key);
        if (type != keyType) {
            return false;
        }
        if (version == DtlsVersion.DTLS_1_3 && keyType == KeyType.EC && key instanceof ECKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize() == curveBits;
        }
        return true;
    }

    /// Signs data.
    ///
    /// @param key  the private key
    /// @param data the data
    /// @return the signature
    /// @throws DtlsException if signing fails
    byte[] sign(PrivateKey key, byte[] data) throws DtlsException {
        try {
            var signer = Signature.getInstance(algorithm);
            if (pss != null) {
                signer.setParameter(pss);
            }
            signer.initSign(key);
            signer.update(data);
            return signer.sign();
        } catch (GeneralSecurityException exception) {
            throw new DtlsException(DtlsAlert.INTERNAL_ERROR, false, "signing with " + this + " failed", exception);
        }
    }

    /// {@return whether a signature verifies; a malformed signature or key does not}
    ///
    /// @param key       the public key
    /// @param data      the signed data
    /// @param signature the signature
    boolean verify(PublicKey key, byte[] data, byte[] signature) {
        try {
            var verifier = Signature.getInstance(algorithm);
            if (pss != null) {
                verifier.setParameter(pss);
            }
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException exception) {
            return false;
        }
    }

    /// {@return the key type of a private key}
    private static KeyType keyTypeOf(Key key) {
        return switch (key.getAlgorithm().toUpperCase(java.util.Locale.ROOT)) {
            case "EC" -> KeyType.EC;
            case "RSA" -> KeyType.RSA;
            case "ED25519", "EDDSA" -> KeyType.ED25519;
            default -> throw new IllegalArgumentException("unsupported key algorithm " + key.getAlgorithm());
        };
    }
}
