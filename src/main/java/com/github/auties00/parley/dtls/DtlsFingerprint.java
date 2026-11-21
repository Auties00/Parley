package com.github.auties00.parley.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/// The fingerprint of a certificate, as an `a=fingerprint` attribute carries it: a hash function name and the digest
/// of the certificate's DER encoding.
///
/// A DTLS endpoint never validates the peer's certificate through a chain; it accepts the certificate only when it
/// matches a fingerprint the peer signalled ([#matches(X509Certificate)], and
/// [#select(List)] for the choice among several):
///
/// ```text
/// a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3E:5C:7B:3E:1F:2C:8B:4E:5A:6D:7C:8B
/// ```
///
/// The supported hash functions are `sha-1`, `sha-224`, `sha-256`, `sha-384` and `sha-512`; the algorithm name is
/// kept in lower case and the digest is copied in and out.
///
/// @param algorithm the hash function name, lower case, such as `sha-256`
/// @param value     the digest, whose length matches the hash function
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8827.html#section-6.5 RFC 8827: WebRTC Security Architecture
public record DtlsFingerprint(String algorithm, byte[] value) {
    /// The supported hash function names, strongest first.
    private static final List<String> ALGORITHMS = List.of("sha-512", "sha-384", "sha-256", "sha-224", "sha-1");

    /// Creates a fingerprint, normalizing the algorithm name and copying the digest.
    ///
    /// @param algorithm the hash function name, matched case-insensitively
    /// @param value     the digest
    /// @throws IllegalArgumentException if the hash function is unsupported or the digest has the wrong length
    public DtlsFingerprint {
        algorithm = algorithm.toLowerCase(Locale.ROOT);
        if (!ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("unsupported fingerprint hash function " + algorithm);
        }
        value = value.clone();
        if (value.length != digestLength(algorithm)) {
            throw new IllegalArgumentException(algorithm + " fingerprint of " + value.length + " bytes");
        }
    }

    /// {@return the fingerprint an `a=fingerprint` value carries}
    ///
    /// The value is the hash function name, white space, and the colon-separated hex digest; hex digits and the name
    /// are matched case-insensitively.
    ///
    /// @param sdpValue the attribute value, such as `sha-256 4A:AD:...`
    /// @throws IllegalArgumentException if the value is malformed or names an unsupported hash function
    public static DtlsFingerprint parse(String sdpValue) {
        var tokens = sdpValue.trim().split("\\s+");
        if (tokens.length != 2) {
            throw new IllegalArgumentException("malformed fingerprint: " + sdpValue);
        }
        byte[] digest;
        try {
            digest = HexFormat.ofDelimiter(":").parseHex(tokens[1]);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("malformed fingerprint digest: " + tokens[1], exception);
        }
        return new DtlsFingerprint(tokens[0], digest);
    }

    /// {@return the fingerprint of a certificate under a hash function}
    ///
    /// @param algorithm   the hash function name
    /// @param certificate the certificate
    /// @throws IllegalArgumentException if the hash function is unsupported or the certificate cannot be encoded
    public static DtlsFingerprint of(String algorithm, X509Certificate certificate) {
        try {
            return of(algorithm, certificate.getEncoded());
        } catch (CertificateEncodingException exception) {
            throw new IllegalArgumentException("cannot encode the certificate", exception);
        }
    }

    /// {@return the fingerprint of a DER-encoded certificate under a hash function}
    ///
    /// @param algorithm the hash function name
    /// @param encoded   the DER encoding
    /// @throws IllegalArgumentException if the hash function is unsupported
    public static DtlsFingerprint of(String algorithm, byte[] encoded) {
        var name = algorithm.toLowerCase(Locale.ROOT);
        if (!ALGORITHMS.contains(name)) {
            throw new IllegalArgumentException("unsupported fingerprint hash function " + algorithm);
        }
        return new DtlsFingerprint(name, digest(name, encoded));
    }

    /// {@return the fingerprints of `fingerprints` a certificate must match one of}
    ///
    /// When the peer signals several fingerprints, the endpoint uses those of the strongest hash function among them
    /// and accepts the certificate when it matches any one of that set.
    ///
    /// @param fingerprints the signalled fingerprints
    /// @spec https://www.rfc-editor.org/rfc/rfc8122.html#section-5 RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
    public static List<DtlsFingerprint> select(List<DtlsFingerprint> fingerprints) {
        for (var algorithm : ALGORITHMS) {
            var matching = fingerprints.stream().filter(fingerprint -> fingerprint.algorithm.equals(algorithm)).toList();
            if (!matching.isEmpty()) {
                return matching;
            }
        }
        return List.of();
    }

    /// {@return a copy of the digest}
    @Override
    public byte[] value() {
        return value.clone();
    }

    /// {@return whether a certificate has this fingerprint}
    ///
    /// @param certificate the certificate
    public boolean matches(X509Certificate certificate) {
        try {
            return matches(certificate.getEncoded());
        } catch (CertificateEncodingException exception) {
            return false;
        }
    }

    /// {@return whether a DER-encoded certificate has this fingerprint}
    ///
    /// @param encoded the DER encoding
    public boolean matches(byte[] encoded) {
        return MessageDigest.isEqual(value, digest(algorithm, encoded));
    }

    /// {@return the `a=fingerprint` value: the algorithm, a space and the upper-case colon-separated hex digest}
    public String toSdp() {
        return algorithm + " " + HexFormat.ofDelimiter(":").withUpperCase().formatHex(value);
    }

    /// {@return whether another object is a fingerprint with the same algorithm and digest}
    ///
    /// @param other the object to compare with
    @Override
    public boolean equals(Object other) {
        return other instanceof DtlsFingerprint that && algorithm.equals(that.algorithm) && Arrays.equals(value, that.value);
    }

    /// {@return a hash of the algorithm and the digest}
    @Override
    public int hashCode() {
        return Objects.hash(algorithm, Arrays.hashCode(value));
    }

    /// {@return the `a=fingerprint` value; a fingerprint is public, so nothing is redacted}
    @Override
    public String toString() {
        return toSdp();
    }

    /// {@return the digest length of a hash function}
    private static int digestLength(String algorithm) {
        return switch (algorithm) {
            case "sha-1" -> 20;
            case "sha-224" -> 28;
            case "sha-256" -> 32;
            case "sha-384" -> 48;
            default -> 64;
        };
    }

    /// {@return the digest of `data` under a supported hash function name}
    private static byte[] digest(String algorithm, byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm.toUpperCase(Locale.ROOT)).digest(data);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(algorithm + " unavailable", exception);
        }
    }
}
