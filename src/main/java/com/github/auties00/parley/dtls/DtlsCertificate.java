package com.github.auties00.parley.dtls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/// The ephemeral self-signed certificate a DTLS-SRTP endpoint presents, with the fingerprint its session description
/// advertises in `a=fingerprint`.
///
/// [#generate()] creates an ECDSA P-256 key pair and a version 3 certificate with the subject and issuer `CN=WebRTC`,
/// valid from one day ago for thirty days and signed with `ecdsa-with-SHA256`, the shape WebRTC endpoints use. The
/// peer authenticates it only through the fingerprint carried over the signalling channel, never through a
/// certificate chain, so one certificate may serve every association of a session or of the whole application.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc5280.html RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
public final class DtlsCertificate {
    /// The source of serial numbers and keys.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// The DER encoding of the `ecdsa-with-SHA256` algorithm identifier, OID 1.2.840.10045.4.3.2.
    private static final byte[] ECDSA_SHA256 = {0x30, 0x0A, 0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02};

    /// The key pair whose public half the certificate holds.
    private final KeyPair keyPair;

    /// The certificate.
    private final X509Certificate certificate;

    /// Creates a certificate holder.
    private DtlsCertificate(KeyPair keyPair, X509Certificate certificate) {
        this.keyPair = keyPair;
        this.certificate = certificate;
    }

    /// {@return a fresh ECDSA P-256 key pair and its self-signed certificate}
    ///
    /// Generating a key pair takes milliseconds of CPU time; reuse one certificate where the application allows it.
    ///
    /// @throws IllegalStateException if the JDK cannot generate EC keys on `secp256r1` or sign with
    ///                               `SHA256withECDSA`
    public static DtlsCertificate generate() {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            var keyPair = generator.generateKeyPair();
            var now = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
            var name = name("WebRTC");
            var tbs = sequence(
                    new byte[]{(byte) 0xA0, 0x03, 0x02, 0x01, 0x02},
                    integer(new BigInteger(63, RANDOM).add(BigInteger.ONE)),
                    ECDSA_SHA256,
                    name,
                    sequence(utcTime(now.minusDays(1)), utcTime(now.plusDays(30))),
                    name,
                    keyPair.getPublic().getEncoded());
            var signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(tbs);
            var signature = signer.sign();
            var bitString = new byte[signature.length + 1];
            System.arraycopy(signature, 0, bitString, 1, signature.length);
            var der = sequence(tbs, ECDSA_SHA256, tlv(0x03, bitString));
            var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            return new DtlsCertificate(keyPair, certificate);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("cannot generate the DTLS certificate", exception);
        }
    }

    /// {@return the X.509 certificate}
    public X509Certificate certificate() {
        return certificate;
    }

    /// {@return the ECDSA private key of the certificate, which signs this endpoint's handshake messages}
    PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    /// {@return the DER encoding of the certificate}
    ///
    /// @throws IllegalStateException if the certificate cannot be encoded
    public byte[] encoded() {
        try {
            return certificate.getEncoded();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("cannot encode the DTLS certificate", exception);
        }
    }

    /// {@return the `a=fingerprint` value of the certificate: `sha-256 ` followed by the upper-case, colon-separated
    /// SHA-256 of its DER encoding}
    ///
    /// ```text
    /// sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3E:5C:7B:3E:1F:2C:8B:4E:5A:6D:7C:8B
    /// ```
    public String fingerprint() {
        return "sha-256 " + fingerprintHex(encoded(), "SHA-256");
    }

    /// {@return whether the digest of a certificate equals the one an `a=fingerprint` value advertises}
    ///
    /// The hash function name is matched case-insensitively and may be `sha-1`, `sha-224`, `sha-256`, `sha-384` or
    /// `sha-512`; any other name, or a value that is not two tokens, never matches. The hex digits are compared
    /// case-insensitively.
    ///
    /// @param encoded     the DER encoding of the certificate
    /// @param fingerprint the attribute value, `<hash> <hex>`
    public static boolean matches(byte[] encoded, String fingerprint) {
        Objects.requireNonNull(encoded, "encoded cannot be null");
        Objects.requireNonNull(fingerprint, "fingerprint cannot be null");
        var tokens = fingerprint.trim().split(" +");
        if (tokens.length != 2) {
            return false;
        }
        var algorithm = switch (tokens[0].toLowerCase(Locale.ROOT)) {
            case "sha-1" -> "SHA-1";
            case "sha-224" -> "SHA-224";
            case "sha-256" -> "SHA-256";
            case "sha-384" -> "SHA-384";
            case "sha-512" -> "SHA-512";
            default -> null;
        };
        if (algorithm == null) {
            return false;
        }
        return fingerprintHex(encoded, algorithm).equalsIgnoreCase(tokens[1]);
    }

    /// {@return the colon-separated upper-case hex digest of `data` under the JDK digest `algorithm`}
    private static String fingerprintHex(byte[] data, String algorithm) {
        try {
            var digest = MessageDigest.getInstance(algorithm).digest(data);
            return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(algorithm + " unavailable", exception);
        }
    }

    /// {@return the DER encoding of a `Name` with one common name}
    private static byte[] name(String commonName) {
        var attribute = sequence(new byte[]{0x06, 0x03, 0x55, 0x04, 0x03},
                tlv(0x0C, commonName.getBytes(StandardCharsets.UTF_8)));
        return sequence(tlv(0x31, attribute));
    }

    /// {@return the DER encoding of a `UTCTime`, which covers the years 1950 to 2049}
    private static byte[] utcTime(ZonedDateTime time) {
        var text = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").format(time);
        return tlv(0x17, text.getBytes(StandardCharsets.US_ASCII));
    }

    /// {@return the DER encoding of a positive `INTEGER`}
    private static byte[] integer(BigInteger value) {
        return tlv(0x02, value.toByteArray());
    }

    /// {@return the DER encoding of a `SEQUENCE` of already encoded elements}
    private static byte[] sequence(byte[]... elements) {
        var body = new ByteArrayOutputStream();
        for (var element : elements) {
            body.writeBytes(element);
        }
        return tlv(0x30, body.toByteArray());
    }

    /// {@return a DER tag-length-value with a definite length of up to two bytes}
    private static byte[] tlv(int tag, byte[] value) {
        var out = new ByteArrayOutputStream();
        out.write(tag);
        var length = value.length;
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else {
            out.write(0x82);
            out.write(length >>> 8);
            out.write(length);
        }
        out.writeBytes(value);
        return out.toByteArray();
    }
}
