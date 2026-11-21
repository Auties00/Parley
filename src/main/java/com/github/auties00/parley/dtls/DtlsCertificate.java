package com.github.auties00.parley.dtls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

/// The certificate and private key a DTLS endpoint authenticates with, the counterpart of the W3C `RTCCertificate`.
///
/// [#generateEcdsa()] creates an ECDSA P-256 key pair, the WebRTC default, and [#generateRsa()] an RSA-2048 one; each
/// comes with a version 3 self-signed certificate, subject and issuer `CN=WebRTC`, valid from one day ago for thirty
/// days. [#of(PrivateKey,X509Certificate)] imports an existing pair, which is how an application persists a
/// certificate across sessions: it stores [#privateKey()] and [#certificate()] and imports them again.
///
/// The peer authenticates the certificate only through the fingerprint carried over the signalling channel
/// ([#fingerprints()]), never through a chain, so one certificate may serve every association of the application
/// until it [expires][#expires()].
///
/// {@snippet lang = java :
/// var certificate = DtlsCertificate.generateEcdsa();
/// for (var fingerprint : certificate.fingerprints()) {
///     sdp.append("a=fingerprint:").append(fingerprint.toSdp()).append("\r\n");
/// }
/// }
///
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc5280.html RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public final class DtlsCertificate {
    /// The source of serial numbers and keys.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// The default validity of a generated certificate.
    private static final Duration DEFAULT_VALIDITY = Duration.ofDays(30);

    /// The fingerprint hash functions [#fingerprints()] lists, in order.
    private static final List<String> FINGERPRINT_ALGORITHMS = List.of("sha-256", "sha-384", "sha-512");

    /// The DER encoding of the `ecdsa-with-SHA256` algorithm identifier, OID 1.2.840.10045.4.3.2.
    private static final byte[] ECDSA_SHA256 = {0x30, 0x0A, 0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02};

    /// The DER encoding of the `sha256WithRSAEncryption` algorithm identifier, OID 1.2.840.113549.1.1.11.
    private static final byte[] RSA_SHA256 = {0x30, 0x0D, 0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7,
            0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00};

    /// The private key.
    private final PrivateKey privateKey;

    /// The certificate.
    private final X509Certificate certificate;

    /// The DER encoding of the certificate.
    private final byte[] encoded;

    /// The fingerprints of the certificate.
    private final List<DtlsFingerprint> fingerprints;

    /// Creates a certificate holder.
    private DtlsCertificate(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
        try {
            this.encoded = certificate.getEncoded();
        } catch (CertificateEncodingException exception) {
            throw new IllegalArgumentException("cannot encode the certificate", exception);
        }
        this.fingerprints = FINGERPRINT_ALGORITHMS.stream().map(name -> DtlsFingerprint.of(name, encoded)).toList();
    }

    /// {@return a fresh ECDSA P-256 key pair and its self-signed certificate, valid for thirty days}
    ///
    /// Generating a key pair takes milliseconds of CPU time; reuse one certificate where the application allows it.
    ///
    /// @throws IllegalStateException if the JDK cannot generate EC keys on `secp256r1` or sign with `SHA256withECDSA`
    public static DtlsCertificate generateEcdsa() {
        return generateEcdsa(DEFAULT_VALIDITY);
    }

    /// {@return a fresh ECDSA P-256 key pair and its self-signed certificate, valid for `validity` from now}
    ///
    /// @param validity how long the certificate stays valid, positive
    /// @throws IllegalArgumentException if `validity` is not positive
    /// @throws IllegalStateException    if the JDK cannot generate the key or sign
    public static DtlsCertificate generateEcdsa(Duration validity) {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return selfSigned(generator.generateKeyPair(), "SHA256withECDSA", ECDSA_SHA256, validity);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("cannot generate the ECDSA certificate", exception);
        }
    }

    /// {@return a fresh RSA-2048 key pair and its self-signed certificate, valid for thirty days}
    ///
    /// RSA generation takes tens to hundreds of milliseconds; prefer [#generateEcdsa()] unless a peer requires RSA.
    ///
    /// @throws IllegalStateException if the JDK cannot generate RSA keys or sign with `SHA256withRSA`
    public static DtlsCertificate generateRsa() {
        return generateRsa(DEFAULT_VALIDITY);
    }

    /// {@return a fresh RSA-2048 key pair, public exponent 65537, and its self-signed certificate, valid for
    /// `validity` from now}
    ///
    /// @param validity how long the certificate stays valid, positive
    /// @throws IllegalArgumentException if `validity` is not positive
    /// @throws IllegalStateException    if the JDK cannot generate the key or sign
    public static DtlsCertificate generateRsa(Duration validity) {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), RANDOM);
            return selfSigned(generator.generateKeyPair(), "SHA256withRSA", RSA_SHA256, validity);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("cannot generate the RSA certificate", exception);
        }
    }

    /// {@return a certificate holder for an existing private key and certificate}
    ///
    /// The key must be an EC key on P-256, P-384 or P-521, or an RSA key, and must belong to the certificate's public
    /// key, which this method checks by signing and verifying a test value.
    ///
    /// @param privateKey  the private key
    /// @param certificate the certificate
    /// @throws IllegalArgumentException if the key type is unsupported or the key does not match the certificate
    public static DtlsCertificate of(PrivateKey privateKey, X509Certificate certificate) {
        Objects.requireNonNull(privateKey, "privateKey cannot be null");
        Objects.requireNonNull(certificate, "certificate cannot be null");
        var type = KeyType.of(certificate.getPublicKey());
        if (type == KeyType.ED25519) {
            throw new IllegalArgumentException("Ed25519 certificates are not supported");
        }
        var algorithm = type == KeyType.EC ? "SHA256withECDSA" : "SHA256withRSA";
        try {
            var challenge = new byte[32];
            RANDOM.nextBytes(challenge);
            var signer = Signature.getInstance(algorithm);
            signer.initSign(privateKey);
            signer.update(challenge);
            var signature = signer.sign();
            var verifier = Signature.getInstance(algorithm);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            if (!verifier.verify(signature)) {
                throw new IllegalArgumentException("the private key does not belong to the certificate");
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("the private key does not belong to the certificate", exception);
        }
        return new DtlsCertificate(privateKey, certificate);
    }

    /// {@return the X.509 certificate}
    public X509Certificate certificate() {
        return certificate;
    }

    /// {@return the private key, which signs this endpoint's handshake messages}
    ///
    /// The key is secret: an application reads it only to persist the certificate and import it later with
    /// [#of(PrivateKey,X509Certificate)].
    public PrivateKey privateKey() {
        return privateKey;
    }

    /// {@return the DER encoding of the certificate}
    public byte[] encoded() {
        return encoded.clone();
    }

    /// {@return when the certificate stops being valid, its `notAfter` time}
    public Instant expires() {
        return certificate.getNotAfter().toInstant();
    }

    /// {@return whether the certificate has expired at `instant`}
    ///
    /// @param instant the instant to check
    public boolean isExpired(Instant instant) {
        return !instant.isBefore(expires());
    }

    /// {@return the unmodifiable fingerprints of the certificate under SHA-256, SHA-384 and SHA-512, in that order}
    ///
    /// Each becomes one `a=fingerprint` line; peers that support only SHA-256 use the first.
    public List<DtlsFingerprint> fingerprints() {
        return fingerprints;
    }

    /// {@return the type of the certificate key}
    KeyType keyType() {
        return KeyType.of(certificate.getPublicKey());
    }

    /// {@return the DER encoding without copying, for the handshake}
    byte[] encodedUnsafe() {
        return encoded;
    }

    /// {@return a certificate signed by its own key}
    private static DtlsCertificate selfSigned(KeyPair keyPair, String signatureAlgorithm, byte[] algorithmIdentifier,
                                              Duration validity) throws GeneralSecurityException {
        if (validity.isNegative() || validity.isZero()) {
            throw new IllegalArgumentException("validity must be positive");
        }
        var now = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
        var name = name("WebRTC");
        var tbs = sequence(
                new byte[]{(byte) 0xA0, 0x03, 0x02, 0x01, 0x02},
                integer(new BigInteger(63, RANDOM).add(BigInteger.ONE)),
                algorithmIdentifier,
                name,
                sequence(time(now.minusDays(1)), time(now.plus(validity))),
                name,
                keyPair.getPublic().getEncoded());
        var signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(keyPair.getPrivate());
        signer.update(tbs);
        var signature = signer.sign();
        var bitString = new byte[signature.length + 1];
        System.arraycopy(signature, 0, bitString, 1, signature.length);
        var der = sequence(tbs, algorithmIdentifier, tlv(0x03, bitString));
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        return new DtlsCertificate(keyPair.getPrivate(), certificate);
    }

    /// {@return the DER encoding of a `Name` with one common name}
    private static byte[] name(String commonName) {
        var attribute = sequence(new byte[]{0x06, 0x03, 0x55, 0x04, 0x03},
                tlv(0x0C, commonName.getBytes(StandardCharsets.UTF_8)));
        return sequence(tlv(0x31, attribute));
    }

    /// {@return the DER encoding of a `Time`: `UTCTime` up to 2049, `GeneralizedTime` after}
    private static byte[] time(ZonedDateTime time) {
        if (time.getYear() < 2050) {
            var text = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").format(time);
            return tlv(0x17, text.getBytes(StandardCharsets.US_ASCII));
        }
        var text = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").format(time);
        return tlv(0x18, text.getBytes(StandardCharsets.US_ASCII));
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
