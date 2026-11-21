package com.github.auties00.parley.dtls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/// The state and the shared steps of one side of a DTLS handshake, in either version: the transcript, the negotiated
/// parameters, certificate and extension encoding, and both key schedules.
///
/// A subclass drives one role; it receives complete messages in order from the connection through
/// [#onMessage(HandshakeMessage,long)] and answers through [DtlsConnection#sendFlight(List,boolean)]. Every method runs
/// with the connection's lock held.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc5705.html RFC 5705: Keying Material Exporters for Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc7627.html RFC 7627: Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
abstract sealed class Handshake permits ClientHandshake, ServerHandshake {
    /// The `random` of a `ServerHello` that is a `HelloRetryRequest`: the SHA-256 of `HelloRetryRequest`.
    static final byte[] HELLO_RETRY_REQUEST_RANDOM =
            HexFormat.of().parseHex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    /// The last eight bytes of a DTLS 1.2 `ServerHello` random from a server that supports DTLS 1.3.
    static final byte[] DOWNGRADE_SENTINEL = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};

    /// The `supported_groups` extension.
    static final int EXT_SUPPORTED_GROUPS = 10;

    /// The `ec_point_formats` extension.
    static final int EXT_EC_POINT_FORMATS = 11;

    /// The `signature_algorithms` extension.
    static final int EXT_SIGNATURE_ALGORITHMS = 13;

    /// The `use_srtp` extension.
    static final int EXT_USE_SRTP = 14;

    /// The `extended_master_secret` extension.
    static final int EXT_EXTENDED_MASTER_SECRET = 23;

    /// The `supported_versions` extension.
    static final int EXT_SUPPORTED_VERSIONS = 43;

    /// The `cookie` extension.
    static final int EXT_COOKIE = 44;

    /// The `key_share` extension.
    static final int EXT_KEY_SHARE = 51;

    /// The `renegotiation_info` extension.
    static final int EXT_RENEGOTIATION_INFO = 0xFF01;

    /// The length of a `Finished` value in DTLS 1.2.
    static final int FINISHED_LENGTH_12 = 12;

    /// The connection the handshake runs on.
    final DtlsConnection connection;

    /// The settings.
    final DtlsConfig config;

    /// The fingerprints the peer's certificate must match one of.
    final List<DtlsFingerprint> acceptedFingerprints;

    /// Whether the handshake fails when no SRTP profile is agreed.
    final boolean requireSrtp;

    /// The messages the transcript covers.
    final Transcript transcript = new Transcript();

    /// The negotiated version, `null` until the `ServerHello`.
    DtlsVersion version;

    /// The negotiated cipher suite, `null` until the `ServerHello`.
    CipherSuite suite;

    /// The negotiated SRTP profile, `null` when none is agreed yet.
    SrtpProfile profile;

    /// The peer's verified certificate, `null` before it arrived.
    X509Certificate peerCertificate;

    /// The certificate this side presents, `null` until chosen.
    DtlsCertificate localCertificate;

    /// The next outgoing message sequence number.
    int sendSeq;

    /// Whether this side completed the handshake.
    boolean complete;

    /// The client random.
    byte[] clientRandom;

    /// The server random.
    byte[] serverRandom;

    /// The DTLS 1.2 master secret, or the DTLS 1.3 handshake secret before the master secret replaces it.
    byte[] masterSecret;

    /// The DTLS 1.3 client handshake traffic secret.
    byte[] clientHandshakeSecret;

    /// The DTLS 1.3 server handshake traffic secret.
    byte[] serverHandshakeSecret;

    /// The current DTLS 1.3 client application traffic secret.
    byte[] clientApplicationSecret;

    /// The current DTLS 1.3 server application traffic secret.
    byte[] serverApplicationSecret;

    /// The DTLS 1.3 exporter master secret.
    byte[] exporterSecret;

    /// Creates the state of a handshake.
    ///
    /// @param connection           the connection
    /// @param remoteFingerprints   the peer's signalled fingerprints
    /// @param requireSrtp          whether an SRTP profile must be agreed
    Handshake(DtlsConnection connection, List<DtlsFingerprint> remoteFingerprints, boolean requireSrtp) {
        this.connection = connection;
        this.config = connection.config();
        this.acceptedFingerprints = DtlsFingerprint.select(remoteFingerprints);
        this.requireSrtp = requireSrtp;
    }

    /// Starts the handshake: a client sends its `ClientHello`, a server does nothing.
    ///
    /// @throws IOException if sending fails
    abstract void start() throws IOException;

    /// Handles one complete handshake message, in message sequence order.
    ///
    /// @param message the message
    /// @param epoch   the epoch its fragments arrived in
    /// @throws IOException if the message is unexpected or invalid, or a send fails
    abstract void onMessage(HandshakeMessage message, long epoch) throws IOException;

    /// {@return the role of this side}
    abstract DtlsRole role();

    /// {@return whether the peer's first flight was verified: a server accepted a `ClientHello` (after its cookie when
    /// cookies are exchanged), a client accepted the `ServerHello`}
    abstract boolean helloAccepted();

    /// {@return a new outgoing message with the next message sequence number}
    ///
    /// @param type the handshake type
    /// @param body the body
    final HandshakeMessage newMessage(int type, byte[] body) {
        return new HandshakeMessage(type, sendSeq++, body);
    }

    /// Fails unless a message arrived in the epoch its position in the handshake requires.
    ///
    /// @param epoch    the epoch it arrived in
    /// @param expected the required epoch
    /// @param message  the message
    /// @throws DtlsException if the epochs differ
    static void requireEpoch(long epoch, long expected, HandshakeMessage message) throws DtlsException {
        if (epoch != expected) {
            throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE,
                    "handshake message " + message.type() + " in epoch " + epoch + ", expected " + expected);
        }
    }

    /// {@return the extensions of a hello or `EncryptedExtensions`, in order}
    ///
    /// @param reader the reader positioned at the extensions vector; absent extensions give an empty map
    /// @throws DtlsException if the vector is malformed or repeats an extension
    static Map<Integer, byte[]> readExtensions(TlsReader reader) throws DtlsException {
        var extensions = new LinkedHashMap<Integer, byte[]>();
        if (!reader.hasRemaining()) {
            return extensions;
        }
        var vector = reader.sub16();
        while (vector.hasRemaining()) {
            var type = vector.u16();
            var data = vector.vector16();
            if (extensions.put(type, data) != null) {
                throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "extension " + type + " repeated");
            }
        }
        reader.expectEnd();
        return extensions;
    }

    /// Writes one extension.
    ///
    /// @param writer the writer
    /// @param type   the extension type
    /// @param data   the extension data
    static void writeExtension(TlsWriter writer, int type, byte[] data) {
        writer.u16(type).vector16(data);
    }

    /// {@return the data of a `use_srtp` extension listing profiles with an empty MKI}
    ///
    /// @param profiles the profiles
    static byte[] useSrtp(List<SrtpProfile> profiles) {
        var writer = new TlsWriter();
        var mark = writer.open16();
        for (var profile : profiles) {
            writer.u16(profile.id());
        }
        writer.close(mark);
        return writer.u8(0).toByteArray();
    }

    /// {@return the profiles a `use_srtp` extension lists that this library supports, in the listed order}
    ///
    /// @param data the extension data
    /// @throws DtlsException if the data is malformed
    static List<SrtpProfile> readUseSrtp(byte[] data) throws DtlsException {
        var reader = new TlsReader(data);
        var ids = reader.sub16();
        var profiles = new ArrayList<SrtpProfile>();
        while (ids.hasRemaining()) {
            SrtpProfile.ofId(ids.u16()).ifPresent(profiles::add);
        }
        reader.vector8();
        reader.expectEnd();
        return profiles;
    }

    /// {@return the data of a `signature_algorithms` extension}
    ///
    /// @param includeLegacy whether to include the DTLS 1.2-only schemes
    static byte[] signatureAlgorithms(boolean includeLegacy) {
        var writer = new TlsWriter();
        var mark = writer.open16();
        for (var scheme : SignatureScheme.advertised(includeLegacy)) {
            writer.u16(scheme.id());
        }
        writer.close(mark);
        return writer.toByteArray();
    }

    /// {@return the scheme codes a `signature_algorithms` extension lists}
    ///
    /// @param data the extension data
    /// @throws DtlsException if the data is malformed
    static List<Integer> readSignatureAlgorithms(byte[] data) throws DtlsException {
        var reader = new TlsReader(data);
        var vector = reader.sub16();
        reader.expectEnd();
        return readU16List(vector);
    }

    /// {@return the 16-bit values a reader holds}
    ///
    /// @param reader the reader
    /// @throws DtlsException if a value is truncated
    static List<Integer> readU16List(TlsReader reader) throws DtlsException {
        var values = new ArrayList<Integer>();
        while (reader.hasRemaining()) {
            values.add(reader.u16());
        }
        return values;
    }

    /// {@return the data of a `supported_groups` extension listing every group of this library}
    static byte[] supportedGroups() {
        var writer = new TlsWriter();
        var mark = writer.open16();
        for (var group : NamedGroup.values()) {
            writer.u16(group.id());
        }
        writer.close(mark);
        return writer.toByteArray();
    }

    /// {@return the first SRTP profile of the configuration that `offered` contains, if any}
    ///
    /// @param offered the profiles the client offered
    final Optional<SrtpProfile> chooseProfile(List<SrtpProfile> offered) {
        return config.srtpProfiles().stream().filter(offered::contains).findFirst();
    }

    /// Fails when no SRTP profile was agreed although the caller requires one.
    ///
    /// @throws DtlsException if SRTP is required and missing
    final void checkSrtp() throws DtlsException {
        if (profile == null && requireSrtp) {
            throw new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "no SRTP profile was agreed");
        }
    }

    /// {@return the leaf of a certificate chain, verified against the signalled fingerprints}
    ///
    /// @param chain the DER certificates, leaf first
    /// @throws DtlsException if the chain is empty, malformed, or the leaf matches no fingerprint
    final X509Certificate acceptCertificate(List<byte[]> chain) throws DtlsException {
        if (chain.isEmpty()) {
            throw new DtlsException(version == DtlsVersion.DTLS_1_3 ? DtlsAlert.CERTIFICATE_REQUIRED : DtlsAlert.HANDSHAKE_FAILURE,
                    "the peer presented no certificate");
        }
        var leaf = chain.getFirst();
        var matches = false;
        for (var fingerprint : acceptedFingerprints) {
            matches |= fingerprint.matches(leaf);
        }
        if (!matches) {
            throw new DtlsException(DtlsAlert.BAD_CERTIFICATE, "the peer's certificate matches no signalled fingerprint");
        }
        try {
            var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(leaf));
            KeyType.of(certificate.getPublicKey());
            return certificate;
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new DtlsException(DtlsAlert.UNSUPPORTED_CERTIFICATE, false, "the peer's certificate is unusable", exception);
        }
    }

    /// {@return the body of a DTLS 1.2 `Certificate` message}
    ///
    /// @param certificate the certificate, or `null` for an empty list
    static byte[] certificate12(DtlsCertificate certificate) {
        var writer = new TlsWriter(2048);
        var list = writer.open24();
        if (certificate != null) {
            writer.vector24(certificate.encodedUnsafe());
        }
        writer.close(list);
        return writer.toByteArray();
    }

    /// {@return the DER certificates of a DTLS 1.2 `Certificate` message}
    ///
    /// @param body the body
    /// @throws DtlsException if the message is malformed
    static List<byte[]> readCertificate12(byte[] body) throws DtlsException {
        var reader = new TlsReader(body);
        var list = reader.sub24();
        reader.expectEnd();
        var chain = new ArrayList<byte[]>();
        while (list.hasRemaining()) {
            chain.add(list.vector24());
        }
        return chain;
    }

    /// {@return the body of a DTLS 1.3 `Certificate` message}
    ///
    /// @param context     the certificate request context
    /// @param certificate the certificate
    static byte[] certificate13(byte[] context, DtlsCertificate certificate) {
        var writer = new TlsWriter(2048).vector8(context);
        var list = writer.open24();
        writer.vector24(certificate.encodedUnsafe()).u16(0);
        writer.close(list);
        return writer.toByteArray();
    }

    /// {@return the DER certificates of a DTLS 1.3 `Certificate` message}
    ///
    /// @param body            the body
    /// @param expectedContext the certificate request context it must carry
    /// @throws DtlsException if the message is malformed or the context differs
    static List<byte[]> readCertificate13(byte[] body, byte[] expectedContext) throws DtlsException {
        var reader = new TlsReader(body);
        var context = reader.vector8();
        if (!Arrays.equals(context, expectedContext)) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "certificate request context mismatch");
        }
        var list = reader.sub24();
        reader.expectEnd();
        var chain = new ArrayList<byte[]>();
        while (list.hasRemaining()) {
            chain.add(list.vector24());
            list.vector16();
        }
        return chain;
    }

    /// {@return the certificate of the configuration that can sign with a scheme the peer lists}
    ///
    /// @param peerSchemes the scheme codes the peer listed
    /// @param types       the key types acceptable, in any order
    final Optional<DtlsCertificate> chooseCertificate(List<Integer> peerSchemes, List<KeyType> types) {
        for (var certificate : config.certificates()) {
            if (types.contains(certificate.keyType())
                    && SignatureScheme.choose(certificate.privateKey(), peerSchemes, version).isPresent()) {
                return Optional.of(certificate);
            }
        }
        return Optional.empty();
    }

    /// {@return the body of a `CertificateVerify` or the signed part of a `ServerKeyExchange`: scheme and signature}
    ///
    /// @param peerSchemes the scheme codes the peer accepts
    /// @param signed      the data to sign
    /// @throws DtlsException if no scheme fits the local key or signing fails
    final byte[] signature(List<Integer> peerSchemes, byte[] signed) throws DtlsException {
        var key = localCertificate.privateKey();
        var scheme = SignatureScheme.choose(key, peerSchemes, version)
                .orElseThrow(() -> new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "no common signature scheme"));
        return new TlsWriter(256).u16(scheme.id()).vector16(scheme.sign(key, signed)).toByteArray();
    }

    /// Verifies a signature of the peer, read as scheme and signature from `reader`.
    ///
    /// @param reader  the reader positioned at the scheme
    /// @param signed  the data that was signed
    /// @param offered the scheme codes this side offered, which the peer must have used one of
    /// @throws DtlsException if the scheme is not offered or does not fit the key, or the signature does not verify
    final void verifySignature(TlsReader reader, byte[] signed, List<Integer> offered) throws DtlsException {
        var code = reader.u16();
        var signature = reader.vector16();
        var key = peerCertificate.getPublicKey();
        var scheme = SignatureScheme.ofId(code)
                .filter(candidate -> offered.contains(code) && candidate.accepts(key, version))
                .orElseThrow(() -> new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "unacceptable signature scheme 0x"
                        + Integer.toHexString(code)));
        if (!scheme.verify(key, signed, signature)) {
            throw new DtlsException(DtlsAlert.DECRYPT_ERROR, "the peer's signature does not verify");
        }
    }

    /// {@return the scheme codes this side advertises, as a list}
    final List<Integer> advertisedSchemes() {
        return SignatureScheme.advertised(version != DtlsVersion.DTLS_1_3).stream().map(SignatureScheme::id).toList();
    }

    /// Derives the DTLS 1.2 master secret and installs the epoch 1 keys of both directions.
    ///
    /// The read epoch is usable at once: a record of epoch 1 can only be the peer's, sent after its
    /// `ChangeCipherSpec`.
    ///
    /// @param preMaster            the ECDHE shared secret, wiped afterwards
    /// @param extendedMasterSecret whether the extended master secret was negotiated
    final void deriveKeys12(byte[] preMaster, boolean extendedMasterSecret) {
        var hash = suite.hash();
        masterSecret = extendedMasterSecret
                ? TlsPrf.compute(hash, preMaster, "extended master secret", transcript.hash(version, hash), 48)
                : TlsPrf.compute(hash, preMaster, "master secret", TlsPrf.concat(clientRandom, serverRandom), 48);
        Arrays.fill(preMaster, (byte) 0);
        var aead = suite.aead();
        var keyLength = aead.keyLength();
        var ivLength = Dtls12RecordCipher.fixedIvLength(aead);
        var block = TlsPrf.compute(hash, masterSecret, "key expansion", TlsPrf.concat(serverRandom, clientRandom),
                2 * keyLength + 2 * ivLength);
        var client = new Dtls12RecordCipher(aead, Arrays.copyOfRange(block, 0, keyLength),
                Arrays.copyOfRange(block, 2 * keyLength, 2 * keyLength + ivLength));
        var server = new Dtls12RecordCipher(aead, Arrays.copyOfRange(block, keyLength, 2 * keyLength),
                Arrays.copyOfRange(block, 2 * keyLength + ivLength, 2 * keyLength + 2 * ivLength));
        Arrays.fill(block, (byte) 0);
        var records = connection.records();
        records.installWrite(1, role() == DtlsRole.CLIENT ? client : server);
        records.installRead(1, role() == DtlsRole.CLIENT ? server : client);
    }

    /// {@return a DTLS 1.2 `Finished` value over the current transcript}
    ///
    /// @param label `client finished` or `server finished`
    final byte[] finished12(String label) {
        var hash = suite.hash();
        return TlsPrf.compute(hash, masterSecret, label, transcript.hash(version, hash), FINISHED_LENGTH_12);
    }

    /// Checks a DTLS 1.2 `Finished` value from the peer.
    ///
    /// @param label `client finished` or `server finished`
    /// @param body  the received value
    /// @throws DtlsException if it differs
    final void verifyFinished12(String label, byte[] body) throws DtlsException {
        if (!MessageDigest.isEqual(finished12(label), body)) {
            throw new DtlsException(DtlsAlert.DECRYPT_ERROR, "the peer's Finished does not verify");
        }
    }

    /// Derives the DTLS 1.3 handshake traffic secrets from the ECDHE secret over the transcript up to the
    /// `ServerHello`, and installs the epoch 2 keys of both directions.
    ///
    /// @param shared the ECDHE shared secret, wiped afterwards
    final void deriveHandshakeSecrets13(byte[] shared) {
        var hash = suite.hash();
        var early = Hkdf.extract(hash, new byte[0], new byte[0]);
        var derived = Hkdf.deriveSecret(hash, early, "derived", hash.hash(new byte[0]));
        var handshakeSecret = Hkdf.extract(hash, derived, shared);
        Arrays.fill(shared, (byte) 0);
        var transcriptHash = transcript.hash(version, hash);
        clientHandshakeSecret = Hkdf.deriveSecret(hash, handshakeSecret, "c hs traffic", transcriptHash);
        serverHandshakeSecret = Hkdf.deriveSecret(hash, handshakeSecret, "s hs traffic", transcriptHash);
        masterSecret = handshakeSecret;
        var records = connection.records();
        var client = Dtls13RecordCipher.fromSecret(suite, clientHandshakeSecret);
        var server = Dtls13RecordCipher.fromSecret(suite, serverHandshakeSecret);
        records.installWrite(2, role() == DtlsRole.CLIENT ? client : server);
        records.installRead(2, role() == DtlsRole.CLIENT ? server : client);
    }

    /// Derives the DTLS 1.3 application traffic and exporter secrets over the transcript up to the server `Finished`.
    final void deriveApplicationSecrets13() {
        var hash = suite.hash();
        var derived = Hkdf.deriveSecret(hash, masterSecret, "derived", hash.hash(new byte[0]));
        var master = Hkdf.extract(hash, derived, new byte[0]);
        var transcriptHash = transcript.hash(version, hash);
        clientApplicationSecret = Hkdf.deriveSecret(hash, master, "c ap traffic", transcriptHash);
        serverApplicationSecret = Hkdf.deriveSecret(hash, master, "s ap traffic", transcriptHash);
        exporterSecret = Hkdf.deriveSecret(hash, master, "exp master", transcriptHash);
        masterSecret = master;
    }

    /// {@return a DTLS 1.3 `Finished` value over the current transcript}
    ///
    /// @param baseSecret the handshake traffic secret of the side that sends it
    final byte[] finished13(byte[] baseSecret) {
        var hash = suite.hash();
        var key = Hkdf.expandLabel(hash, baseSecret, "finished", new byte[0], hash.length());
        return hash.hmac(key, transcript.hash(version, hash));
    }

    /// Checks a DTLS 1.3 `Finished` value from the peer.
    ///
    /// @param baseSecret the peer's handshake traffic secret
    /// @param body       the received value
    /// @throws DtlsException if it differs
    final void verifyFinished13(byte[] baseSecret, byte[] body) throws DtlsException {
        if (!MessageDigest.isEqual(finished13(baseSecret), body)) {
            throw new DtlsException(DtlsAlert.DECRYPT_ERROR, "the peer's Finished does not verify");
        }
    }

    /// {@return the content a DTLS 1.3 `CertificateVerify` signs: 64 spaces, the context string, a zero byte and the
    /// transcript hash}
    ///
    /// @param server whether the server signs it
    final byte[] certificateVerifyContent13(boolean server) {
        var context = (server ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify")
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        var prefix = new byte[64];
        Arrays.fill(prefix, (byte) 0x20);
        return TlsPrf.concat(prefix, context, new byte[1], transcript.hash(version, suite.hash()));
    }

    /// {@return the next application traffic secret of a DTLS 1.3 key update}
    ///
    /// @param secret the current secret
    final byte[] nextApplicationSecret(byte[] secret) {
        var hash = suite.hash();
        return Hkdf.expandLabel(hash, secret, "traffic upd", new byte[0], hash.length());
    }

    /// {@return `length` bytes of keying material exported under `label` with no context}
    ///
    /// @param label  the exporter label, such as `EXTRACTOR-dtls_srtp`
    /// @param length the number of bytes
    final byte[] export(String label, int length) {
        var hash = suite.hash();
        if (version == DtlsVersion.DTLS_1_3) {
            var secret = Hkdf.deriveSecret(hash, exporterSecret, label, hash.hash(new byte[0]));
            return Hkdf.expandLabel(hash, secret, "exporter", hash.hash(new byte[0]), length);
        }
        return TlsPrf.compute(hash, masterSecret, label, TlsPrf.concat(clientRandom, serverRandom), length);
    }

    /// {@return the SRTP keys of the negotiated profile, assigned to this side's role}
    ///
    /// The exporter output is `client_key || server_key || client_salt || server_salt` (RFC 5764 section 4.2).
    final DtlsSrtpKeys srtpKeys() {
        var keyLength = profile.keyLength();
        var saltLength = profile.saltLength();
        var material = export("EXTRACTOR-dtls_srtp", 2 * (keyLength + saltLength));
        var clientKey = Arrays.copyOfRange(material, 0, keyLength);
        var serverKey = Arrays.copyOfRange(material, keyLength, 2 * keyLength);
        var clientSalt = Arrays.copyOfRange(material, 2 * keyLength, 2 * keyLength + saltLength);
        var serverSalt = Arrays.copyOfRange(material, 2 * keyLength + saltLength, material.length);
        Arrays.fill(material, (byte) 0);
        return role() == DtlsRole.CLIENT
                ? new DtlsSrtpKeys(profile, clientKey, clientSalt, serverKey, serverSalt)
                : new DtlsSrtpKeys(profile, serverKey, serverSalt, clientKey, clientSalt);
    }

    /// {@return a fresh 32-byte random}
    static byte[] random() {
        var bytes = new byte[32];
        DtlsConnection.RANDOM.nextBytes(bytes);
        return bytes;
    }
}
