package com.github.auties00.parley.dtls;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/// The client side of a DTLS handshake, negotiating DTLS 1.3 or DTLS 1.2 with one `ClientHello`.
///
/// The `ClientHello` is DTLS 1.2 compatible and, when DTLS 1.3 is configured, also carries `supported_versions` and an
/// X25519 `key_share`; the `ServerHello` decides the version. A DTLS 1.2 server may answer with a
/// `HelloVerifyRequest` and a DTLS 1.3 server with a `HelloRetryRequest` (cookie, other group, or both), each answered
/// with a new `ClientHello`. Flights:
///
/// ```text
/// DTLS 1.2: ClientHello -> ServerHello Certificate ServerKeyExchange CertificateRequest ServerHelloDone
///           Certificate ClientKeyExchange CertificateVerify [ChangeCipherSpec] Finished -> [ChangeCipherSpec] Finished
/// DTLS 1.3: ClientHello -> ServerHello {EncryptedExtensions CertificateRequest Certificate CertificateVerify Finished}
///           {Certificate CertificateVerify Finished} -> [ACK]
/// ```
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc8422.html RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
/// @spec https://www.rfc-editor.org/rfc/rfc5746.html RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension
final class ClientHandshake extends Handshake {
    /// Whether DTLS 1.2 is offered.
    private final boolean offer12;

    /// Whether DTLS 1.3 is offered.
    private final boolean offer13;

    /// The DTLS 1.3 key shares sent, by group.
    private final Map<NamedGroup, KeyPair> keyShares = new EnumMap<>(NamedGroup.class);

    /// The DTLS 1.2 cookie of a `HelloVerifyRequest`, empty before one.
    private byte[] legacyCookie = new byte[0];

    /// The DTLS 1.3 cookie of a `HelloRetryRequest`, or `null`.
    private byte[] retryCookie;

    /// Whether a `HelloRetryRequest` arrived.
    private boolean retried;

    /// The suite a `HelloRetryRequest` chose, which the `ServerHello` must repeat, or `null`.
    private CipherSuite retrySuite;

    /// Whether the `ServerHello` arrived.
    private boolean serverHelloReceived;

    /// The DTLS 1.2 group of the server key exchange.
    private NamedGroup group;

    /// The server's DTLS 1.2 ephemeral key.
    private PublicKey serverEphemeral;

    /// Whether the DTLS 1.2 extended master secret was negotiated.
    private boolean extendedMasterSecret;

    /// Whether the server asked for this client's certificate.
    private boolean certificateRequested;

    /// The signature schemes the server's `CertificateRequest` listed.
    private List<Integer> requestedSchemes = List.of();

    /// The key types a DTLS 1.2 `CertificateRequest` accepts.
    private List<KeyType> requestedTypes = List.of(KeyType.EC, KeyType.RSA);

    /// The DTLS 1.3 certificate request context.
    private byte[] requestContext = new byte[0];

    /// Whether the server's DTLS 1.3 `CertificateVerify` verified, without which its `Finished` proves nothing.
    private boolean serverVerified;

    /// Creates the client side.
    ///
    /// @param connection         the connection
    /// @param remoteFingerprints the server's signalled fingerprints
    /// @param requireSrtp        whether an SRTP profile must be agreed
    ClientHandshake(DtlsConnection connection, List<DtlsFingerprint> remoteFingerprints, boolean requireSrtp) {
        super(connection, remoteFingerprints, requireSrtp);
        this.offer12 = config.versions().contains(DtlsVersion.DTLS_1_2);
        this.offer13 = config.versions().contains(DtlsVersion.DTLS_1_3);
    }

    @Override
    DtlsRole role() {
        return DtlsRole.CLIENT;
    }

    @Override
    void start() throws IOException {
        clientRandom = random();
        if (offer13) {
            keyShares.put(NamedGroup.X25519, NamedGroup.X25519.generate());
        }
        sendClientHello();
    }

    @Override
    void onMessage(HandshakeMessage message, long epoch) throws IOException {
        if (complete) {
            return;
        }
        if (!serverHelloReceived) {
            requireEpoch(epoch, 0, message);
            switch (message.type()) {
                case HandshakeMessage.HELLO_VERIFY_REQUEST -> onHelloVerifyRequest(message);
                case HandshakeMessage.SERVER_HELLO -> onServerHello(message);
                default -> throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE,
                        "expected ServerHello, got message " + message.type());
            }
            return;
        }
        if (version == DtlsVersion.DTLS_1_3) {
            onMessage13(message, epoch);
        } else {
            onMessage12(message, epoch);
        }
    }

    /// Sends a `ClientHello` with the current cookies and key shares, as a new flight.
    private void sendClientHello() throws IOException {
        var body = new TlsWriter(512)
                .u16(DtlsVersion.DTLS_1_2.wireValue())
                .bytes(clientRandom)
                .vector8(new byte[0])
                .vector8(legacyCookie);
        var suites = body.open16();
        if (offer13) {
            for (var suite : CipherSuite.of(DtlsVersion.DTLS_1_3)) {
                body.u16(suite.id());
            }
        }
        if (offer12) {
            for (var suite : CipherSuite.of(DtlsVersion.DTLS_1_2)) {
                body.u16(suite.id());
            }
        }
        body.close(suites);
        body.vector8(new byte[]{0});
        var extensions = body.open16();
        writeExtension(body, EXT_SUPPORTED_GROUPS, supportedGroups());
        writeExtension(body, EXT_SIGNATURE_ALGORITHMS, signatureAlgorithms(offer12));
        if (!config.srtpProfiles().isEmpty()) {
            writeExtension(body, EXT_USE_SRTP, useSrtp(config.srtpProfiles()));
        }
        if (offer12) {
            writeExtension(body, EXT_EC_POINT_FORMATS, new byte[]{1, 0});
            writeExtension(body, EXT_EXTENDED_MASTER_SECRET, new byte[0]);
            writeExtension(body, EXT_RENEGOTIATION_INFO, new byte[]{0});
        }
        if (offer13) {
            var versions = new TlsWriter().u8(offer12 ? 4 : 2).u16(DtlsVersion.DTLS_1_3.wireValue());
            if (offer12) {
                versions.u16(DtlsVersion.DTLS_1_2.wireValue());
            }
            writeExtension(body, EXT_SUPPORTED_VERSIONS, versions.toByteArray());
            var shares = new TlsWriter();
            var list = shares.open16();
            for (var entry : keyShares.entrySet()) {
                shares.u16(entry.getKey().id()).vector16(entry.getKey().encode(entry.getValue().getPublic()));
            }
            shares.close(list);
            writeExtension(body, EXT_KEY_SHARE, shares.toByteArray());
            if (retryCookie != null) {
                writeExtension(body, EXT_COOKIE, new TlsWriter().vector16(retryCookie).toByteArray());
            }
        }
        body.close(extensions);
        var hello = newMessage(HandshakeMessage.CLIENT_HELLO, body.toByteArray());
        transcript.add(hello);
        connection.sendFlight(List.of(new Outgoing.Message(hello, 0)), true);
    }

    /// Answers a DTLS 1.2 `HelloVerifyRequest` with a `ClientHello` carrying its cookie.
    private void onHelloVerifyRequest(HandshakeMessage message) throws IOException {
        if (!offer12) {
            throw new DtlsException(DtlsAlert.PROTOCOL_VERSION, "a DTLS 1.2 HelloVerifyRequest to a DTLS 1.3-only client");
        }
        if (retried) {
            throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "unexpected HelloVerifyRequest");
        }
        var reader = new TlsReader(message.body());
        reader.u16();
        var cookie = reader.vector8();
        reader.expectEnd();
        if (cookie.length == 0) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "HelloVerifyRequest without a cookie");
        }
        legacyCookie = cookie;
        transcript.clear();
        sendClientHello();
    }

    /// Handles a `ServerHello` or a `HelloRetryRequest`.
    private void onServerHello(HandshakeMessage message) throws IOException {
        var reader = new TlsReader(message.body());
        var legacyVersion = reader.u16();
        var random = reader.bytes(32);
        var sessionId = reader.vector8();
        var suiteId = reader.u16();
        var compression = reader.u8();
        var extensions = readExtensions(reader);
        if (compression != 0) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the server chose compression");
        }
        var chosenSuite = CipherSuite.ofId(suiteId)
                .orElseThrow(() -> new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the server chose an unoffered suite"));
        var supportedVersion = extensions.get(EXT_SUPPORTED_VERSIONS);
        if (supportedVersion != null) {
            if (!offer13) {
                throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "supported_versions in a DTLS 1.2 ServerHello");
            }
            var selected = new TlsReader(supportedVersion);
            var wire = selected.u16();
            selected.expectEnd();
            if (wire != DtlsVersion.DTLS_1_3.wireValue() || legacyVersion != DtlsVersion.DTLS_1_2.wireValue()) {
                throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the server selected an unoffered version");
            }
            if (chosenSuite.version() != DtlsVersion.DTLS_1_3 || sessionId.length != 0) {
                throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "invalid DTLS 1.3 ServerHello");
            }
            if (Arrays.equals(random, HELLO_RETRY_REQUEST_RANDOM)) {
                onHelloRetryRequest(message, chosenSuite, extensions);
                return;
            }
            serverHello13(message, random, chosenSuite, extensions);
            return;
        }
        if (!offer12 || legacyVersion != DtlsVersion.DTLS_1_2.wireValue() || chosenSuite.version() != DtlsVersion.DTLS_1_2
                || retried) {
            throw new DtlsException(DtlsAlert.PROTOCOL_VERSION, "the server chose an unoffered version or suite");
        }
        if (offer13 && Arrays.equals(Arrays.copyOfRange(random, 24, 32), DOWNGRADE_SENTINEL)) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "DTLS 1.3 downgrade detected");
        }
        serverHello12(message, random, chosenSuite, extensions);
    }

    /// Handles a DTLS 1.3 `HelloRetryRequest`: replaces the transcript's first hello and sends a new `ClientHello`.
    private void onHelloRetryRequest(HandshakeMessage message, CipherSuite chosenSuite, Map<Integer, byte[]> extensions)
            throws IOException {
        if (retried) {
            throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "a second HelloRetryRequest");
        }
        retried = true;
        retrySuite = chosenSuite;
        var changed = false;
        var keyShare = extensions.get(EXT_KEY_SHARE);
        if (keyShare != null) {
            var reader = new TlsReader(keyShare);
            var selected = NamedGroup.ofId(reader.u16())
                    .orElseThrow(() -> new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the server selected an unoffered group"));
            reader.expectEnd();
            if (keyShares.containsKey(selected)) {
                throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "HelloRetryRequest for a group already shared");
            }
            keyShares.clear();
            keyShares.put(selected, selected.generate());
            changed = true;
        }
        var cookie = extensions.get(EXT_COOKIE);
        if (cookie != null) {
            var reader = new TlsReader(cookie);
            retryCookie = reader.vector16();
            reader.expectEnd();
            changed = true;
        }
        if (!changed) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "HelloRetryRequest changes nothing");
        }
        version = DtlsVersion.DTLS_1_3;
        transcript.replaceWithMessageHash(chosenSuite.hash());
        transcript.add(message);
        sendClientHello();
    }

    /// Handles a DTLS 1.3 `ServerHello`: derives and installs the handshake keys.
    private void serverHello13(HandshakeMessage message, byte[] random, CipherSuite chosenSuite,
                               Map<Integer, byte[]> extensions) throws IOException {
        if (retrySuite != null && retrySuite != chosenSuite) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the ServerHello changed the HelloRetryRequest suite");
        }
        var share = extensions.get(EXT_KEY_SHARE);
        if (share == null) {
            throw new DtlsException(DtlsAlert.MISSING_EXTENSION, "DTLS 1.3 ServerHello without key_share");
        }
        var reader = new TlsReader(share);
        var selected = NamedGroup.ofId(reader.u16()).filter(keyShares::containsKey)
                .orElseThrow(() -> new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the server shared an unoffered group"));
        var serverKey = selected.decode(reader.vector16());
        reader.expectEnd();
        version = DtlsVersion.DTLS_1_3;
        suite = chosenSuite;
        serverRandom = random;
        serverHelloReceived = true;
        connection.onVersionNegotiated(version, suite);
        transcript.add(message);
        deriveHandshakeSecrets13(selected.agree(keyShares.get(selected), serverKey));
        connection.setWriteEpoch(2);
    }

    /// Handles a DTLS 1.2 `ServerHello`.
    private void serverHello12(HandshakeMessage message, byte[] random, CipherSuite chosenSuite,
                               Map<Integer, byte[]> extensions) throws IOException {
        var useSrtp = extensions.get(EXT_USE_SRTP);
        if (useSrtp != null) {
            var chosen = readUseSrtp(useSrtp);
            if (chosen.size() != 1 || !config.srtpProfiles().contains(chosen.getFirst())) {
                throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the server chose an unoffered SRTP profile");
            }
            profile = chosen.getFirst();
        }
        var renegotiation = extensions.get(EXT_RENEGOTIATION_INFO);
        if (renegotiation != null && !Arrays.equals(renegotiation, new byte[]{0})) {
            throw new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "non-empty renegotiation_info in an initial handshake");
        }
        extendedMasterSecret = extensions.containsKey(EXT_EXTENDED_MASTER_SECRET);
        version = DtlsVersion.DTLS_1_2;
        suite = chosenSuite;
        serverRandom = random;
        serverHelloReceived = true;
        connection.onVersionNegotiated(version, suite);
        checkSrtp();
        transcript.add(message);
    }

    /// Handles a DTLS 1.2 message after the `ServerHello`.
    private void onMessage12(HandshakeMessage message, long epoch) throws IOException {
        var body = message.body();
        switch (message.type()) {
            case HandshakeMessage.CERTIFICATE -> {
                requireEpoch(epoch, 0, message);
                if (peerCertificate != null) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "a second Certificate");
                }
                peerCertificate = acceptCertificate(readCertificate12(body));
                if (KeyType.of(peerCertificate.getPublicKey()) != suite.keyType().orElseThrow()) {
                    throw new DtlsException(DtlsAlert.UNSUPPORTED_CERTIFICATE, "certificate key does not fit the suite");
                }
                transcript.add(message);
            }
            case HandshakeMessage.SERVER_KEY_EXCHANGE -> {
                requireEpoch(epoch, 0, message);
                requireCertificate();
                var reader = new TlsReader(body);
                if (reader.u8() != 3) {
                    throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "server key exchange is not a named curve");
                }
                group = NamedGroup.ofId(reader.u16())
                        .orElseThrow(() -> new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "server chose an unoffered group"));
                var point = reader.vector8();
                var params = Arrays.copyOfRange(body, 0, reader.position());
                verifySignature(reader, TlsPrf.concat(clientRandom, serverRandom, params), advertisedSchemes());
                reader.expectEnd();
                serverEphemeral = group.decode(point);
                transcript.add(message);
            }
            case HandshakeMessage.CERTIFICATE_REQUEST -> {
                requireEpoch(epoch, 0, message);
                var reader = new TlsReader(body);
                var types = new ArrayList<KeyType>();
                for (var type : reader.vector8()) {
                    switch (type) {
                        case 64 -> types.add(KeyType.EC);
                        case 1 -> types.add(KeyType.RSA);
                        default -> {
                        }
                    }
                }
                requestedSchemes = readU16List(reader.sub16());
                reader.vector16();
                reader.expectEnd();
                requestedTypes = types;
                certificateRequested = true;
                transcript.add(message);
            }
            case HandshakeMessage.SERVER_HELLO_DONE -> {
                requireEpoch(epoch, 0, message);
                if (serverEphemeral == null) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "ServerHelloDone before the key exchange");
                }
                transcript.add(message);
                sendFinalFlight12();
            }
            case HandshakeMessage.FINISHED -> {
                requireEpoch(epoch, 1, message);
                if (masterSecret == null) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "Finished before the key exchange");
                }
                verifyFinished12("server finished", body);
                transcript.add(message);
                complete = true;
            }
            default -> throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "unexpected handshake message " + message.type());
        }
    }

    /// Sends the DTLS 1.2 client's second flight.
    private void sendFinalFlight12() throws IOException {
        var flight = new ArrayList<Outgoing>();
        if (certificateRequested) {
            localCertificate = chooseCertificate(requestedSchemes, requestedTypes).orElse(null);
            var certificate = newMessage(HandshakeMessage.CERTIFICATE, certificate12(localCertificate));
            transcript.add(certificate);
            flight.add(new Outgoing.Message(certificate, 0));
        }
        var ephemeral = group.generate();
        var exchange = newMessage(HandshakeMessage.CLIENT_KEY_EXCHANGE,
                new TlsWriter(100).vector8(group.encode(ephemeral.getPublic())).toByteArray());
        transcript.add(exchange);
        flight.add(new Outgoing.Message(exchange, 0));
        deriveKeys12(group.agree(ephemeral, serverEphemeral), extendedMasterSecret);
        if (localCertificate != null) {
            var verify = newMessage(HandshakeMessage.CERTIFICATE_VERIFY,
                    signature(requestedSchemes, transcript.bytes(version)));
            transcript.add(verify);
            flight.add(new Outgoing.Message(verify, 0));
        }
        flight.add(new Outgoing.Record(RecordLayer.CHANGE_CIPHER_SPEC, 0, new byte[]{1}));
        var finished = newMessage(HandshakeMessage.FINISHED, finished12("client finished"));
        transcript.add(finished);
        flight.add(new Outgoing.Message(finished, 1));
        connection.setWriteEpoch(1);
        connection.sendFlight(flight, true);
    }

    /// Handles a DTLS 1.3 message after the `ServerHello`.
    private void onMessage13(HandshakeMessage message, long epoch) throws IOException {
        requireEpoch(epoch, 2, message);
        var body = message.body();
        switch (message.type()) {
            case HandshakeMessage.ENCRYPTED_EXTENSIONS -> {
                var reader = new TlsReader(body);
                var extensions = readExtensions(reader);
                var useSrtp = extensions.get(EXT_USE_SRTP);
                if (useSrtp != null) {
                    var chosen = readUseSrtp(useSrtp);
                    if (chosen.size() != 1 || !config.srtpProfiles().contains(chosen.getFirst())) {
                        throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the server chose an unoffered SRTP profile");
                    }
                    profile = chosen.getFirst();
                }
                checkSrtp();
                transcript.add(message);
            }
            case HandshakeMessage.CERTIFICATE_REQUEST -> {
                var reader = new TlsReader(body);
                requestContext = reader.vector8();
                var extensions = readExtensions(reader);
                var schemes = extensions.get(EXT_SIGNATURE_ALGORITHMS);
                if (schemes == null) {
                    throw new DtlsException(DtlsAlert.MISSING_EXTENSION, "CertificateRequest without signature_algorithms");
                }
                requestedSchemes = readSignatureAlgorithms(schemes);
                certificateRequested = true;
                transcript.add(message);
            }
            case HandshakeMessage.CERTIFICATE -> {
                if (peerCertificate != null) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "a second Certificate");
                }
                peerCertificate = acceptCertificate(readCertificate13(body, new byte[0]));
                transcript.add(message);
            }
            case HandshakeMessage.CERTIFICATE_VERIFY -> {
                requireCertificate();
                var reader = new TlsReader(body);
                verifySignature(reader, certificateVerifyContent13(true), advertisedSchemes());
                reader.expectEnd();
                serverVerified = true;
                transcript.add(message);
            }
            case HandshakeMessage.FINISHED -> {
                if (!serverVerified) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "Finished before the server's CertificateVerify");
                }
                verifyFinished13(serverHandshakeSecret, body);
                transcript.add(message);
                deriveApplicationSecrets13();
                sendFinalFlight13();
            }
            default -> throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "unexpected handshake message " + message.type());
        }
    }

    /// Sends the DTLS 1.3 client's final flight and installs the application keys.
    private void sendFinalFlight13() throws IOException {
        var flight = new ArrayList<Outgoing>();
        if (certificateRequested) {
            localCertificate = chooseCertificate(requestedSchemes, List.of(KeyType.EC, KeyType.RSA))
                    .orElseThrow(() -> new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "no certificate fits the server's schemes"));
            var certificate = newMessage(HandshakeMessage.CERTIFICATE, certificate13(requestContext, localCertificate));
            transcript.add(certificate);
            flight.add(new Outgoing.Message(certificate, 2));
            var verify = newMessage(HandshakeMessage.CERTIFICATE_VERIFY,
                    signature(requestedSchemes, certificateVerifyContent13(false)));
            transcript.add(verify);
            flight.add(new Outgoing.Message(verify, 2));
        }
        var finished = newMessage(HandshakeMessage.FINISHED, finished13(clientHandshakeSecret));
        transcript.add(finished);
        flight.add(new Outgoing.Message(finished, 2));
        connection.sendFlight(flight, true);
        var records = connection.records();
        records.installWrite(3, Dtls13RecordCipher.fromSecret(suite, clientApplicationSecret));
        records.installRead(3, Dtls13RecordCipher.fromSecret(suite, serverApplicationSecret));
        connection.setWriteEpoch(3);
        complete = true;
    }

    /// Fails when the server's certificate has not arrived yet.
    private void requireCertificate() throws DtlsException {
        if (peerCertificate == null) {
            throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "the server did not present its certificate");
        }
    }
}
