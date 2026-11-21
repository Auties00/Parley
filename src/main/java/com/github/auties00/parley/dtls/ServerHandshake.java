package com.github.auties00.parley.dtls;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/// The server side of a DTLS handshake: picks DTLS 1.3 when the client offers it and the configuration allows it,
/// DTLS 1.2 otherwise, and always requests the client's certificate, since WebRTC authenticates both sides.
///
/// With [DtlsConfig#cookieExchange()] the server proves the client's address before committing to the handshake:
/// with a `HelloVerifyRequest` in DTLS 1.2, with a `HelloRetryRequest` carrying a cookie in DTLS 1.3. A DTLS 1.3
/// `HelloRetryRequest` also asks for another key share when the client sent none for a group the server supports.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc8422.html RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
/// @spec https://www.rfc-editor.org/rfc/rfc5746.html RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension
final class ServerHandshake extends Handshake {
    /// The scheme codes a DTLS 1.2 server assumes when the client sends no `signature_algorithms`.
    private static final List<Integer> DEFAULT_SCHEMES_12 = List.of(0x0403, 0x0401);

    /// Whether DTLS 1.2 is configured.
    private final boolean support12;

    /// Whether DTLS 1.3 is configured.
    private final boolean support13;

    /// The secret the cookies are derived from.
    private final byte[] cookieSecret = random();

    /// Whether the client's hello was accepted.
    private boolean helloAccepted;

    /// Whether a DTLS 1.3 `HelloRetryRequest` was sent.
    private boolean retried;

    /// The cookie a `HelloRetryRequest` carried, or `null`.
    private byte[] retryCookie;

    /// The suite a `HelloRetryRequest` chose, or `null`.
    private CipherSuite retrySuite;

    /// The group a `HelloRetryRequest` asked for, or `null`.
    private NamedGroup retryGroup;

    /// The signature schemes the client accepts.
    private List<Integer> clientSchemes = List.of();

    /// The DTLS 1.2 group.
    private NamedGroup group;

    /// The DTLS 1.2 ephemeral key pair.
    private java.security.KeyPair ephemeral;

    /// Whether the DTLS 1.2 extended master secret was negotiated.
    private boolean extendedMasterSecret;

    /// Whether the client's `CertificateVerify` verified.
    private boolean clientVerified;

    /// Creates the server side.
    ///
    /// @param connection         the connection
    /// @param remoteFingerprints the client's signalled fingerprints
    /// @param requireSrtp        whether an SRTP profile must be agreed
    ServerHandshake(DtlsConnection connection, List<DtlsFingerprint> remoteFingerprints, boolean requireSrtp) {
        super(connection, remoteFingerprints, requireSrtp);
        this.support12 = config.versions().contains(DtlsVersion.DTLS_1_2);
        this.support13 = config.versions().contains(DtlsVersion.DTLS_1_3);
    }

    @Override
    boolean helloAccepted() {
        return helloAccepted;
    }

    @Override
    DtlsRole role() {
        return DtlsRole.SERVER;
    }

    @Override
    void start() {
    }

    @Override
    void onMessage(HandshakeMessage message, long epoch) throws IOException {
        if (complete) {
            return;
        }
        if (!helloAccepted) {
            requireEpoch(epoch, 0, message);
            if (message.type() != HandshakeMessage.CLIENT_HELLO) {
                throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "expected ClientHello, got message " + message.type());
            }
            onClientHello(message);
            return;
        }
        if (version == DtlsVersion.DTLS_1_3) {
            onMessage13(message, epoch);
        } else {
            onMessage12(message, epoch);
        }
    }

    /// Parses a `ClientHello` and continues in the version it leads to.
    private void onClientHello(HandshakeMessage message) throws IOException {
        var reader = new TlsReader(message.body());
        var legacyVersion = reader.u16();
        var random = reader.bytes(32);
        reader.vector8();
        var legacyCookie = reader.vector8();
        var suites = readU16List(reader.sub16());
        var compression = reader.vector8();
        var extensions = readExtensions(reader);
        var compressionNull = false;
        for (var method : compression) {
            compressionNull |= method == 0;
        }
        if (!compressionNull) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the client offers no null compression");
        }
        var offered13 = false;
        var supportedVersions = extensions.get(EXT_SUPPORTED_VERSIONS);
        if (supportedVersions != null) {
            var versions = new TlsReader(supportedVersions);
            var list = versions.sub8();
            versions.expectEnd();
            offered13 = readU16List(list).contains(DtlsVersion.DTLS_1_3.wireValue());
        }
        if (support13 && offered13) {
            clientHello13(message, random, legacyCookie, suites, extensions);
        } else if (support12 && legacyVersion <= DtlsVersion.DTLS_1_2.wireValue() && !retried) {
            clientHello12(message, random, legacyCookie, suites, extensions);
        } else {
            throw new DtlsException(DtlsAlert.PROTOCOL_VERSION, "no common DTLS version");
        }
    }

    /// Accepts a DTLS 1.2 `ClientHello`, or answers it with a `HelloVerifyRequest`.
    private void clientHello12(HandshakeMessage message, byte[] random, byte[] legacyCookie, List<Integer> suites,
                               Map<Integer, byte[]> extensions) throws IOException {
        var expectedCookie = cookie(random);
        if (config.cookieExchange() && !MessageDigest.isEqual(expectedCookie, legacyCookie)) {
            var body = new TlsWriter(40).u16(0xFEFF).vector8(expectedCookie).toByteArray();
            var request = new HandshakeMessage(HandshakeMessage.HELLO_VERIFY_REQUEST, message.messageSeq(), body);
            connection.sendFlight(List.of(new Outgoing.Record(RecordLayer.HANDSHAKE, 0, request.dtlsEncoding(), 0xFEFF)),
                    false);
            return;
        }
        version = DtlsVersion.DTLS_1_2;
        clientRandom = random;
        sendSeq = message.messageSeq();
        var schemes = extensions.get(EXT_SIGNATURE_ALGORITHMS);
        clientSchemes = schemes == null ? DEFAULT_SCHEMES_12 : readSignatureAlgorithms(schemes);
        for (var candidate : CipherSuite.of(DtlsVersion.DTLS_1_2)) {
            if (suites.contains(candidate.id())) {
                var certificate = chooseCertificate(clientSchemes, List.of(candidate.keyType().orElseThrow()));
                if (certificate.isPresent()) {
                    suite = candidate;
                    localCertificate = certificate.get();
                    break;
                }
            }
        }
        if (suite == null) {
            throw new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "the client offers no usable cipher suite");
        }
        group = chooseGroup(extensions);
        var useSrtp = extensions.get(EXT_USE_SRTP);
        if (useSrtp != null) {
            profile = chooseProfile(readUseSrtp(useSrtp)).orElse(null);
        }
        checkSrtp();
        extendedMasterSecret = extensions.containsKey(EXT_EXTENDED_MASTER_SECRET);
        var renegotiation = extensions.get(EXT_RENEGOTIATION_INFO);
        if (renegotiation != null && !Arrays.equals(renegotiation, new byte[]{0})) {
            throw new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "non-empty renegotiation_info in an initial handshake");
        }
        var secureRenegotiation = renegotiation != null || suites.contains(CipherSuite.EMPTY_RENEGOTIATION_INFO_SCSV);
        serverRandom = random();
        if (support13) {
            System.arraycopy(DOWNGRADE_SENTINEL, 0, serverRandom, 24, DOWNGRADE_SENTINEL.length);
        }
        helloAccepted = true;
        connection.onVersionNegotiated(version, suite);
        transcript.add(message);

        var hello = new TlsWriter(128).u16(DtlsVersion.DTLS_1_2.wireValue()).bytes(serverRandom).vector8(new byte[0])
                .u16(suite.id()).u8(0);
        var list = hello.open16();
        if (profile != null) {
            writeExtension(hello, EXT_USE_SRTP, useSrtp(List.of(profile)));
        }
        if (extendedMasterSecret) {
            writeExtension(hello, EXT_EXTENDED_MASTER_SECRET, new byte[0]);
        }
        if (secureRenegotiation) {
            writeExtension(hello, EXT_RENEGOTIATION_INFO, new byte[]{0});
        }
        if (extensions.containsKey(EXT_EC_POINT_FORMATS)) {
            writeExtension(hello, EXT_EC_POINT_FORMATS, new byte[]{1, 0});
        }
        hello.close(list);
        var flight = new ArrayList<Outgoing>();
        flight.add(add(newMessage(HandshakeMessage.SERVER_HELLO, hello.toByteArray()), 0));
        flight.add(add(newMessage(HandshakeMessage.CERTIFICATE, certificate12(localCertificate)), 0));
        ephemeral = group.generate();
        var params = new TlsWriter(128).u8(3).u16(group.id()).vector8(group.encode(ephemeral.getPublic())).toByteArray();
        var keyExchange = TlsPrf.concat(params, signature(clientSchemes, TlsPrf.concat(clientRandom, serverRandom, params)));
        flight.add(add(newMessage(HandshakeMessage.SERVER_KEY_EXCHANGE, keyExchange), 0));
        var request = new TlsWriter(64).vector8(new byte[]{64, 1}).bytes(signatureAlgorithms(true)).u16(0).toByteArray();
        flight.add(add(newMessage(HandshakeMessage.CERTIFICATE_REQUEST, request), 0));
        flight.add(add(newMessage(HandshakeMessage.SERVER_HELLO_DONE, new byte[0]), 0));
        connection.sendFlight(flight, true);
    }

    /// Handles a DTLS 1.2 message after the server's first flight.
    private void onMessage12(HandshakeMessage message, long epoch) throws IOException {
        var body = message.body();
        switch (message.type()) {
            case HandshakeMessage.CERTIFICATE -> {
                requireEpoch(epoch, 0, message);
                if (peerCertificate != null) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "a second Certificate");
                }
                peerCertificate = acceptCertificate(readCertificate12(body));
                transcript.add(message);
            }
            case HandshakeMessage.CLIENT_KEY_EXCHANGE -> {
                requireEpoch(epoch, 0, message);
                requireCertificate();
                if (masterSecret != null) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "a second ClientKeyExchange");
                }
                var reader = new TlsReader(body);
                PublicKey clientKey = group.decode(reader.vector8());
                reader.expectEnd();
                transcript.add(message);
                deriveKeys12(group.agree(ephemeral, clientKey), extendedMasterSecret);
            }
            case HandshakeMessage.CERTIFICATE_VERIFY -> {
                requireEpoch(epoch, 0, message);
                if (masterSecret == null) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "CertificateVerify before the key exchange");
                }
                var reader = new TlsReader(body);
                verifySignature(reader, transcript.bytes(version), advertisedSchemes());
                reader.expectEnd();
                clientVerified = true;
                transcript.add(message);
            }
            case HandshakeMessage.FINISHED -> {
                requireEpoch(epoch, 1, message);
                if (!clientVerified) {
                    throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "Finished before the client's CertificateVerify");
                }
                verifyFinished12("client finished", body);
                transcript.add(message);
                var finished = add(newMessage(HandshakeMessage.FINISHED, finished12("server finished")), 1);
                connection.setWriteEpoch(1);
                connection.sendFlight(List.of(new Outgoing.Record(RecordLayer.CHANGE_CIPHER_SPEC, 0, new byte[]{1}), finished),
                        false);
                complete = true;
            }
            default -> throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "unexpected handshake message " + message.type());
        }
    }

    /// Accepts a DTLS 1.3 `ClientHello`, or answers it with a `HelloRetryRequest`.
    private void clientHello13(HandshakeMessage message, byte[] random, byte[] legacyCookie, List<Integer> suites,
                               Map<Integer, byte[]> extensions) throws IOException {
        if (legacyCookie.length != 0) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "legacy cookie in a DTLS 1.3 ClientHello");
        }
        version = DtlsVersion.DTLS_1_3;
        CipherSuite chosen = null;
        for (var candidate : CipherSuite.of(DtlsVersion.DTLS_1_3)) {
            if (suites.contains(candidate.id())) {
                chosen = candidate;
                break;
            }
        }
        if (chosen == null || (retrySuite != null && !suites.contains(retrySuite.id()))) {
            throw new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "the client offers no DTLS 1.3 cipher suite");
        }
        if (retrySuite != null) {
            chosen = retrySuite;
        }
        var schemes = extensions.get(EXT_SIGNATURE_ALGORITHMS);
        if (schemes == null) {
            throw new DtlsException(DtlsAlert.MISSING_EXTENSION, "ClientHello without signature_algorithms");
        }
        clientSchemes = readSignatureAlgorithms(schemes);
        var shares = readKeyShares(extensions.get(EXT_KEY_SHARE));
        NamedGroup selected = null;
        for (var candidate : NamedGroup.values()) {
            if (shares.containsKey(candidate)) {
                selected = candidate;
                break;
            }
        }
        var cookieValid = false;
        if (retried) {
            var cookie = extensions.get(EXT_COOKIE);
            if (retryCookie != null) {
                if (cookie == null) {
                    throw new DtlsException(DtlsAlert.MISSING_EXTENSION, "the second ClientHello has no cookie");
                }
                var reader = new TlsReader(cookie);
                cookieValid = MessageDigest.isEqual(retryCookie, reader.vector16());
                if (!cookieValid) {
                    throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "invalid cookie");
                }
            }
            if (retryGroup != null && selected != retryGroup) {
                throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "the second ClientHello lacks the requested key share");
            }
        }
        var needGroup = selected == null;
        var needCookie = config.cookieExchange() && !retried;
        if (needGroup || needCookie) {
            if (retried) {
                throw new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "the second ClientHello is still unusable");
            }
            var group = needGroup ? chooseGroup(extensions) : null;
            sendHelloRetryRequest(message, chosen, group, needCookie);
            return;
        }
        suite = chosen;
        clientRandom = random;
        sendSeq = message.messageSeq();
        var useSrtp = extensions.get(EXT_USE_SRTP);
        if (useSrtp != null) {
            profile = chooseProfile(readUseSrtp(useSrtp)).orElse(null);
        }
        checkSrtp();
        localCertificate = chooseCertificate(clientSchemes, List.of(KeyType.EC, KeyType.RSA))
                .orElseThrow(() -> new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "no certificate fits the client's schemes"));
        helloAccepted = true;
        connection.onVersionNegotiated(version, suite);
        transcript.add(message);

        serverRandom = random();
        var keyPair = selected.generate();
        var hello = new TlsWriter(128).u16(DtlsVersion.DTLS_1_2.wireValue()).bytes(serverRandom).vector8(new byte[0])
                .u16(suite.id()).u8(0);
        var list = hello.open16();
        writeExtension(hello, EXT_SUPPORTED_VERSIONS, new TlsWriter().u16(DtlsVersion.DTLS_1_3.wireValue()).toByteArray());
        writeExtension(hello, EXT_KEY_SHARE,
                new TlsWriter().u16(selected.id()).vector16(selected.encode(keyPair.getPublic())).toByteArray());
        hello.close(list);
        var flight = new ArrayList<Outgoing>();
        flight.add(add(newMessage(HandshakeMessage.SERVER_HELLO, hello.toByteArray()), 0));
        deriveHandshakeSecrets13(selected.agree(keyPair, shares.get(selected)));

        var encrypted = new TlsWriter(32);
        var encryptedList = encrypted.open16();
        if (profile != null) {
            writeExtension(encrypted, EXT_USE_SRTP, useSrtp(List.of(profile)));
        }
        encrypted.close(encryptedList);
        flight.add(add(newMessage(HandshakeMessage.ENCRYPTED_EXTENSIONS, encrypted.toByteArray()), 2));
        var request = new TlsWriter(64).vector8(new byte[0]);
        var requestList = request.open16();
        writeExtension(request, EXT_SIGNATURE_ALGORITHMS, signatureAlgorithms(false));
        request.close(requestList);
        flight.add(add(newMessage(HandshakeMessage.CERTIFICATE_REQUEST, request.toByteArray()), 2));
        flight.add(add(newMessage(HandshakeMessage.CERTIFICATE, certificate13(new byte[0], localCertificate)), 2));
        flight.add(add(newMessage(HandshakeMessage.CERTIFICATE_VERIFY,
                signature(clientSchemes, certificateVerifyContent13(true))), 2));
        flight.add(add(newMessage(HandshakeMessage.FINISHED, finished13(serverHandshakeSecret)), 2));
        deriveApplicationSecrets13();
        connection.records().installWrite(3, Dtls13RecordCipher.fromSecret(suite, serverApplicationSecret));
        connection.setWriteEpoch(2);
        connection.sendFlight(flight, true);
    }

    /// Sends a `HelloRetryRequest` asking for a group, a cookie, or both.
    private void sendHelloRetryRequest(HandshakeMessage clientHello, CipherSuite chosen, NamedGroup group,
                                       boolean withCookie) throws IOException {
        retried = true;
        retrySuite = chosen;
        retryGroup = group;
        retryCookie = withCookie ? random() : null;
        var body = new TlsWriter(128).u16(DtlsVersion.DTLS_1_2.wireValue()).bytes(HELLO_RETRY_REQUEST_RANDOM)
                .vector8(new byte[0]).u16(chosen.id()).u8(0);
        var list = body.open16();
        writeExtension(body, EXT_SUPPORTED_VERSIONS, new TlsWriter().u16(DtlsVersion.DTLS_1_3.wireValue()).toByteArray());
        if (group != null) {
            writeExtension(body, EXT_KEY_SHARE, new TlsWriter().u16(group.id()).toByteArray());
        }
        if (retryCookie != null) {
            writeExtension(body, EXT_COOKIE, new TlsWriter().vector16(retryCookie).toByteArray());
        }
        body.close(list);
        transcript.add(clientHello);
        transcript.replaceWithMessageHash(chosen.hash());
        var retry = new HandshakeMessage(HandshakeMessage.SERVER_HELLO, clientHello.messageSeq(), body.toByteArray());
        transcript.add(retry);
        connection.sendFlight(List.of(new Outgoing.Message(retry, 0)), false);
    }

    /// Handles a DTLS 1.3 message of the client's final flight.
    private void onMessage13(HandshakeMessage message, long epoch) throws IOException {
        requireEpoch(epoch, 2, message);
        var body = message.body();
        switch (message.type()) {
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
                verifySignature(reader, certificateVerifyContent13(false), advertisedSchemes());
                reader.expectEnd();
                clientVerified = true;
                transcript.add(message);
            }
            case HandshakeMessage.FINISHED -> {
                if (!clientVerified) {
                    throw new DtlsException(DtlsAlert.CERTIFICATE_REQUIRED, "the client did not authenticate");
                }
                verifyFinished13(clientHandshakeSecret, body);
                transcript.add(message);
                connection.records().installRead(3, Dtls13RecordCipher.fromSecret(suite, clientApplicationSecret));
                connection.setWriteEpoch(3);
                complete = true;
            }
            default -> throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "unexpected handshake message " + message.type());
        }
    }

    /// {@return the key shares of a `key_share` extension, by supported group}
    private static Map<NamedGroup, PublicKey> readKeyShares(byte[] data) throws DtlsException {
        var shares = new LinkedHashMap<NamedGroup, PublicKey>();
        if (data == null) {
            return shares;
        }
        var reader = new TlsReader(data);
        var list = reader.sub16();
        reader.expectEnd();
        while (list.hasRemaining()) {
            var id = list.u16();
            var key = list.vector16();
            var group = NamedGroup.ofId(id);
            if (group.isPresent()) {
                if (shares.containsKey(group.get())) {
                    throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "key share repeated");
                }
                shares.put(group.get(), group.get().decode(key));
            }
        }
        return shares;
    }

    /// {@return this side's preferred group among those the client supports}
    private static NamedGroup chooseGroup(Map<Integer, byte[]> extensions) throws DtlsException {
        var data = extensions.get(EXT_SUPPORTED_GROUPS);
        if (data == null) {
            return NamedGroup.SECP256R1;
        }
        var reader = new TlsReader(data);
        var offered = readU16List(reader.sub16());
        reader.expectEnd();
        for (var group : NamedGroup.values()) {
            if (offered.contains(group.id())) {
                return group;
            }
        }
        throw new DtlsException(DtlsAlert.HANDSHAKE_FAILURE, "no common group");
    }

    /// {@return the DTLS 1.2 cookie of a client random}
    private byte[] cookie(byte[] random) {
        return HashAlgorithm.SHA256.hmac(cookieSecret, random);
    }

    /// {@return a flight element for a message, after adding it to the transcript}
    private Outgoing add(HandshakeMessage message, long epoch) {
        transcript.add(message);
        return new Outgoing.Message(message, epoch);
    }

    /// Fails when the client's certificate has not arrived yet.
    private void requireCertificate() throws DtlsException {
        if (peerCertificate == null) {
            throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE, "the client did not present its certificate");
        }
    }
}
