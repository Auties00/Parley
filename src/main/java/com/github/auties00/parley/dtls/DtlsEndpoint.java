package com.github.auties00.parley.dtls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import javax.crypto.KeyAgreement;

/// Runs a DTLS 1.2 handshake that negotiates SRTP keys with the `use_srtp` extension, as either the client or the
/// server of the association, and exports the SRTP master keys of both directions.
///
/// The endpoint implements the profile WebRTC media uses and nothing more:
///
/// - the cipher suites `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and, as a client,
///   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, with the P-256 group;
/// - mutual authentication with self-signed certificates, each checked only against the `a=fingerprint` the peer
///   advertised in its session description;
/// - the extended master secret whenever the peer supports it;
/// - handshake message fragmentation and reassembly, retransmission of the last flight with a doubling timer, and a
///   `HelloVerifyRequest` cookie exchange when a server asks for one (this endpoint, as a server, does not ask);
/// - the `EXTRACTOR-dtls_srtp` exporter that yields the SRTP master keys.
///
/// Session resumption, renegotiation and application data are not supported: the association exists only to key
/// SRTP. The endpoint owns no socket; it talks to the peer through a [DtlsDatagramIo]:
///
/// {@snippet lang = java :
/// var certificate = DtlsCertificate.generate();
/// // advertise certificate.fingerprint() in a=fingerprint, read the peer's from its description
/// var endpoint = new DtlsEndpoint(DtlsEndpoint.Role.CLIENT, certificate, peerFingerprint,
///         List.of(SrtpProfile.values()), io);
/// DtlsSrtpKeys keys = endpoint.handshake(Duration.ofSeconds(10));
/// }
///
/// # Lifecycle
///
/// An endpoint runs one handshake. After [#handshake(Duration)] returns, the owner keeps feeding the DTLS datagrams
/// it receives to [#handleAfterHandshake(byte\[\])], which sends this endpoint's last flight again when the peer
/// shows that it missed it and reports a closure alert. [#close()] sends `close_notify`.
///
/// # Threading
///
/// [#handshake(Duration)] blocks the calling thread and must be called once. [#handleAfterHandshake(byte\[\])],
/// [#close()] and [#role()] may be called from any thread, concurrently with each other.
///
/// @implNote This implementation exists because the JDK's DTLS engine cannot negotiate `use_srtp`: SunJSSE
///           registers the extension id with no producer or consumer, so a peer that requires it fails the
///           handshake.
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc5289.html RFC 5289: TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
/// @spec https://www.rfc-editor.org/rfc/rfc8422.html RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
/// @spec https://www.rfc-editor.org/rfc/rfc7627.html RFC 7627: Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
/// @spec https://www.rfc-editor.org/rfc/rfc5705.html RFC 5705: Keying Material Exporters for Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc5746.html RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
public final class DtlsEndpoint {
    /// The DTLS 1.2 protocol version on the wire.
    private static final int VERSION = 0xFEFD;

    /// The `change_cipher_spec` content type.
    private static final int CHANGE_CIPHER_SPEC = 20;

    /// The `alert` content type.
    private static final int ALERT = 21;

    /// The `handshake` content type.
    private static final int HANDSHAKE = 22;

    /// The `client_hello` handshake type.
    private static final int CLIENT_HELLO = 1;

    /// The `server_hello` handshake type.
    private static final int SERVER_HELLO = 2;

    /// The `hello_verify_request` handshake type.
    private static final int HELLO_VERIFY_REQUEST = 3;

    /// The `certificate` handshake type.
    private static final int CERTIFICATE = 11;

    /// The `server_key_exchange` handshake type.
    private static final int SERVER_KEY_EXCHANGE = 12;

    /// The `certificate_request` handshake type.
    private static final int CERTIFICATE_REQUEST = 13;

    /// The `server_hello_done` handshake type.
    private static final int SERVER_HELLO_DONE = 14;

    /// The `certificate_verify` handshake type.
    private static final int CERTIFICATE_VERIFY = 15;

    /// The `client_key_exchange` handshake type.
    private static final int CLIENT_KEY_EXCHANGE = 16;

    /// The `finished` handshake type.
    private static final int FINISHED = 20;

    /// The `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` cipher suite.
    private static final int ECDHE_ECDSA_AES_128_GCM = 0xC02B;

    /// The `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` cipher suite.
    private static final int ECDHE_RSA_AES_128_GCM = 0xC02F;

    /// The `secp256r1` named group.
    private static final int SECP256R1 = 23;

    /// The `ecdsa_secp256r1_sha256` signature scheme.
    private static final int ECDSA_SHA256 = 0x0403;

    /// The signature schemes this endpoint can verify, in preference order.
    private static final int[] SIGNATURE_SCHEMES = {0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501, 0x0201, 0x0203};

    /// The `supported_groups` extension type.
    private static final int EXT_SUPPORTED_GROUPS = 10;

    /// The `ec_point_formats` extension type.
    private static final int EXT_EC_POINT_FORMATS = 11;

    /// The `signature_algorithms` extension type.
    private static final int EXT_SIGNATURE_ALGORITHMS = 13;

    /// The `use_srtp` extension type.
    private static final int EXT_USE_SRTP = 14;

    /// The `extended_master_secret` extension type.
    private static final int EXT_EXTENDED_MASTER_SECRET = 23;

    /// The `renegotiation_info` extension type.
    private static final int EXT_RENEGOTIATION_INFO = 0xFF01;

    /// The size of a record header.
    private static final int RECORD_HEADER_LENGTH = 13;

    /// The size of a handshake message header.
    private static final int HANDSHAKE_HEADER_LENGTH = 12;

    /// The largest datagram this endpoint sends.
    ///
    /// @implNote This implementation uses 1200 bytes, the size WebRTC stacks assume fits any path without
    ///           IP fragmentation.
    private static final int MAX_DATAGRAM = 1200;

    /// The largest handshake fragment body, so a fragment with its two headers and the record
    /// protection fits [#MAX_DATAGRAM].
    private static final int MAX_FRAGMENT = MAX_DATAGRAM - RECORD_HEADER_LENGTH - HANDSHAKE_HEADER_LENGTH - 32;

    /// The initial retransmission timeout.
    private static final long INITIAL_RTO_NANOS = TimeUnit.MILLISECONDS.toNanos(400);

    /// The largest retransmission timeout.
    private static final long MAX_RTO_NANOS = TimeUnit.SECONDS.toNanos(3);

    /// The source of randoms.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// The role of this endpoint.
    private final Role role;

    /// The certificate this endpoint presents.
    private final DtlsCertificate certificate;

    /// The `a=fingerprint` value the peer advertised.
    private final String remoteFingerprint;

    /// The datagram channel to the peer.
    private final DtlsDatagramIo io;

    /// The SRTP profiles this endpoint accepts, in preference order.
    private final List<SrtpProfile> profiles;

    /// The lock that serializes sending and state changes after the handshake.
    private final Object lock = new Object();

    /// The handshake messages that enter the transcript hash.
    private final ByteArrayOutputStream transcript = new ByteArrayOutputStream();

    /// The partially received handshake messages, keyed by message sequence number.
    private final Map<Integer, Reassembly> reassembly = new HashMap<>();

    /// The next record sequence number of each write epoch.
    private final long[] writeSequence = new long[2];

    /// The client random.
    private byte[] clientRandom;

    /// The server random.
    private byte[] serverRandom;

    /// The encoded `ClientHello` this client sent last, added to the transcript once the
    /// `ServerHello` arrives.
    private byte[] pendingClientHello;

    /// The next outgoing handshake message sequence number.
    private int sendMessageSeq;

    /// The next expected incoming handshake message sequence number, or `-1` before the first.
    private int receiveMessageSeq = -1;

    /// The epoch of outgoing records.
    private int writeEpoch;

    /// The epoch of incoming records.
    private int readEpoch;

    /// The record protection of outgoing epoch 1 records.
    private DtlsRecordCipher writeCipher;

    /// The record protection of incoming epoch 1 records once the peer's change cipher spec arrived.
    private DtlsRecordCipher readCipher;

    /// The record protection of incoming epoch 1 records before the peer's change cipher spec.
    private DtlsRecordCipher pendingReadCipher;

    /// The ephemeral ECDH key pair.
    private KeyPair ephemeral;

    /// The negotiated cipher suite.
    private int cipherSuite;

    /// The negotiated SRTP profile.
    private SrtpProfile profile;

    /// Whether the extended master secret was negotiated.
    private boolean extendedMasterSecret;

    /// Whether the peer sent `renegotiation_info`, which a server echoes.
    private boolean peerRenegotiationInfo;

    /// Whether the peer sent `ec_point_formats`, which a server echoes.
    private boolean peerPointFormats;

    /// Whether the server asked for this client's certificate.
    private boolean certificateRequested;

    /// The peer's certificate.
    private X509Certificate peerCertificate;

    /// The peer's ephemeral ECDH public key.
    private PublicKey peerEphemeral;

    /// The master secret.
    private byte[] masterSecret;

    /// The last flight this endpoint sent, for retransmission.
    private List<Outgoing> lastFlight = List.of();

    /// Whether the handshake completed.
    private boolean established;

    /// Creates an endpoint; it sends nothing until [#handshake(Duration)] is called.
    ///
    /// @param role              the DTLS role of this endpoint
    /// @param certificate       the certificate to present, whose [DtlsCertificate#fingerprint()] this side
    ///                          advertised
    /// @param remoteFingerprint the peer's `a=fingerprint` value, `<hash> <hex>`, which its certificate must match
    /// @param profiles          the SRTP profiles to accept, in preference order; as the server, the first one the
    ///                          client offers is chosen
    /// @param io                the datagram channel to the peer
    /// @throws IllegalArgumentException if `profiles` is empty
    public DtlsEndpoint(Role role, DtlsCertificate certificate, String remoteFingerprint,
                        List<SrtpProfile> profiles, DtlsDatagramIo io) {
        this.role = Objects.requireNonNull(role, "role cannot be null");
        this.certificate = Objects.requireNonNull(certificate, "certificate cannot be null");
        this.remoteFingerprint = Objects.requireNonNull(remoteFingerprint, "remoteFingerprint cannot be null");
        this.profiles = List.copyOf(profiles);
        this.io = Objects.requireNonNull(io, "io cannot be null");
        if (this.profiles.isEmpty()) {
            throw new IllegalArgumentException("profiles cannot be empty");
        }
    }

    /// Runs the handshake and returns the exported SRTP keys.
    ///
    /// Blocks until the handshake completes. This endpoint's last flight is sent again whenever the peer is silent for
    /// the current retransmission timeout (400 ms, doubling up to 3 s) or shows that it missed it. When the handshake
    /// fails, a `handshake_failure` alert is sent to the peer, best effort, before the exception is thrown.
    ///
    /// @param timeout the longest time the whole handshake may take
    /// @return the SRTP keys of both directions, already assigned to this endpoint's role
    /// @throws DtlsException        if the handshake fails: the peer's certificate does not match its fingerprint,
    ///                              the peer offers or chooses no common cipher suite or SRTP profile, a message does
    ///                              not verify, the peer sends a fatal alert, [DtlsDatagramIo] fails, or the timeout
    ///                              elapses
    /// @throws InterruptedException if the calling thread is interrupted while waiting for a datagram
    public DtlsSrtpKeys handshake(Duration timeout) throws DtlsException, InterruptedException {
        var deadline = System.nanoTime() + timeout.toNanos();
        try {
            synchronized (lock) {
                if (role == Role.CLIENT) {
                    sendClientHello(new byte[0]);
                }
            }
            var rto = INITIAL_RTO_NANOS;
            var nextRetransmit = System.nanoTime() + rto;
            while (true) {
                synchronized (lock) {
                    if (established) {
                        return exportKeys();
                    }
                }
                var now = System.nanoTime();
                if (now - deadline >= 0) {
                    throw new DtlsException("DTLS handshake did not complete within " + timeout.toMillis() + " ms");
                }
                var datagram = io.receive(Math.max(1, Math.min(deadline - now, nextRetransmit - now)));
                if (datagram == null) {
                    if (System.nanoTime() - nextRetransmit >= 0) {
                        synchronized (lock) {
                            transmit(lastFlight);
                        }
                        rto = Math.min(rto * 2, MAX_RTO_NANOS);
                        nextRetransmit = System.nanoTime() + rto;
                    }
                    continue;
                }
                boolean progressed;
                synchronized (lock) {
                    progressed = processDatagram(datagram);
                }
                if (progressed) {
                    rto = INITIAL_RTO_NANOS;
                    nextRetransmit = System.nanoTime() + rto;
                }
            }
        } catch (DtlsException exception) {
            sendAlertQuietly(40);
            throw exception;
        } catch (IOException exception) {
            throw new DtlsException("DTLS transport failed", exception);
        }
    }

    /// Handles a DTLS datagram received after the handshake completed.
    ///
    /// A handshake record means that the peer missed this endpoint's last flight, which is sent again; an alert
    /// means that the peer closed the association or failed; anything else is ignored. A datagram that arrives before
    /// the handshake completed is never answered.
    ///
    /// @param datagram the datagram
    /// @return what the datagram meant
    public AfterHandshake handleAfterHandshake(byte[] datagram) {
        synchronized (lock) {
            var buffer = ByteBuffer.wrap(datagram);
            var retransmit = false;
            while (buffer.remaining() >= RECORD_HEADER_LENGTH) {
                var type = buffer.get() & 0xFF;
                buffer.getShort();
                buffer.getShort();
                buffer.position(buffer.position() + 6);
                var length = buffer.getShort() & 0xFFFF;
                if (length > buffer.remaining()) {
                    break;
                }
                buffer.position(buffer.position() + length);
                if (type == ALERT) {
                    return AfterHandshake.CLOSED;
                }
                if (type == HANDSHAKE) {
                    retransmit = true;
                }
            }
            if (retransmit && established) {
                try {
                    transmit(lastFlight);
                } catch (IOException exception) {
                    return AfterHandshake.IGNORED;
                }
                return AfterHandshake.RETRANSMITTED;
            }
            return AfterHandshake.IGNORED;
        }
    }

    /// Sends a `close_notify` alert to the peer, best effort: a send failure is ignored.
    ///
    /// The endpoint keeps no other resource, so it needs no closing; calling this method more than once sends the
    /// alert again.
    public void close() {
        sendAlertQuietly(0);
    }

    /// {@return the role of this endpoint}
    public Role role() {
        return role;
    }

    /// Processes one received datagram during the handshake; the caller holds [#lock].
    ///
    /// @param datagram the datagram
    /// @return `true` if it advanced the handshake
    /// @throws IOException if the handshake fails or a send fails
    private boolean processDatagram(byte[] datagram) throws IOException {
        var buffer = ByteBuffer.wrap(datagram);
        var progressed = false;
        var retransmissionSeen = false;
        while (buffer.remaining() >= RECORD_HEADER_LENGTH) {
            var type = buffer.get() & 0xFF;
            var version = buffer.getShort() & 0xFFFF;
            var epoch = buffer.getShort() & 0xFFFF;
            var sequence = ((long) (buffer.getShort() & 0xFFFF) << 32) | (buffer.getInt() & 0xFFFFFFFFL);
            var length = buffer.getShort() & 0xFFFF;
            if (length > buffer.remaining()) {
                break;
            }
            var fragment = new byte[length];
            buffer.get(fragment);
            if (epoch != readEpoch) {
                if (epoch < readEpoch && type == HANDSHAKE) {
                    retransmissionSeen = true;
                }
                continue;
            }
            byte[] plaintext;
            if (epoch == 0) {
                plaintext = fragment;
            } else {
                try {
                    plaintext = readCipher.decrypt(((long) epoch << 48) | sequence, type, version, fragment);
                } catch (DtlsException exception) {
                    continue;
                }
            }
            switch (type) {
                case CHANGE_CIPHER_SPEC -> {
                    if (pendingReadCipher != null && readEpoch == 0) {
                        readCipher = pendingReadCipher;
                        readEpoch = 1;
                        progressed = true;
                    }
                }
                case ALERT -> {
                    if (plaintext.length >= 2 && (plaintext[0] == 2 || plaintext[1] == 0)) {
                        throw new DtlsException("peer sent DTLS alert " + (plaintext[1] & 0xFF));
                    }
                }
                case HANDSHAKE -> {
                    var result = processHandshakeRecord(plaintext);
                    progressed |= result > 0;
                    retransmissionSeen |= result < 0;
                }
                default -> {
                }
            }
        }
        if (retransmissionSeen && !progressed) {
            transmit(lastFlight);
        }
        return progressed;
    }

    /// Processes the handshake fragments of one record; the caller holds [#lock].
    ///
    /// @param plaintext the record plaintext
    /// @return a positive number if a message was handled, a negative one if only already-handled
    ///         messages were seen, zero otherwise
    /// @throws IOException if a message is invalid or a send fails
    private int processHandshakeRecord(byte[] plaintext) throws IOException {
        var buffer = ByteBuffer.wrap(plaintext);
        var handled = 0;
        var old = false;
        while (buffer.remaining() >= HANDSHAKE_HEADER_LENGTH) {
            var type = buffer.get() & 0xFF;
            var length = readUint24(buffer);
            var messageSeq = buffer.getShort() & 0xFFFF;
            var fragmentOffset = readUint24(buffer);
            var fragmentLength = readUint24(buffer);
            if (fragmentLength > buffer.remaining() || fragmentOffset + fragmentLength > length) {
                throw new DtlsException("malformed handshake fragment");
            }
            var body = new byte[fragmentLength];
            buffer.get(body);
            if (receiveMessageSeq < 0 && (type == CLIENT_HELLO || type == SERVER_HELLO || type == HELLO_VERIFY_REQUEST)) {
                receiveMessageSeq = messageSeq;
            }
            if (receiveMessageSeq < 0) {
                continue;
            }
            if (messageSeq < receiveMessageSeq) {
                old = true;
                continue;
            }
            var entry = reassembly.computeIfAbsent(messageSeq, _ -> new Reassembly(type, length));
            entry.add(fragmentOffset, body);
            while (true) {
                var next = reassembly.get(receiveMessageSeq);
                if (next == null || !next.complete()) {
                    break;
                }
                reassembly.remove(receiveMessageSeq);
                var full = messageBytes(next.type, receiveMessageSeq, next.body);
                receiveMessageSeq++;
                handleMessage(next.type, next.body, full);
                handled++;
            }
        }
        return handled > 0 ? 1 : old ? -1 : 0;
    }

    /// Handles one complete handshake message; the caller holds [#lock].
    ///
    /// @param type the handshake type
    /// @param body the message body
    /// @param full the message with its unfragmented header, as the transcript hashes it
    /// @throws IOException if the message is unexpected or invalid, or a send fails
    private void handleMessage(int type, byte[] body, byte[] full) throws IOException {
        if (role == Role.CLIENT) {
            handleAsClient(type, body, full);
        } else {
            handleAsServer(type, body, full);
        }
    }

    /// Handles a handshake message as the client.
    ///
    /// @param type the handshake type
    /// @param body the message body
    /// @param full the message as hashed
    /// @throws IOException if the message is unexpected or invalid, or a send fails
    private void handleAsClient(int type, byte[] body, byte[] full) throws IOException {
        var buffer = ByteBuffer.wrap(body);
        switch (type) {
            case HELLO_VERIFY_REQUEST -> {
                buffer.getShort();
                var cookie = readVector8(buffer);
                sendClientHello(cookie);
            }
            case SERVER_HELLO -> {
                transcript.writeBytes(pendingClientHello);
                transcript.writeBytes(full);
                buffer.getShort();
                serverRandom = readBytes(buffer, 32);
                readVector8(buffer);
                cipherSuite = buffer.getShort() & 0xFFFF;
                buffer.get();
                if (cipherSuite != ECDHE_ECDSA_AES_128_GCM && cipherSuite != ECDHE_RSA_AES_128_GCM) {
                    throw new DtlsException("server chose an unoffered cipher suite 0x" + Integer.toHexString(cipherSuite));
                }
                if (buffer.remaining() >= 2) {
                    var extensions = ByteBuffer.wrap(readVector16(buffer));
                    while (extensions.remaining() >= 4) {
                        var extensionType = extensions.getShort() & 0xFFFF;
                        var data = ByteBuffer.wrap(readVector16(extensions));
                        switch (extensionType) {
                            case EXT_USE_SRTP -> {
                                var ids = ByteBuffer.wrap(readVector16(data));
                                if (ids.remaining() >= 2) {
                                    var id = ids.getShort() & 0xFFFF;
                                    profile = SrtpProfile.ofId(id).filter(profiles::contains)
                                            .orElseThrow(() -> new DtlsException("server chose an unoffered SRTP profile"));
                                }
                            }
                            case EXT_EXTENDED_MASTER_SECRET -> extendedMasterSecret = true;
                            default -> {
                            }
                        }
                    }
                }
                if (profile == null) {
                    throw new DtlsException("server did not negotiate use_srtp");
                }
            }
            case CERTIFICATE -> {
                peerCertificate = readCertificate(buffer);
                transcript.writeBytes(full);
            }
            case SERVER_KEY_EXCHANGE -> {
                requireCertificate();
                var start = buffer.position();
                if ((buffer.get() & 0xFF) != 3 || (buffer.getShort() & 0xFFFF) != SECP256R1) {
                    throw new DtlsException("server key exchange uses an unsupported group");
                }
                var point = readVector8(buffer);
                var params = Arrays.copyOfRange(body, start, buffer.position());
                var scheme = buffer.getShort() & 0xFFFF;
                var signature = readVector16(buffer);
                var signed = TlsPrf.concat(TlsPrf.concat(clientRandom, serverRandom), params);
                if (!verify(peerCertificate.getPublicKey(), scheme, signed, signature)) {
                    throw new DtlsException("server key exchange signature does not verify");
                }
                peerEphemeral = decodePoint(point);
                transcript.writeBytes(full);
            }
            case CERTIFICATE_REQUEST -> {
                certificateRequested = true;
                transcript.writeBytes(full);
            }
            case SERVER_HELLO_DONE -> {
                transcript.writeBytes(full);
                sendClientFinalFlight();
            }
            case FINISHED -> {
                var expected = TlsPrf.compute(masterSecret, "server finished", transcriptHash(), 12);
                if (!MessageDigest.isEqual(expected, body)) {
                    throw new DtlsException("server Finished does not verify");
                }
                transcript.writeBytes(full);
                established = true;
            }
            default -> throw new DtlsException("unexpected handshake message " + type);
        }
    }

    /// Handles a handshake message as the server.
    ///
    /// @param type the handshake type
    /// @param body the message body
    /// @param full the message as hashed
    /// @throws IOException if the message is unexpected or invalid, or a send fails
    private void handleAsServer(int type, byte[] body, byte[] full) throws IOException {
        var buffer = ByteBuffer.wrap(body);
        switch (type) {
            case CLIENT_HELLO -> {
                if (clientRandom != null) {
                    return;
                }
                transcript.writeBytes(full);
                buffer.getShort();
                clientRandom = readBytes(buffer, 32);
                readVector8(buffer);
                readVector8(buffer);
                var suites = ByteBuffer.wrap(readVector16(buffer));
                var ecdsaOffered = false;
                while (suites.remaining() >= 2) {
                    var suite = suites.getShort() & 0xFFFF;
                    ecdsaOffered |= suite == ECDHE_ECDSA_AES_128_GCM;
                    peerRenegotiationInfo |= suite == 0x00FF;
                }
                readVector8(buffer);
                if (!ecdsaOffered) {
                    throw new DtlsException("client offers no supported cipher suite");
                }
                cipherSuite = ECDHE_ECDSA_AES_128_GCM;
                var offeredProfiles = new ArrayList<SrtpProfile>();
                if (buffer.remaining() >= 2) {
                    var extensions = ByteBuffer.wrap(readVector16(buffer));
                    while (extensions.remaining() >= 4) {
                        var extensionType = extensions.getShort() & 0xFFFF;
                        var data = ByteBuffer.wrap(readVector16(extensions));
                        switch (extensionType) {
                            case EXT_USE_SRTP -> {
                                var ids = ByteBuffer.wrap(readVector16(data));
                                while (ids.remaining() >= 2) {
                                    SrtpProfile.ofId(ids.getShort() & 0xFFFF).ifPresent(offeredProfiles::add);
                                }
                            }
                            case EXT_EXTENDED_MASTER_SECRET -> extendedMasterSecret = true;
                            case EXT_RENEGOTIATION_INFO -> peerRenegotiationInfo = true;
                            case EXT_EC_POINT_FORMATS -> peerPointFormats = true;
                            default -> {
                            }
                        }
                    }
                }
                profile = profiles.stream()
                        .filter(offeredProfiles::contains)
                        .findFirst()
                        .orElseThrow(() -> new DtlsException("client offers no supported SRTP profile"));
                sendServerFlight();
            }
            case CERTIFICATE -> {
                peerCertificate = readCertificate(buffer);
                transcript.writeBytes(full);
            }
            case CLIENT_KEY_EXCHANGE -> {
                requireCertificate();
                peerEphemeral = decodePoint(readVector8(buffer));
                transcript.writeBytes(full);
                deriveKeys();
            }
            case CERTIFICATE_VERIFY -> {
                var scheme = buffer.getShort() & 0xFFFF;
                var signature = readVector16(buffer);
                if (!verify(peerCertificate.getPublicKey(), scheme, transcript.toByteArray(), signature)) {
                    throw new DtlsException("client certificate verify does not verify");
                }
                transcript.writeBytes(full);
            }
            case FINISHED -> {
                if (masterSecret == null || readEpoch != 1) {
                    throw new DtlsException("client Finished before its keys");
                }
                var expected = TlsPrf.compute(masterSecret, "client finished", transcriptHash(), 12);
                if (!MessageDigest.isEqual(expected, body)) {
                    throw new DtlsException("client Finished does not verify");
                }
                transcript.writeBytes(full);
                var flight = new ArrayList<Outgoing>();
                flight.add(new Outgoing(CHANGE_CIPHER_SPEC, 0, new byte[]{1}));
                writeEpoch = 1;
                var verifyData = TlsPrf.compute(masterSecret, "server finished", transcriptHash(), 12);
                flight.add(handshakeMessage(FINISHED, verifyData, 1));
                sendFlight(flight);
                established = true;
            }
            default -> throw new DtlsException("unexpected handshake message " + type);
        }
    }

    /// Sends a `ClientHello`, with the cookie of a `HelloVerifyRequest` when there was one.
    ///
    /// @param cookie the cookie, empty for the first hello
    /// @throws IOException if the send fails
    private void sendClientHello(byte[] cookie) throws IOException {
        if (clientRandom == null) {
            clientRandom = random();
        }
        var body = new ByteArrayOutputStream();
        writeUint16(body, VERSION);
        body.writeBytes(clientRandom);
        body.write(0);
        writeVector8(body, cookie);
        var suites = new ByteArrayOutputStream();
        writeUint16(suites, ECDHE_ECDSA_AES_128_GCM);
        writeUint16(suites, ECDHE_RSA_AES_128_GCM);
        writeVector16(body, suites.toByteArray());
        body.write(1);
        body.write(0);
        var extensions = new ByteArrayOutputStream();
        writeExtension(extensions, EXT_SUPPORTED_GROUPS, new byte[]{0, 2, 0, (byte) SECP256R1});
        writeExtension(extensions, EXT_EC_POINT_FORMATS, new byte[]{1, 0});
        var schemes = new ByteArrayOutputStream();
        for (var scheme : SIGNATURE_SCHEMES) {
            writeUint16(schemes, scheme);
        }
        var schemeVector = new ByteArrayOutputStream();
        writeVector16(schemeVector, schemes.toByteArray());
        writeExtension(extensions, EXT_SIGNATURE_ALGORITHMS, schemeVector.toByteArray());
        writeExtension(extensions, EXT_USE_SRTP, useSrtpExtension(profiles));
        writeExtension(extensions, EXT_EXTENDED_MASTER_SECRET, new byte[0]);
        writeExtension(extensions, EXT_RENEGOTIATION_INFO, new byte[]{0});
        writeVector16(body, extensions.toByteArray());
        var message = rawHandshakeMessage(CLIENT_HELLO, body.toByteArray());
        pendingClientHello = message.payload();
        sendFlight(List.of(message));
    }

    /// Sends the client's second flight: its certificate, key exchange, certificate verify, change
    /// cipher spec and `Finished`.
    ///
    /// @throws IOException if key agreement fails or the send fails
    private void sendClientFinalFlight() throws IOException {
        requireCertificate();
        if (peerEphemeral == null) {
            throw new DtlsException("server sent no key exchange");
        }
        var flight = new ArrayList<Outgoing>();
        if (certificateRequested) {
            flight.add(handshakeMessage(CERTIFICATE, certificateBody(), 0));
        }
        ephemeral = generateEphemeral();
        var exchange = new ByteArrayOutputStream();
        writeVector8(exchange, encodePoint((ECPublicKey) ephemeral.getPublic()));
        flight.add(handshakeMessage(CLIENT_KEY_EXCHANGE, exchange.toByteArray(), 0));
        deriveKeys();
        if (certificateRequested) {
            var verify = new ByteArrayOutputStream();
            writeUint16(verify, ECDSA_SHA256);
            writeVector16(verify, sign(transcript.toByteArray()));
            flight.add(handshakeMessage(CERTIFICATE_VERIFY, verify.toByteArray(), 0));
        }
        flight.add(new Outgoing(CHANGE_CIPHER_SPEC, 0, new byte[]{1}));
        writeEpoch = 1;
        var verifyData = TlsPrf.compute(masterSecret, "client finished", transcriptHash(), 12);
        flight.add(handshakeMessage(FINISHED, verifyData, 1));
        sendFlight(flight);
    }

    /// Sends the server's first flight: hello, certificate, key exchange, certificate request and hello
    /// done.
    ///
    /// @throws IOException if signing fails or the send fails
    private void sendServerFlight() throws IOException {
        serverRandom = random();
        ephemeral = generateEphemeral();
        var flight = new ArrayList<Outgoing>();
        var hello = new ByteArrayOutputStream();
        writeUint16(hello, VERSION);
        hello.writeBytes(serverRandom);
        hello.write(0);
        writeUint16(hello, cipherSuite);
        hello.write(0);
        var extensions = new ByteArrayOutputStream();
        writeExtension(extensions, EXT_USE_SRTP, useSrtpExtension(List.of(profile)));
        if (extendedMasterSecret) {
            writeExtension(extensions, EXT_EXTENDED_MASTER_SECRET, new byte[0]);
        }
        if (peerRenegotiationInfo) {
            writeExtension(extensions, EXT_RENEGOTIATION_INFO, new byte[]{0});
        }
        if (peerPointFormats) {
            writeExtension(extensions, EXT_EC_POINT_FORMATS, new byte[]{1, 0});
        }
        writeVector16(hello, extensions.toByteArray());
        flight.add(handshakeMessage(SERVER_HELLO, hello.toByteArray(), 0));
        flight.add(handshakeMessage(CERTIFICATE, certificateBody(), 0));
        var params = new ByteArrayOutputStream();
        params.write(3);
        writeUint16(params, SECP256R1);
        writeVector8(params, encodePoint((ECPublicKey) ephemeral.getPublic()));
        var keyExchange = new ByteArrayOutputStream();
        keyExchange.writeBytes(params.toByteArray());
        writeUint16(keyExchange, ECDSA_SHA256);
        writeVector16(keyExchange, sign(TlsPrf.concat(TlsPrf.concat(clientRandom, serverRandom), params.toByteArray())));
        flight.add(handshakeMessage(SERVER_KEY_EXCHANGE, keyExchange.toByteArray(), 0));
        var request = new ByteArrayOutputStream();
        writeVector8(request, new byte[]{64, 1});
        var schemes = new ByteArrayOutputStream();
        for (var scheme : SIGNATURE_SCHEMES) {
            writeUint16(schemes, scheme);
        }
        writeVector16(request, schemes.toByteArray());
        writeUint16(request, 0);
        flight.add(handshakeMessage(CERTIFICATE_REQUEST, request.toByteArray(), 0));
        flight.add(handshakeMessage(SERVER_HELLO_DONE, new byte[0], 0));
        sendFlight(flight);
    }

    /// Computes the master secret and the record keys once both ephemeral keys are known.
    ///
    /// @throws DtlsException if key agreement fails
    private void deriveKeys() throws DtlsException {
        if (ephemeral == null) {
            throw new DtlsException("no local ephemeral key");
        }
        byte[] preMaster;
        try {
            var agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(ephemeral.getPrivate());
            agreement.doPhase(peerEphemeral, true);
            preMaster = agreement.generateSecret();
        } catch (GeneralSecurityException exception) {
            throw new DtlsException("ECDH key agreement failed", exception);
        }
        masterSecret = extendedMasterSecret
                ? TlsPrf.compute(preMaster, "extended master secret", transcriptHash(), 48)
                : TlsPrf.compute(preMaster, "master secret", TlsPrf.concat(clientRandom, serverRandom), 48);
        Arrays.fill(preMaster, (byte) 0);
        var block = TlsPrf.compute(masterSecret, "key expansion", TlsPrf.concat(serverRandom, clientRandom), 40);
        var client = new DtlsRecordCipher(Arrays.copyOfRange(block, 0, 16), Arrays.copyOfRange(block, 32, 36));
        var server = new DtlsRecordCipher(Arrays.copyOfRange(block, 16, 32), Arrays.copyOfRange(block, 36, 40));
        writeCipher = role == Role.CLIENT ? client : server;
        pendingReadCipher = role == Role.CLIENT ? server : client;
    }

    /// Exports the SRTP keys from the master secret.
    ///
    /// @return the keys of both directions
    private DtlsSrtpKeys exportKeys() {
        var keyLength = profile.keyLength();
        var saltLength = profile.saltLength();
        var material = TlsPrf.compute(masterSecret, "EXTRACTOR-dtls_srtp",
                TlsPrf.concat(clientRandom, serverRandom), 2 * (keyLength + saltLength));
        var clientKey = Arrays.copyOfRange(material, 0, keyLength);
        var serverKey = Arrays.copyOfRange(material, keyLength, 2 * keyLength);
        var clientSalt = Arrays.copyOfRange(material, 2 * keyLength, 2 * keyLength + saltLength);
        var serverSalt = Arrays.copyOfRange(material, 2 * keyLength + saltLength, material.length);
        return role == Role.CLIENT
                ? new DtlsSrtpKeys(profile, clientKey, clientSalt, serverKey, serverSalt)
                : new DtlsSrtpKeys(profile, serverKey, serverSalt, clientKey, clientSalt);
    }

    /// {@return the body of a `Certificate` message carrying this endpoint's certificate}
    private byte[] certificateBody() {
        var der = certificate.encoded();
        var entry = new ByteArrayOutputStream();
        writeUint24(entry, der.length);
        entry.writeBytes(der);
        var body = new ByteArrayOutputStream();
        writeUint24(body, entry.size());
        body.writeBytes(entry.toByteArray());
        return body.toByteArray();
    }

    /// Reads the leaf of a `Certificate` message and checks it against the advertised fingerprint.
    ///
    /// @param buffer the message body
    /// @return the leaf certificate
    /// @throws DtlsException if the message carries no certificate or the fingerprint does not match
    private X509Certificate readCertificate(ByteBuffer buffer) throws DtlsException {
        var total = readUint24(buffer);
        if (total == 0 || buffer.remaining() < 3) {
            throw new DtlsException("peer presented no certificate");
        }
        var length = readUint24(buffer);
        var der = readBytes(buffer, length);
        if (!DtlsCertificate.matches(der, remoteFingerprint)) {
            throw new DtlsException("peer certificate does not match the advertised fingerprint");
        }
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException exception) {
            throw new DtlsException("peer certificate is malformed", exception);
        }
    }

    /// Fails when the peer's certificate has not arrived yet.
    ///
    /// @throws DtlsException if there is no peer certificate
    private void requireCertificate() throws DtlsException {
        if (peerCertificate == null) {
            throw new DtlsException("peer did not present its certificate");
        }
    }

    /// Signs data with this endpoint's key, `ecdsa_secp256r1_sha256`.
    ///
    /// @param data the data
    /// @return the DER signature
    /// @throws DtlsException if signing fails
    private byte[] sign(byte[] data) throws DtlsException {
        try {
            var signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(certificate.privateKey());
            signer.update(data);
            return signer.sign();
        } catch (GeneralSecurityException exception) {
            throw new DtlsException("signing failed", exception);
        }
    }

    /// Verifies a TLS 1.2 digital signature.
    ///
    /// @param key       the public key
    /// @param scheme    the signature scheme
    /// @param data      the signed data
    /// @param signature the signature
    /// @return `true` if it verifies
    /// @throws DtlsException if the scheme is unsupported
    private static boolean verify(PublicKey key, int scheme, byte[] data, byte[] signature) throws DtlsException {
        try {
            var verifier = switch (scheme) {
                case 0x0403 -> Signature.getInstance("SHA256withECDSA");
                case 0x0503 -> Signature.getInstance("SHA384withECDSA");
                case 0x0203 -> Signature.getInstance("SHA1withECDSA");
                case 0x0401 -> Signature.getInstance("SHA256withRSA");
                case 0x0501 -> Signature.getInstance("SHA384withRSA");
                case 0x0201 -> Signature.getInstance("SHA1withRSA");
                case 0x0804, 0x0805 -> {
                    var pss = Signature.getInstance("RSASSA-PSS");
                    pss.setParameter(scheme == 0x0804
                            ? new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
                            : new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1));
                    yield pss;
                }
                default -> throw new DtlsException("unsupported signature scheme 0x" + Integer.toHexString(scheme));
            };
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (GeneralSecurityException exception) {
            return false;
        }
    }

    /// Generates an ephemeral P-256 key pair.
    ///
    /// @return the key pair
    /// @throws DtlsException if the JDK cannot generate it
    private static KeyPair generateEphemeral() throws DtlsException {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new DtlsException("cannot generate the ephemeral key", exception);
        }
    }

    /// Encodes a P-256 public key as an uncompressed point.
    ///
    /// @param key the key
    /// @return `0x04 || x || y`, 65 bytes
    private static byte[] encodePoint(ECPublicKey key) {
        var point = new byte[65];
        point[0] = 4;
        copyUnsigned(key.getW().getAffineX(), point, 1);
        copyUnsigned(key.getW().getAffineY(), point, 33);
        return point;
    }

    /// Decodes an uncompressed P-256 point.
    ///
    /// @param point the encoded point
    /// @return the public key
    /// @throws DtlsException if the point is not a valid uncompressed P-256 point
    private static PublicKey decodePoint(byte[] point) throws DtlsException {
        if (point.length != 65 || point[0] != 4) {
            throw new DtlsException("peer sent an unsupported EC point encoding");
        }
        try {
            var x = new BigInteger(1, Arrays.copyOfRange(point, 1, 33));
            var y = new BigInteger(1, Arrays.copyOfRange(point, 33, 65));
            var parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            var spec = parameters.getParameterSpec(ECParameterSpec.class);
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
        } catch (GeneralSecurityException exception) {
            throw new DtlsException("peer sent an invalid EC point", exception);
        }
    }

    /// Writes an unsigned big integer into 32 bytes.
    ///
    /// @param value       the value
    /// @param destination the destination
    /// @param offset      the offset
    private static void copyUnsigned(BigInteger value, byte[] destination, int offset) {
        var bytes = value.toByteArray();
        var start = Math.max(0, bytes.length - 32);
        var length = bytes.length - start;
        System.arraycopy(bytes, start, destination, offset + 32 - length, length);
    }

    /// {@return the SHA-256 of the transcript}
    private byte[] transcriptHash() {
        try {
            return MessageDigest.getInstance("SHA-256").digest(transcript.toByteArray());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    /// {@return a handshake message that enters the transcript}
    ///
    /// @param type  the handshake type
    /// @param body  the body
    /// @param epoch the epoch to send it in
    private Outgoing handshakeMessage(int type, byte[] body, int epoch) {
        var message = messageBytes(type, sendMessageSeq++, body);
        transcript.writeBytes(message);
        return new Outgoing(HANDSHAKE, epoch, message);
    }

    /// {@return a handshake message that does not enter the transcript yet}
    ///
    /// @param type the handshake type
    /// @param body the body
    private Outgoing rawHandshakeMessage(int type, byte[] body) {
        return new Outgoing(HANDSHAKE, 0, messageBytes(type, sendMessageSeq++, body));
    }

    /// Encodes a handshake message with an unfragmented header.
    ///
    /// @param type       the handshake type
    /// @param messageSeq the message sequence number
    /// @param body       the body
    /// @return the header followed by the body
    private static byte[] messageBytes(int type, int messageSeq, byte[] body) {
        var out = new ByteArrayOutputStream();
        out.write(type);
        writeUint24(out, body.length);
        writeUint16(out, messageSeq);
        writeUint24(out, 0);
        writeUint24(out, body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

    /// Sends a flight and remembers it for retransmission.
    ///
    /// @param flight the messages
    /// @throws IOException if the send fails
    private void sendFlight(List<Outgoing> flight) throws IOException {
        lastFlight = List.copyOf(flight);
        transmit(lastFlight);
    }

    /// Encodes a flight into records, fragmenting large handshake messages, and sends the records packed
    /// into datagrams of at most [#MAX_DATAGRAM] bytes.
    ///
    /// @param flight the messages
    /// @throws IOException if encryption or the send fails
    private void transmit(List<Outgoing> flight) throws IOException {
        var datagram = new ByteArrayOutputStream();
        for (var message : flight) {
            for (var fragment : fragments(message)) {
                var record = encodeRecord(message.contentType(), message.epoch(), fragment);
                if (datagram.size() > 0 && datagram.size() + record.length > MAX_DATAGRAM) {
                    io.send(datagram.toByteArray());
                    datagram.reset();
                }
                datagram.writeBytes(record);
            }
        }
        if (datagram.size() > 0) {
            io.send(datagram.toByteArray());
        }
    }

    /// Splits an outgoing message into record payloads.
    ///
    /// @param message the message
    /// @return one payload for anything but a large handshake message, which is split into fragments
    private static List<byte[]> fragments(Outgoing message) {
        var payload = message.payload();
        if (message.contentType() != HANDSHAKE || payload.length - HANDSHAKE_HEADER_LENGTH <= MAX_FRAGMENT) {
            return List.of(payload);
        }
        var body = Arrays.copyOfRange(payload, HANDSHAKE_HEADER_LENGTH, payload.length);
        var result = new ArrayList<byte[]>();
        for (var offset = 0; offset < body.length; offset += MAX_FRAGMENT) {
            var length = Math.min(MAX_FRAGMENT, body.length - offset);
            var out = new ByteArrayOutputStream();
            out.write(payload, 0, 6);
            writeUint24(out, offset);
            writeUint24(out, length);
            out.write(body, offset, length);
            result.add(out.toByteArray());
        }
        return result;
    }

    /// Encodes one record.
    ///
    /// @param type    the content type
    /// @param epoch   the epoch
    /// @param payload the plaintext payload
    /// @return the record
    /// @throws DtlsException if encryption fails
    private byte[] encodeRecord(int type, int epoch, byte[] payload) throws DtlsException {
        var sequence = writeSequence[epoch]++;
        var epochAndSequence = ((long) epoch << 48) | sequence;
        var fragment = epoch == 0 ? payload : writeCipher.encrypt(epochAndSequence, type, VERSION, payload);
        return ByteBuffer.allocate(RECORD_HEADER_LENGTH + fragment.length)
                .put((byte) type)
                .putShort((short) VERSION)
                .putLong(epochAndSequence)
                .putShort((short) fragment.length)
                .put(fragment)
                .array();
    }

    /// Sends an alert in the current write epoch, ignoring failures.
    ///
    /// @param description the alert description, `0` for `close_notify`
    private void sendAlertQuietly(int description) {
        synchronized (lock) {
            try {
                var level = description == 0 ? 1 : 2;
                var epoch = writeEpoch == 1 && writeCipher != null ? 1 : 0;
                io.send(encodeRecord(ALERT, epoch, new byte[]{(byte) level, (byte) description}));
            } catch (IOException | RuntimeException exception) {
                // the alert is a courtesy to the peer; the association is over either way
            }
        }
    }

    /// {@return a 32-byte random}
    private static byte[] random() {
        var random = new byte[32];
        RANDOM.nextBytes(random);
        return random;
    }

    /// {@return the `use_srtp` extension data for a profile list with an empty MKI}
    ///
    /// @param list the profiles
    private static byte[] useSrtpExtension(List<SrtpProfile> list) {
        var ids = new ByteArrayOutputStream();
        for (var entry : list) {
            writeUint16(ids, entry.id());
        }
        var data = new ByteArrayOutputStream();
        writeVector16(data, ids.toByteArray());
        data.write(0);
        return data.toByteArray();
    }

    /// Writes one extension.
    ///
    /// @param out  the destination
    /// @param type the extension type
    /// @param data the extension data
    private static void writeExtension(ByteArrayOutputStream out, int type, byte[] data) {
        writeUint16(out, type);
        writeVector16(out, data);
    }

    /// Writes a 16-bit big-endian integer.
    ///
    /// @param out   the destination
    /// @param value the value
    private static void writeUint16(ByteArrayOutputStream out, int value) {
        out.write(value >>> 8);
        out.write(value);
    }

    /// Writes a 24-bit big-endian integer.
    ///
    /// @param out   the destination
    /// @param value the value
    private static void writeUint24(ByteArrayOutputStream out, int value) {
        out.write(value >>> 16);
        out.write(value >>> 8);
        out.write(value);
    }

    /// Writes a vector with an 8-bit length.
    ///
    /// @param out  the destination
    /// @param data the data
    private static void writeVector8(ByteArrayOutputStream out, byte[] data) {
        out.write(data.length);
        out.writeBytes(data);
    }

    /// Writes a vector with a 16-bit length.
    ///
    /// @param out  the destination
    /// @param data the data
    private static void writeVector16(ByteArrayOutputStream out, byte[] data) {
        writeUint16(out, data.length);
        out.writeBytes(data);
    }

    /// Reads a 24-bit big-endian integer.
    ///
    /// @param buffer the source
    /// @return the value
    private static int readUint24(ByteBuffer buffer) {
        return (buffer.get() & 0xFF) << 16 | (buffer.get() & 0xFF) << 8 | (buffer.get() & 0xFF);
    }

    /// Reads a number of bytes.
    ///
    /// @param buffer the source
    /// @param length the number of bytes
    /// @return the bytes
    /// @throws DtlsException if fewer bytes remain
    private static byte[] readBytes(ByteBuffer buffer, int length) throws DtlsException {
        if (length > buffer.remaining()) {
            throw new DtlsException("truncated handshake message");
        }
        var bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    /// Reads a vector with an 8-bit length.
    ///
    /// @param buffer the source
    /// @return the vector data
    /// @throws DtlsException if the vector is truncated
    private static byte[] readVector8(ByteBuffer buffer) throws DtlsException {
        return readBytes(buffer, buffer.get() & 0xFF);
    }

    /// Reads a vector with a 16-bit length.
    ///
    /// @param buffer the source
    /// @return the vector data
    /// @throws DtlsException if the vector is truncated
    private static byte[] readVector16(ByteBuffer buffer) throws DtlsException {
        return readBytes(buffer, buffer.getShort() & 0xFFFF);
    }

    /// The DTLS role of an endpoint.
    ///
    /// The `a=setup` attribute of a session description decides the roles: the side that writes `active` is the
    /// client and the side that writes `passive` the server; an answerer facing `actpass` picks either.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
    public enum Role {
        /// Sends the `ClientHello`; `a=setup:active` in a session description.
        CLIENT,

        /// Answers the `ClientHello`; `a=setup:passive` in a session description.
        SERVER
    }

    /// What a DTLS datagram received after the handshake meant, as [#handleAfterHandshake(byte\[\])] reports it.
    public enum AfterHandshake {
        /// The datagram carried nothing this endpoint acts on.
        IGNORED,

        /// The peer repeated handshake messages, so this endpoint sent its last flight again.
        RETRANSMITTED,

        /// The peer sent an alert: it closed the association or failed.
        CLOSED
    }

    /// One message of a flight.
    ///
    /// @param contentType the record content type
    /// @param epoch       the epoch it is sent in
    /// @param payload     the plaintext payload; for a handshake message, the message with its
    ///                    unfragmented header
    private record Outgoing(int contentType, int epoch, byte[] payload) {
    }

    /// A handshake message being reassembled from fragments.
    private static final class Reassembly {
        /// The handshake type.
        private final int type;

        /// The message body being filled.
        private final byte[] body;

        /// Which body bytes have arrived.
        private final BitSet received;

        /// Creates an empty reassembly.
        ///
        /// @param type   the handshake type
        /// @param length the body length
        private Reassembly(int type, int length) {
            this.type = type;
            this.body = new byte[length];
            this.received = new BitSet(length);
        }

        /// Adds a fragment.
        ///
        /// @param offset   the fragment offset
        /// @param fragment the fragment bytes
        private void add(int offset, byte[] fragment) {
            if (offset + fragment.length > body.length) {
                return;
            }
            System.arraycopy(fragment, 0, body, offset, fragment.length);
            received.set(offset, offset + fragment.length);
        }

        /// {@return whether every byte arrived}
        private boolean complete() {
            return received.cardinality() == body.length;
        }
    }
}
