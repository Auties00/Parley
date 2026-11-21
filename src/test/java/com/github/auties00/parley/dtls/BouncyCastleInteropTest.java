package com.github.auties00.parley.dtls;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.ExporterLabel;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SRTPProtectionProfile;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSRTPUtils;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.UseSRTPData;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Runs [DtlsTransport] against BouncyCastle's independent DTLS 1.2 implementation in both roles, with ECDSA and RSA
/// certificates, every DTLS 1.2 cipher suite, BouncyCastle's cookie exchange, a lossy link, and application data.
///
/// BouncyCastle 1.80 implements no DTLS 1.3, so a client of this library offering both versions also proves its
/// fallback, and a BouncyCastle client proves this library's DTLS 1.2 server path with the downgrade sentinel.
@DisplayName("DtlsTransport against BouncyCastle")
class BouncyCastleInteropTest {
    private static final JcaTlsCrypto CRYPTO = new JcaTlsCryptoProvider()
            .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()).create(new SecureRandom());
    private static final DtlsCertificate ECDSA = DtlsCertificate.generateEcdsa();
    private static final DtlsCertificate ECDSA_PEER = DtlsCertificate.generateEcdsa();
    private static final DtlsCertificate RSA = DtlsCertificate.generateRsa();
    private static final DtlsCertificate RSA_PEER = DtlsCertificate.generateRsa();
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    static Stream<Object[]> suites() {
        return Stream.of(
                new Object[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ECDSA, ECDSA_PEER},
                new Object[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ECDSA, ECDSA_PEER},
                new Object[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, ECDSA, ECDSA_PEER},
                new Object[]{CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, RSA, RSA_PEER},
                new Object[]{CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, RSA, RSA_PEER},
                new Object[]{CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, RSA, RSA_PEER});
    }

    @Nested
    @DisplayName("as the client")
    class AsClient {
        @ParameterizedTest(name = "suite 0x{0}")
        @MethodSource("com.github.auties00.parley.dtls.BouncyCastleInteropTest#suites")
        @DisplayName("completes a handshake with a BouncyCastle server and exports the same keys")
        void suite(int suite, DtlsCertificate serverCertificate, DtlsCertificate clientCertificate) throws Exception {
            var link = new MemoryLink();
            var server = new SrtpServer(serverCertificate, clientCertificate.fingerprints().getFirst(), suite);
            var serverResult = startServer(server, link);
            var client = DtlsTransport.over(link.left, DtlsConfig.of(clientCertificate));
            var keys = client.handshake(DtlsRole.CLIENT, serverCertificate.fingerprints(), TIMEOUT);
            var transport = await(serverResult);
            assertEquals(DtlsVersion.DTLS_1_2, client.negotiatedVersion().orElseThrow());
            assertEquals(SrtpProfile.AES128_CM_HMAC_SHA1_80, keys.profile());
            var exported = server.exported;
            assertArrayEquals(Arrays.copyOfRange(exported, 0, 16), keys.localKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 16, 32), keys.remoteKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 32, 46), keys.localSalt());
            assertArrayEquals(Arrays.copyOfRange(exported, 46, 60), keys.remoteSalt());
            assertTrue(server.clientCertificateMatched);
            exchangeData(client, transport);
            client.close();
            link.close();
        }

        @Test
        @DisplayName("completes over a lossy link with BouncyCastle's cookie exchange")
        void lossy() throws Exception {
            for (var seed = 1; seed <= 4; seed++) {
                var link = new MemoryLink(new MemoryLink.Conditions(0.2, 0.1, 0.15, seed));
                var server = new SrtpServer(ECDSA, ECDSA_PEER.fingerprints().getFirst(),
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
                var serverResult = startServer(server, link, true);
                var client = DtlsTransport.over(link.left,
                        DtlsConfig.of(ECDSA_PEER).withInitialRetransmit(Duration.ofMillis(100)));
                var keys = client.handshake(DtlsRole.CLIENT, ECDSA.fingerprints(), TIMEOUT);
                await(serverResult);
                assertArrayEquals(Arrays.copyOfRange(server.exported, 0, 16), keys.localKey());
                client.close();
                link.close();
            }
        }

        @Test
        @DisplayName("fails when the server certificate does not match the signalled fingerprint")
        void wrongFingerprint() {
            var link = new MemoryLink();
            var server = new SrtpServer(ECDSA, ECDSA_PEER.fingerprints().getFirst(),
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
            startServer(server, link);
            var client = DtlsTransport.over(link.left, DtlsConfig.of(ECDSA_PEER));
            var exception = assertThrows(DtlsException.class, () -> client.handshake(DtlsRole.CLIENT,
                    DtlsCertificate.generateEcdsa().fingerprints(), Duration.ofSeconds(5)));
            assertEquals(DtlsAlert.BAD_CERTIFICATE, exception.alert().orElseThrow());
            link.close();
        }
    }

    @Nested
    @DisplayName("as the server")
    class AsServer {
        @ParameterizedTest(name = "suite 0x{0}")
        @MethodSource("com.github.auties00.parley.dtls.BouncyCastleInteropTest#suites")
        @DisplayName("completes a handshake with a BouncyCastle client and exports the same keys")
        void suite(int suite, DtlsCertificate serverCertificate, DtlsCertificate clientCertificate) throws Exception {
            var link = new MemoryLink();
            var client = new SrtpClient(clientCertificate, serverCertificate.fingerprints().getFirst(), suite);
            var clientResult = startClient(client, link);
            var server = DtlsTransport.over(link.left, DtlsConfig.of(serverCertificate));
            var keys = server.handshake(DtlsRole.SERVER, clientCertificate.fingerprints(), TIMEOUT);
            var transport = await(clientResult);
            assertEquals(DtlsVersion.DTLS_1_2, server.negotiatedVersion().orElseThrow());
            var exported = client.exported;
            assertArrayEquals(Arrays.copyOfRange(exported, 0, 16), keys.remoteKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 16, 32), keys.localKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 32, 46), keys.remoteSalt());
            assertArrayEquals(Arrays.copyOfRange(exported, 46, 60), keys.localSalt());
            exchangeData(server, transport);
            server.close();
            link.close();
        }

        @Test
        @DisplayName("completes over a lossy link with its own cookie exchange")
        void lossy() throws Exception {
            for (var seed = 1; seed <= 4; seed++) {
                var link = new MemoryLink(new MemoryLink.Conditions(0.2, 0.1, 0.15, seed));
                var client = new SrtpClient(ECDSA_PEER, ECDSA.fingerprints().getFirst(),
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
                var clientResult = startClient(client, link);
                var server = DtlsTransport.over(link.left,
                        DtlsConfig.of(ECDSA).withInitialRetransmit(Duration.ofMillis(100)));
                var keys = server.handshake(DtlsRole.SERVER, ECDSA_PEER.fingerprints(), TIMEOUT);
                await(clientResult);
                assertArrayEquals(Arrays.copyOfRange(client.exported, 0, 16), keys.remoteKey());
                server.close();
                link.close();
            }
        }

        @Test
        @DisplayName("completes without its cookie exchange, DTLS 1.2 only")
        void withoutCookie() throws Exception {
            var link = new MemoryLink();
            var client = new SrtpClient(ECDSA_PEER, ECDSA.fingerprints().getFirst(),
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
            var clientResult = startClient(client, link);
            var server = DtlsTransport.over(link.left, DtlsConfig.of(ECDSA).withCookieExchange(false)
                    .withVersions(Set.of(DtlsVersion.DTLS_1_2)));
            server.handshake(DtlsRole.SERVER, ECDSA_PEER.fingerprints(), TIMEOUT);
            assertNotNull(await(clientResult));
            server.close();
            link.close();
        }
    }

    /// Exchanges one application data record each way between this library and BouncyCastle.
    private static void exchangeData(DtlsTransport transport, DTLSTransport bouncyCastle) throws Exception {
        var received = new LinkedBlockingQueue<String>();
        transport.applicationData().setReceiver((packet, _) -> received.add(DtlsTransportTest.utf8(packet)));
        transport.applicationData().send(ByteBuffer.wrap("to-bc".getBytes(StandardCharsets.UTF_8)));
        var buffer = new byte[256];
        var length = bouncyCastle.receive(buffer, 0, buffer.length, 5000);
        assertEquals("to-bc", new String(buffer, 0, length, StandardCharsets.UTF_8));
        var reply = "from-bc".getBytes(StandardCharsets.UTF_8);
        bouncyCastle.send(reply, 0, reply.length);
        assertEquals("from-bc", received.poll(5, TimeUnit.SECONDS));
    }

    private static AtomicReference<Object> startServer(SrtpServer server, MemoryLink link) {
        return startServer(server, link, false);
    }

    /// Starts a BouncyCastle server; with `pump`, keeps reading its transport afterwards, which is how BouncyCastle
    /// answers a client that retransmits its final flight because the server's last flight was lost.
    private static AtomicReference<Object> startServer(SrtpServer server, MemoryLink link, boolean pump) {
        var result = new AtomicReference<>();
        Thread.ofVirtual().start(() -> {
            try {
                var transport = new DTLSServerProtocol().accept(server, bouncyCastleSide(link.right));
                result.set(transport);
                var buffer = new byte[2048];
                var until = System.nanoTime() + TIMEOUT.toNanos();
                while (pump && System.nanoTime() < until) {
                    if (transport.receive(buffer, 0, buffer.length, 100) < -1) {
                        return;
                    }
                }
            } catch (Throwable throwable) {
                if (Boolean.getBoolean("parley.debug")) {
                    throwable.printStackTrace();
                }
                result.set(throwable);
            }
        });
        return result;
    }

    private static AtomicReference<Object> startClient(SrtpClient client, MemoryLink link) {
        var result = new AtomicReference<>();
        Thread.ofVirtual().start(() -> {
            try {
                result.set(new DTLSClientProtocol().connect(client, bouncyCastleSide(link.right)));
            } catch (Throwable throwable) {
                if (Boolean.getBoolean("parley.debug")) {
                    throwable.printStackTrace();
                }
                result.set(throwable);
            }
        });
        return result;
    }

    private static DTLSTransport await(AtomicReference<Object> result) throws Exception {
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (result.get() == null && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        var value = result.get();
        if (value instanceof Throwable throwable) {
            throw new AssertionError("BouncyCastle failed", throwable);
        }
        assertNotNull(value, "BouncyCastle did not finish");
        return (DTLSTransport) value;
    }

    private static DatagramTransport bouncyCastleSide(MemoryLink.Endpoint endpoint) {
        return new DatagramTransport() {
            @Override
            public int getReceiveLimit() {
                return 1500;
            }

            @Override
            public int getSendLimit() {
                return 1200;
            }

            @Override
            public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
                try {
                    var datagram = endpoint.poll(waitMillis);
                    if (datagram == null) {
                        return -1;
                    }
                    var length = Math.min(len, datagram.length);
                    System.arraycopy(datagram, 0, buf, off, length);
                    return length;
                } catch (InterruptedException exception) {
                    throw new IOException(exception);
                }
            }

            @Override
            public void send(byte[] buf, int off, int len) throws IOException {
                endpoint.send(ByteBuffer.wrap(buf, off, len));
            }

            @Override
            public void close() {
            }
        };
    }

    private static TlsCredentialedSigner signer(TlsCryptoParameters parameters, DtlsCertificate certificate)
            throws IOException {
        var chain = new Certificate(new TlsCertificate[]{CRYPTO.createCertificate(certificate.encoded())});
        var algorithm = certificate.certificate().getPublicKey().getAlgorithm().equals("EC")
                ? SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa)
                : SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
        return new JcaDefaultTlsCredentialedSigner(parameters, CRYPTO, certificate.privateKey(), chain, algorithm);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Hashtable withSrtp(Hashtable extensions) throws IOException {
        var result = extensions == null ? new Hashtable() : extensions;
        TlsSRTPUtils.addUseSRTPExtension(result,
                new UseSRTPData(new int[]{SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80}, TlsUtils.EMPTY_BYTES));
        return result;
    }

    private static final class SrtpServer extends DefaultTlsServer {
        private final DtlsCertificate certificate;
        private final DtlsFingerprint clientFingerprint;
        private final int suite;
        private volatile byte[] exported;
        private volatile boolean clientCertificateMatched;

        SrtpServer(DtlsCertificate certificate, DtlsFingerprint clientFingerprint, int suite) {
            super(CRYPTO);
            this.certificate = certificate;
            this.clientFingerprint = clientFingerprint;
            this.suite = suite;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.DTLSv12.only();
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[]{suite};
        }

        @Override
        protected TlsCredentialedSigner getECDSASignerCredentials() throws IOException {
            return signer(new TlsCryptoParameters(context), certificate);
        }

        @Override
        protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
            return signer(new TlsCryptoParameters(context), certificate);
        }

        @Override
        public CertificateRequest getCertificateRequest() {
            return new CertificateRequest(new short[]{ClientCertificateType.ecdsa_sign, ClientCertificateType.rsa_sign},
                    TlsUtils.getDefaultSupportedSignatureAlgorithms(context), null);
        }

        @Override
        public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
            if (clientCertificate.isEmpty() || !clientFingerprint.matches(clientCertificate.getCertificateAt(0).getEncoded())) {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
            clientCertificateMatched = true;
        }

        @Override
        @SuppressWarnings({"rawtypes"})
        public Hashtable getServerExtensions() throws IOException {
            return withSrtp(super.getServerExtensions());
        }

        @Override
        public void notifyHandshakeComplete() throws IOException {
            super.notifyHandshakeComplete();
            exported = context.exportKeyingMaterial(ExporterLabel.dtls_srtp, null, 60);
        }
    }

    private static final class SrtpClient extends DefaultTlsClient {
        private final DtlsCertificate certificate;
        private final DtlsFingerprint serverFingerprint;
        private final int suite;
        private volatile byte[] exported;

        SrtpClient(DtlsCertificate certificate, DtlsFingerprint serverFingerprint, int suite) {
            super(CRYPTO);
            this.certificate = certificate;
            this.serverFingerprint = serverFingerprint;
            this.suite = suite;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.DTLSv12.only();
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[]{suite};
        }

        @Override
        @SuppressWarnings({"rawtypes"})
        public Hashtable getClientExtensions() throws IOException {
            return withSrtp(super.getClientExtensions());
        }

        @Override
        public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                    var chain = serverCertificate.getCertificate();
                    if (chain.isEmpty() || !serverFingerprint.matches(chain.getCertificateAt(0).getEncoded())) {
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    }
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                    return signer(new TlsCryptoParameters(context), certificate);
                }
            };
        }

        @Override
        public void notifyHandshakeComplete() throws IOException {
            super.notifyHandshakeComplete();
            exported = context.exportKeyingMaterial(ExporterLabel.dtls_srtp, null, 60);
        }
    }

    /// Keeps the list import used by the parameter sources.
    static List<Object> unused() {
        return List.of();
    }
}
