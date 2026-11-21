package com.github.auties00.parley.dtls;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
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
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Runs the DTLS-SRTP handshake of [DtlsEndpoint] against BouncyCastle's independent DTLS 1.2 implementation in both
/// roles, and against itself, over in-memory datagram queues; both sides must export the same SRTP keys.
@DisplayName("DtlsEndpoint")
class DtlsEndpointTest {
    private static final int SRTP_KEY_MATERIAL = 2 * (16 + 14);

    @Nested
    @DisplayName("as the client")
    class AsClient {
        @Test
        @DisplayName("completes a use_srtp handshake with a BouncyCastle server and exports the same keys")
        void againstBouncyCastleServer() throws Exception {
            var pipe = new Pipe();
            var crypto = new JcaTlsCryptoProvider().create(new SecureRandom());
            var serverCertificate = DtlsCertificate.generate();
            var clientCertificate = DtlsCertificate.generate();
            var server = new SrtpServer(crypto, serverCertificate, clientCertificate.fingerprint());
            var serverResult = new AtomicReference<Throwable>();
            var serverThread = Thread.ofVirtual().start(() -> {
                try {
                    new DTLSServerProtocol().accept(server, pipe.right());
                } catch (Throwable throwable) {
                    serverResult.set(throwable);
                }
            });
            var endpoint = new DtlsEndpoint(DtlsEndpoint.Role.CLIENT, clientCertificate, serverCertificate.fingerprint(),
                    List.of(SrtpProfile.AES128_CM_HMAC_SHA1_80), pipe.leftIo());
            var keys = endpoint.handshake(Duration.ofSeconds(10));
            serverThread.join(10_000);
            if (serverResult.get() != null) {
                throw new AssertionError("BouncyCastle server failed", serverResult.get());
            }
            assertEquals(SrtpProfile.AES128_CM_HMAC_SHA1_80, keys.profile());
            var exported = server.exported;
            assertNotNull(exported);
            assertArrayEquals(Arrays.copyOfRange(exported, 0, 16), keys.localKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 16, 32), keys.remoteKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 32, 46), keys.localSalt());
            assertArrayEquals(Arrays.copyOfRange(exported, 46, 60), keys.remoteSalt());
            assertTrue(server.clientCertificateMatched);
        }

        @Test
        @DisplayName("fails when the server certificate does not match the advertised fingerprint")
        void rejectsWrongFingerprint() {
            var pipe = new Pipe();
            var crypto = new JcaTlsCryptoProvider().create(new SecureRandom());
            var serverCertificate = DtlsCertificate.generate();
            var clientCertificate = DtlsCertificate.generate();
            var server = new SrtpServer(crypto, serverCertificate, clientCertificate.fingerprint());
            Thread.ofVirtual().start(() -> {
                try {
                    new DTLSServerProtocol().accept(server, pipe.right());
                } catch (IOException ignored) {
                    // the client aborts the handshake
                }
            });
            var endpoint = new DtlsEndpoint(DtlsEndpoint.Role.CLIENT, clientCertificate,
                    DtlsCertificate.generate().fingerprint(), List.of(SrtpProfile.AES128_CM_HMAC_SHA1_80), pipe.leftIo());
            assertThrows(DtlsException.class, () -> endpoint.handshake(Duration.ofSeconds(5)));
        }
    }

    @Nested
    @DisplayName("as the server")
    class AsServer {
        @Test
        @DisplayName("completes a use_srtp handshake with a BouncyCastle client and exports the same keys")
        void againstBouncyCastleClient() throws Exception {
            var pipe = new Pipe();
            var crypto = new JcaTlsCryptoProvider().create(new SecureRandom());
            var serverCertificate = DtlsCertificate.generate();
            var clientCertificate = DtlsCertificate.generate();
            var client = new SrtpClient(crypto, clientCertificate, serverCertificate.fingerprint());
            var clientResult = new AtomicReference<Throwable>();
            var clientThread = Thread.ofVirtual().start(() -> {
                try {
                    new DTLSClientProtocol().connect(client, pipe.right());
                } catch (Throwable throwable) {
                    clientResult.set(throwable);
                }
            });
            var endpoint = new DtlsEndpoint(DtlsEndpoint.Role.SERVER, serverCertificate, clientCertificate.fingerprint(),
                    List.of(SrtpProfile.values()), pipe.leftIo());
            var keys = endpoint.handshake(Duration.ofSeconds(10));
            clientThread.join(10_000);
            if (clientResult.get() != null) {
                throw new AssertionError("BouncyCastle client failed", clientResult.get());
            }
            var exported = client.exported;
            assertNotNull(exported);
            assertArrayEquals(Arrays.copyOfRange(exported, 0, 16), keys.remoteKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 16, 32), keys.localKey());
            assertArrayEquals(Arrays.copyOfRange(exported, 32, 46), keys.remoteSalt());
            assertArrayEquals(Arrays.copyOfRange(exported, 46, 60), keys.localSalt());
        }
    }

    @Test
    @DisplayName("two endpoints agree on the AEAD profile and on mirrored keys")
    void selfInterop() throws Exception {
        var pipe = new Pipe();
        var clientCertificate = DtlsCertificate.generate();
        var serverCertificate = DtlsCertificate.generate();
        var server = new DtlsEndpoint(DtlsEndpoint.Role.SERVER, serverCertificate, clientCertificate.fingerprint(),
                List.of(SrtpProfile.values()), pipe.rightIo());
        var serverKeys = new AtomicReference<DtlsSrtpKeys>();
        var serverThread = Thread.ofVirtual().start(() -> {
            try {
                serverKeys.set(server.handshake(Duration.ofSeconds(10)));
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        });
        var client = new DtlsEndpoint(DtlsEndpoint.Role.CLIENT, clientCertificate, serverCertificate.fingerprint(),
                List.of(SrtpProfile.values()), pipe.leftIo());
        var clientKeys = client.handshake(Duration.ofSeconds(10));
        serverThread.join(10_000);
        assertEquals(SrtpProfile.AEAD_AES_128_GCM, clientKeys.profile());
        assertArrayEquals(clientKeys.localKey(), serverKeys.get().remoteKey());
        assertArrayEquals(clientKeys.remoteSalt(), serverKeys.get().localSalt());
    }

    @Test
    @DisplayName("matches fingerprints case-insensitively and rejects unknown hash names")
    void fingerprintMatching() {
        var certificate = DtlsCertificate.generate();
        var fingerprint = certificate.fingerprint();
        assertTrue(DtlsCertificate.matches(certificate.encoded(), fingerprint.toLowerCase()));
        assertTrue(fingerprint.startsWith("sha-256 "));
        assertEquals(false, DtlsCertificate.matches(certificate.encoded(), "md5 00:11"));
    }

    private static final class Pipe {
        private final LinkedBlockingQueue<byte[]> toRight = new LinkedBlockingQueue<>();
        private final LinkedBlockingQueue<byte[]> toLeft = new LinkedBlockingQueue<>();

        DtlsDatagramIo leftIo() {
            return io(toRight, toLeft);
        }

        DtlsDatagramIo rightIo() {
            return io(toLeft, toRight);
        }

        DatagramTransport right() {
            return new DatagramTransport() {
                @Override
                public int getReceiveLimit() {
                    return 1500;
                }

                @Override
                public int getSendLimit() {
                    return 1500;
                }

                @Override
                public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
                    try {
                        var datagram = toRight.poll(waitMillis, TimeUnit.MILLISECONDS);
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
                public void send(byte[] buf, int off, int len) {
                    toLeft.add(Arrays.copyOfRange(buf, off, off + len));
                }

                @Override
                public void close() {
                }
            };
        }

        private static DtlsDatagramIo io(LinkedBlockingQueue<byte[]> out, LinkedBlockingQueue<byte[]> in) {
            return new DtlsDatagramIo() {
                @Override
                public void send(byte[] datagram) {
                    out.add(datagram.clone());
                }

                @Override
                public byte[] receive(long timeoutNanos) throws InterruptedException {
                    return in.poll(timeoutNanos, TimeUnit.NANOSECONDS);
                }
            };
        }
    }

    private static TlsCredentialedSigner signer(JcaTlsCrypto crypto, TlsCryptoParameters parameters,
                                                DtlsCertificate certificate) throws IOException {
        var chain = new Certificate(new TlsCertificate[]{crypto.createCertificate(certificate.encoded())});
        return new JcaDefaultTlsCredentialedSigner(parameters, crypto, certificate.privateKey(), chain,
                SignatureAndHashAlgorithm.getInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
    }

    private static final class SrtpServer extends DefaultTlsServer {
        private final JcaTlsCrypto crypto;
        private final DtlsCertificate certificate;
        private final String clientFingerprint;
        private volatile byte[] exported;
        private volatile boolean clientCertificateMatched;

        SrtpServer(JcaTlsCrypto crypto, DtlsCertificate certificate, String clientFingerprint) {
            super(crypto);
            this.crypto = crypto;
            this.certificate = certificate;
            this.clientFingerprint = clientFingerprint;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.DTLSv12.only();
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
        }

        @Override
        protected TlsCredentialedSigner getECDSASignerCredentials() throws IOException {
            return signer(crypto, new TlsCryptoParameters(context), certificate);
        }

        @Override
        public CertificateRequest getCertificateRequest() {
            return new CertificateRequest(new short[]{ClientCertificateType.ecdsa_sign},
                    TlsUtils.getDefaultSupportedSignatureAlgorithms(context), null);
        }

        @Override
        public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
            if (clientCertificate.isEmpty()
                    || !DtlsCertificate.matches(clientCertificate.getCertificateAt(0).getEncoded(), clientFingerprint)) {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
            clientCertificateMatched = true;
        }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        public Hashtable getServerExtensions() throws IOException {
            var extensions = TlsExtensionsHolder.ensure(super.getServerExtensions());
            TlsSRTPUtils.addUseSRTPExtension(extensions,
                    new UseSRTPData(new int[]{SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80}, TlsUtils.EMPTY_BYTES));
            return extensions;
        }

        @Override
        public void notifyHandshakeComplete() throws IOException {
            super.notifyHandshakeComplete();
            exported = context.exportKeyingMaterial(ExporterLabel.dtls_srtp, null, SRTP_KEY_MATERIAL);
        }
    }

    private static final class SrtpClient extends DefaultTlsClient {
        private final JcaTlsCrypto crypto;
        private final DtlsCertificate certificate;
        private final String serverFingerprint;
        private volatile byte[] exported;

        SrtpClient(JcaTlsCrypto crypto, DtlsCertificate certificate, String serverFingerprint) {
            super(crypto);
            this.crypto = crypto;
            this.certificate = certificate;
            this.serverFingerprint = serverFingerprint;
        }

        @Override
        protected ProtocolVersion[] getSupportedVersions() {
            return ProtocolVersion.DTLSv12.only();
        }

        @Override
        protected int[] getSupportedCipherSuites() {
            return new int[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
        }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        public Hashtable getClientExtensions() throws IOException {
            var extensions = TlsExtensionsHolder.ensure(super.getClientExtensions());
            TlsSRTPUtils.addUseSRTPExtension(extensions,
                    new UseSRTPData(new int[]{SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80}, TlsUtils.EMPTY_BYTES));
            return extensions;
        }

        @Override
        public TlsAuthentication getAuthentication() {
            return new TlsAuthentication() {
                @Override
                public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                    var chain = serverCertificate.getCertificate();
                    if (chain.isEmpty() || !DtlsCertificate.matches(chain.getCertificateAt(0).getEncoded(), serverFingerprint)) {
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    }
                }

                @Override
                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                    return signer(crypto, new TlsCryptoParameters(context), certificate);
                }
            };
        }

        @Override
        public void notifyHandshakeComplete() throws IOException {
            super.notifyHandshakeComplete();
            exported = context.exportKeyingMaterial(ExporterLabel.dtls_srtp, null, SRTP_KEY_MATERIAL);
        }
    }

    private static final class TlsExtensionsHolder {
        @SuppressWarnings({"rawtypes", "unchecked"})
        static Hashtable ensure(Hashtable extensions) {
            return extensions == null ? new Hashtable() : extensions;
        }
    }
}
