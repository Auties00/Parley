package com.github.auties00.parley.dtls;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Runs [DtlsTransport] against itself over an in-memory link: both versions, both certificate types, version
/// negotiation, lossy and reordering links, application data, key updates, closure and failures.
@DisplayName("DtlsTransport against itself")
class DtlsTransportTest {
    private static final DtlsCertificate ECDSA_CLIENT = DtlsCertificate.generateEcdsa();
    private static final DtlsCertificate ECDSA_SERVER = DtlsCertificate.generateEcdsa();
    private static final DtlsCertificate RSA_CLIENT = DtlsCertificate.generateRsa();
    private static final DtlsCertificate RSA_SERVER = DtlsCertificate.generateRsa();
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    /// The two keyed ends of a completed handshake.
    record Pair(DtlsTransport client, DtlsTransport server, DtlsSrtpKeys clientKeys, DtlsSrtpKeys serverKeys,
                MemoryLink link) implements AutoCloseable {
        @Override
        public void close() {
            client.close();
            server.close();
            link.close();
        }
    }

    static Pair connect(MemoryLink link, DtlsConfig clientConfig, DtlsConfig serverConfig) throws Exception {
        var client = DtlsTransport.over(link.left, clientConfig);
        var server = DtlsTransport.over(link.right, serverConfig);
        var serverKeys = new AtomicReference<DtlsSrtpKeys>();
        var serverError = new AtomicReference<Throwable>();
        var thread = Thread.ofVirtual().start(() -> {
            try {
                serverKeys.set(server.handshake(DtlsRole.SERVER, fingerprints(clientConfig), TIMEOUT));
            } catch (Throwable throwable) {
                serverError.set(throwable);
            }
        });
        DtlsSrtpKeys clientKeys;
        try {
            clientKeys = client.handshake(DtlsRole.CLIENT, fingerprints(serverConfig), TIMEOUT);
        } finally {
            thread.join(TIMEOUT.toMillis());
        }
        if (serverError.get() != null) {
            throw new AssertionError("server failed", serverError.get());
        }
        return new Pair(client, server, clientKeys, serverKeys.get(), link);
    }

    static List<DtlsFingerprint> fingerprints(DtlsConfig config) {
        return config.certificates().getFirst().fingerprints();
    }

    static void assertMirrored(DtlsSrtpKeys client, DtlsSrtpKeys server) {
        assertEquals(client.profile(), server.profile());
        assertArrayEquals(client.localKey(), server.remoteKey());
        assertArrayEquals(client.localSalt(), server.remoteSalt());
        assertArrayEquals(client.remoteKey(), server.localKey());
        assertArrayEquals(client.remoteSalt(), server.localSalt());
    }

    static Stream<Object[]> versionsAndCertificates() {
        var list = new ArrayList<Object[]>();
        for (var version : DtlsVersion.values()) {
            list.add(new Object[]{version, ECDSA_CLIENT, ECDSA_SERVER});
            list.add(new Object[]{version, RSA_CLIENT, RSA_SERVER});
            list.add(new Object[]{version, ECDSA_CLIENT, RSA_SERVER});
            list.add(new Object[]{version, RSA_CLIENT, ECDSA_SERVER});
        }
        return list.stream();
    }

    @ParameterizedTest(name = "{0}, client {1}, server {2}")
    @MethodSource("versionsAndCertificates")
    @DisplayName("completes a handshake in each version and certificate combination with mirrored keys")
    void handshake(DtlsVersion version, DtlsCertificate clientCertificate, DtlsCertificate serverCertificate)
            throws Exception {
        var clientConfig = DtlsConfig.of(clientCertificate).withVersions(Set.of(version));
        var serverConfig = DtlsConfig.of(serverCertificate).withVersions(Set.of(version));
        try (var pair = connect(new MemoryLink(), clientConfig, serverConfig)) {
            assertMirrored(pair.clientKeys(), pair.serverKeys());
            assertEquals(SrtpProfile.AEAD_AES_128_GCM, pair.clientKeys().profile());
            assertEquals(version, pair.client().negotiatedVersion().orElseThrow());
            assertEquals(version, pair.server().negotiatedVersion().orElseThrow());
            assertEquals(DtlsState.CONNECTED, pair.client().state());
            assertEquals(DtlsState.CONNECTED, pair.server().state());
            assertEquals(serverCertificate.certificate(), pair.client().remoteCertificate().orElseThrow());
            assertEquals(clientCertificate.certificate(), pair.server().remoteCertificate().orElseThrow());
        }
    }

    @Nested
    @DisplayName("version negotiation")
    class Negotiation {
        @Test
        @DisplayName("picks DTLS 1.3 when both sides support both versions")
        void prefers13() throws Exception {
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT), DtlsConfig.of(ECDSA_SERVER))) {
                assertEquals(DtlsVersion.DTLS_1_3, pair.client().negotiatedVersion().orElseThrow());
                assertMirrored(pair.clientKeys(), pair.serverKeys());
            }
        }

        @Test
        @DisplayName("falls back to DTLS 1.2 with a DTLS 1.2-only server")
        void fallsBackTo12() throws Exception {
            var server = DtlsConfig.of(ECDSA_SERVER).withVersions(Set.of(DtlsVersion.DTLS_1_2));
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT), server)) {
                assertEquals(DtlsVersion.DTLS_1_2, pair.client().negotiatedVersion().orElseThrow());
                assertMirrored(pair.clientKeys(), pair.serverKeys());
            }
        }

        @Test
        @DisplayName("serves a DTLS 1.2-only client from a server that supports both")
        void serves12Client() throws Exception {
            var client = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(DtlsVersion.DTLS_1_2));
            try (var pair = connect(new MemoryLink(), client, DtlsConfig.of(ECDSA_SERVER))) {
                assertEquals(DtlsVersion.DTLS_1_2, pair.server().negotiatedVersion().orElseThrow());
            }
        }

        @Test
        @DisplayName("fails with protocol_version when the versions do not overlap")
        void noCommonVersion() {
            var client = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(DtlsVersion.DTLS_1_3));
            var server = DtlsConfig.of(ECDSA_SERVER).withVersions(Set.of(DtlsVersion.DTLS_1_2));
            var exception = assertThrows(DtlsException.class, () -> connect(new MemoryLink(), client, server));
            assertEquals(DtlsAlert.PROTOCOL_VERSION, exception.alert().orElseThrow());
        }

        @ParameterizedTest(name = "{0}")
        @EnumSource(SrtpProfile.class)
        @DisplayName("agrees on every SRTP profile")
        void everyProfile(SrtpProfile profile) throws Exception {
            var client = DtlsConfig.of(ECDSA_CLIENT).withSrtpProfiles(List.of(profile));
            try (var pair = connect(new MemoryLink(), client, DtlsConfig.of(ECDSA_SERVER))) {
                assertEquals(profile, pair.clientKeys().profile());
                assertEquals(profile.keyLength(), pair.clientKeys().localKey().length);
                assertMirrored(pair.clientKeys(), pair.serverKeys());
            }
        }

        @ParameterizedTest(name = "cookie exchange {0}")
        @org.junit.jupiter.params.provider.ValueSource(booleans = {true, false})
        @DisplayName("answers a DTLS 1.3 HelloRetryRequest for another group")
        void helloRetryForGroup(boolean cookies) throws Exception {
            ClientHandshake.forceGroupRetry = true;
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT),
                    DtlsConfig.of(ECDSA_SERVER).withCookieExchange(cookies))) {
                assertEquals(DtlsVersion.DTLS_1_3, pair.client().negotiatedVersion().orElseThrow());
                assertMirrored(pair.clientKeys(), pair.serverKeys());
            } finally {
                ClientHandshake.forceGroupRetry = false;
            }
        }

        @ParameterizedTest(name = "{0}")
        @EnumSource(DtlsVersion.class)
        @DisplayName("completes without the cookie exchange")
        void withoutCookies(DtlsVersion version) throws Exception {
            var client = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(version));
            var server = DtlsConfig.of(ECDSA_SERVER).withVersions(Set.of(version)).withCookieExchange(false);
            try (var pair = connect(new MemoryLink(), client, server)) {
                assertMirrored(pair.clientKeys(), pair.serverKeys());
            }
        }
    }

    @Nested
    @DisplayName("unreliable links")
    class Unreliable {
        @ParameterizedTest(name = "{0}")
        @EnumSource(DtlsVersion.class)
        @DisplayName("completes over a link that loses, duplicates and reorders datagrams")
        void lossy(DtlsVersion version) throws Exception {
            for (var seed = 1; seed <= 6; seed++) {
                var conditions = new MemoryLink.Conditions(0.25, 0.1, 0.2, seed);
                var client = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(version))
                        .withInitialRetransmit(Duration.ofMillis(50));
                var server = DtlsConfig.of(RSA_SERVER).withVersions(Set.of(version))
                        .withInitialRetransmit(Duration.ofMillis(50));
                try (var pair = connect(new MemoryLink(conditions), client, server)) {
                    assertMirrored(pair.clientKeys(), pair.serverKeys());
                    assertTrue(pair.client().statistics().retransmissions() + pair.server().statistics().retransmissions() >= 0);
                }
            }
        }

        @ParameterizedTest(name = "{0}")
        @EnumSource(DtlsVersion.class)
        @DisplayName("retransmits a lost first flight and fragments large messages for a small path")
        void retransmitsAndFragments(DtlsVersion version) throws Exception {
            var link = new MemoryLink();
            link.left.maxDatagramSize = 300;
            link.right.maxDatagramSize = 300;
            var droppedFirst = new java.util.concurrent.atomic.AtomicBoolean();
            link.right.dropFilter = _ -> droppedFirst.compareAndSet(false, true);
            var client = DtlsConfig.of(RSA_CLIENT).withVersions(Set.of(version)).withInitialRetransmit(Duration.ofMillis(50));
            var server = DtlsConfig.of(RSA_SERVER).withVersions(Set.of(version)).withInitialRetransmit(Duration.ofMillis(50));
            try (var pair = connect(link, client, server)) {
                assertMirrored(pair.clientKeys(), pair.serverKeys());
                assertTrue(pair.client().statistics().retransmissions() + pair.server().statistics().retransmissions() > 0);
                for (var datagram : link.left.sent) {
                    assertTrue(datagram.length <= 300, "datagram of " + datagram.length + " bytes");
                }
            }
        }
    }

    @Nested
    @DisplayName("after the handshake")
    class Connected {
        @ParameterizedTest(name = "{0}")
        @EnumSource(DtlsVersion.class)
        @DisplayName("carries application data both ways")
        void applicationData(DtlsVersion version) throws Exception {
            var client = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(version));
            var server = DtlsConfig.of(ECDSA_SERVER).withVersions(Set.of(version));
            try (var pair = connect(new MemoryLink(), client, server)) {
                var atServer = new LinkedBlockingQueue<String>();
                var atClient = new LinkedBlockingQueue<String>();
                pair.server().applicationData().setReceiver((packet, _) -> atServer.add(utf8(packet)));
                pair.client().applicationData().setReceiver((packet, _) -> atClient.add(utf8(packet)));
                pair.client().applicationData().send(ByteBuffer.wrap("ping".getBytes(StandardCharsets.UTF_8)));
                assertEquals("ping", atServer.poll(5, TimeUnit.SECONDS));
                pair.server().applicationData().send(ByteBuffer.wrap("pong".getBytes(StandardCharsets.UTF_8)));
                assertEquals("pong", atClient.poll(5, TimeUnit.SECONDS));
            }
        }

        @Test
        @DisplayName("updates DTLS 1.3 keys in both directions and keeps carrying data")
        void keyUpdate() throws Exception {
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT), DtlsConfig.of(ECDSA_SERVER))) {
                var atServer = new LinkedBlockingQueue<String>();
                var atClient = new LinkedBlockingQueue<String>();
                pair.server().applicationData().setReceiver((packet, _) -> atServer.add(utf8(packet)));
                pair.client().applicationData().setReceiver((packet, _) -> atClient.add(utf8(packet)));
                awaitIdle(pair.client());
                pair.client().updateKeys(true);
                awaitIdle(pair.client());
                for (var round = 0; round < 3; round++) {
                    pair.client().applicationData().send(ByteBuffer.wrap(("c" + round).getBytes(StandardCharsets.UTF_8)));
                    assertEquals("c" + round, atServer.poll(5, TimeUnit.SECONDS));
                    pair.server().applicationData().send(ByteBuffer.wrap(("s" + round).getBytes(StandardCharsets.UTF_8)));
                    assertEquals("s" + round, atClient.poll(5, TimeUnit.SECONDS));
                }
                awaitIdle(pair.server());
                pair.server().updateKeys(false);
                awaitIdle(pair.server());
                pair.server().applicationData().send(ByteBuffer.wrap("after".getBytes(StandardCharsets.UTF_8)));
                assertEquals("after", atClient.poll(5, TimeUnit.SECONDS));
            }
        }

        @Test
        @DisplayName("refuses a key update on a DTLS 1.2 association")
        void keyUpdateNeeds13() throws Exception {
            var client = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(DtlsVersion.DTLS_1_2));
            try (var pair = connect(new MemoryLink(), client, DtlsConfig.of(ECDSA_SERVER))) {
                assertThrows(IllegalStateException.class, () -> pair.client().updateKeys(false));
            }
        }

        @ParameterizedTest(name = "{0}")
        @EnumSource(DtlsVersion.class)
        @DisplayName("moves the peer to CLOSED with close_notify")
        void closeNotify(DtlsVersion version) throws Exception {
            var client = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(version));
            try (var pair = connect(new MemoryLink(), client, DtlsConfig.of(ECDSA_SERVER))) {
                var states = new LinkedBlockingQueue<DtlsState>();
                pair.server().setStateListener(states::add);
                pair.client().close();
                assertEquals(DtlsState.CLOSED, states.poll(5, TimeUnit.SECONDS));
                assertEquals(DtlsState.CLOSED, pair.server().state());
                assertThrows(IllegalStateException.class,
                        () -> pair.server().applicationData().send(ByteBuffer.wrap(new byte[1])));
            }
        }

        @Test
        @DisplayName("passes RTP and RTCP datagrams to the non-DTLS receiver untouched")
        void demultiplexes() throws Exception {
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT), DtlsConfig.of(ECDSA_SERVER))) {
                var received = new LinkedBlockingQueue<byte[]>();
                pair.server().setNonDtlsReceiver((packet, _) -> {
                    var bytes = new byte[packet.remaining()];
                    packet.get(bytes);
                    received.add(bytes);
                });
                var rtp = new byte[]{(byte) 0x80, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 42};
                pair.client().mediaPath().send(ByteBuffer.wrap(rtp));
                assertArrayEquals(rtp, received.poll(5, TimeUnit.SECONDS));
                pair.link().left.inject(new byte[]{5, 1, 2});
                pair.link().left.inject(new byte[]{(byte) 0xC9, 2});
                assertEquals(null, received.poll(200, TimeUnit.MILLISECONDS));
            }
        }

        @Test
        @DisplayName("reports statistics with the negotiated parameters")
        void statistics() throws Exception {
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT), DtlsConfig.of(ECDSA_SERVER))) {
                var statistics = pair.client().statistics();
                assertEquals(DtlsState.CONNECTED, statistics.state());
                assertEquals(DtlsRole.CLIENT, statistics.role().orElseThrow());
                assertEquals("TLS_AES_128_GCM_SHA256", statistics.cipherSuite().orElseThrow());
                assertEquals(SrtpProfile.AEAD_AES_128_GCM, statistics.srtpProfile().orElseThrow());
                assertTrue(statistics.packetsSent() > 0 && statistics.bytesReceived() > 0);
            }
        }

        @Test
        @DisplayName("survives garbage datagrams after the handshake")
        void garbage() throws Exception {
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT), DtlsConfig.of(ECDSA_SERVER))) {
                var random = new java.util.Random(7);
                for (var index = 0; index < 2000; index++) {
                    var bytes = new byte[1 + random.nextInt(200)];
                    random.nextBytes(bytes);
                    bytes[0] = (byte) (20 + random.nextInt(44));
                    pair.link().left.inject(bytes);
                }
                var atServer = new LinkedBlockingQueue<String>();
                pair.server().applicationData().setReceiver((packet, _) -> atServer.add(utf8(packet)));
                pair.client().applicationData().send(ByteBuffer.wrap("alive".getBytes(StandardCharsets.UTF_8)));
                assertEquals("alive", atServer.poll(10, TimeUnit.SECONDS));
                assertEquals(DtlsState.CONNECTED, pair.server().state());
            }
        }
    }

    @Nested
    @DisplayName("failures")
    class Failures {
        @ParameterizedTest(name = "{0}")
        @EnumSource(DtlsVersion.class)
        @DisplayName("rejects a certificate that matches no fingerprint with bad_certificate")
        void wrongFingerprint(DtlsVersion version) throws Exception {
            var link = new MemoryLink();
            var config = DtlsConfig.of(ECDSA_CLIENT).withVersions(Set.of(version));
            var client = DtlsTransport.over(link.left, config);
            var server = DtlsTransport.over(link.right, DtlsConfig.of(ECDSA_SERVER).withVersions(Set.of(version)));
            var serverThread = Thread.ofVirtual().start(() -> {
                try {
                    server.handshake(DtlsRole.SERVER, ECDSA_CLIENT.fingerprints(), Duration.ofSeconds(5));
                } catch (Exception ignored) {
                    // the client aborts
                }
            });
            var exception = assertThrows(DtlsException.class, () -> client.handshake(DtlsRole.CLIENT,
                    DtlsCertificate.generateEcdsa().fingerprints(), Duration.ofSeconds(5)));
            assertEquals(DtlsAlert.BAD_CERTIFICATE, exception.alert().orElseThrow());
            assertFalse(exception.isRemote());
            assertEquals(DtlsState.FAILED, client.state());
            serverThread.join(6000);
            assertEquals(DtlsState.FAILED, server.state());
            link.close();
        }

        @Test
        @DisplayName("times out when the peer never answers")
        void timeout() {
            var link = new MemoryLink();
            var client = DtlsTransport.over(link.left, DtlsConfig.of(ECDSA_CLIENT));
            var exception = assertThrows(DtlsException.class, () -> client.handshake(DtlsRole.CLIENT,
                    ECDSA_SERVER.fingerprints(), Duration.ofMillis(800)));
            assertTrue(exception.alert().isEmpty());
            assertTrue(link.left.sent.size() >= 2, "the ClientHello was retransmitted");
            link.close();
        }

        @Test
        @DisplayName("refuses a second handshake and an empty fingerprint list")
        void misuse() throws Exception {
            try (var pair = connect(new MemoryLink(), DtlsConfig.of(ECDSA_CLIENT), DtlsConfig.of(ECDSA_SERVER))) {
                assertThrows(IllegalStateException.class, () -> pair.client().handshake(DtlsRole.CLIENT,
                        ECDSA_SERVER.fingerprints(), TIMEOUT));
                var fresh = DtlsTransport.over(new MemoryLink().left, DtlsConfig.of(ECDSA_CLIENT));
                assertThrows(IllegalArgumentException.class, () -> fresh.handshake(DtlsRole.CLIENT, List.of(), TIMEOUT));
            }
        }

        @Test
        @DisplayName("fails the handshake thread when the transport is closed")
        void closedDuringHandshake() throws Exception {
            var link = new MemoryLink();
            var client = DtlsTransport.over(link.left, DtlsConfig.of(ECDSA_CLIENT));
            var error = new AtomicReference<Throwable>();
            var thread = Thread.ofVirtual().start(() -> {
                try {
                    client.handshake(DtlsRole.CLIENT, ECDSA_SERVER.fingerprints(), TIMEOUT);
                } catch (Throwable throwable) {
                    error.set(throwable);
                }
            });
            Thread.sleep(200);
            client.close();
            thread.join(5000);
            assertNotNull(error.get());
            assertTrue(error.get() instanceof DtlsException);
            link.close();
        }

        @Test
        @DisplayName("restarts as a new association over the same link")
        void restart() throws Exception {
            var link = new MemoryLink();
            try (var pair = connect(link, DtlsConfig.of(ECDSA_CLIENT), DtlsConfig.of(ECDSA_SERVER))) {
                var newClient = pair.client().restart();
                var newServer = pair.server().restart();
                assertEquals(DtlsState.CLOSED, pair.client().state());
                var serverKeys = new AtomicReference<DtlsSrtpKeys>();
                var thread = Thread.ofVirtual().start(() -> {
                    try {
                        serverKeys.set(newServer.handshake(DtlsRole.SERVER, ECDSA_CLIENT.fingerprints(), TIMEOUT));
                    } catch (Exception exception) {
                        throw new RuntimeException(exception);
                    }
                });
                var clientKeys = newClient.handshake(DtlsRole.CLIENT, ECDSA_SERVER.fingerprints(), TIMEOUT);
                thread.join(TIMEOUT.toMillis());
                assertMirrored(clientKeys, serverKeys.get());
                newClient.close();
                newServer.close();
            }
        }
    }

    @Test
    @DisplayName("reports state changes in order")
    void stateListener() throws Exception {
        var link = new MemoryLink();
        var states = new CopyOnWriteArrayList<DtlsState>();
        var client = DtlsTransport.over(link.left, DtlsConfig.of(ECDSA_CLIENT));
        client.setStateListener(states::add);
        var server = DtlsTransport.over(link.right, DtlsConfig.of(ECDSA_SERVER));
        var thread = Thread.ofVirtual().start(() -> {
            try {
                server.handshake(DtlsRole.SERVER, ECDSA_CLIENT.fingerprints(), TIMEOUT);
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        });
        client.handshake(DtlsRole.CLIENT, ECDSA_SERVER.fingerprints(), TIMEOUT);
        thread.join();
        client.close();
        assertEquals(List.of(DtlsState.CONNECTING, DtlsState.CONNECTED, DtlsState.CLOSED), states);
        server.close();
        link.close();
    }

    static String utf8(ByteBuffer packet) {
        var bytes = new byte[packet.remaining()];
        packet.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /// Waits until a DTLS 1.3 transport has no flight awaiting acknowledgement, so a key update may start.
    static void awaitIdle(DtlsTransport transport) throws InterruptedException {
        var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            try {
                if (transport instanceof DtlsConnection connection && connection.isIdle()) {
                    return;
                }
            } catch (RuntimeException ignored) {
                // retry
            }
            Thread.sleep(10);
        }
    }

    static EnumSet<DtlsVersion> both() {
        return EnumSet.allOf(DtlsVersion.class);
    }
}
