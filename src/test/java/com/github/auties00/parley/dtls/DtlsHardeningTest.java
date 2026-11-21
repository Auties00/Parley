package com.github.auties00.parley.dtls;

import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Regression tests for unauthenticated input reaching a DTLS association (spoofed epoch-0 records after and before
/// the handshake, pre-verification allocation), DTLS 1.3 epoch retention and partial-flight acknowledgements, and the
/// threading of application data delivery and close.
@DisplayName("DtlsTransport hardening")
class DtlsHardeningTest {
    private static final DtlsCertificate CLIENT = DtlsCertificate.generateEcdsa();
    private static final DtlsCertificate SERVER = DtlsCertificate.generateEcdsa();
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private static DtlsTransportTest.Pair connect(DtlsVersion version) throws Exception {
        return DtlsTransportTest.connect(new MemoryLink(), DtlsConfig.of(CLIENT).withVersions(Set.of(version)),
                DtlsConfig.of(SERVER).withVersions(Set.of(version)));
    }

    /// Hands a datagram to a transport as if its lower transport delivered it, on the calling thread.
    private static void deliver(DtlsTransport transport, byte[] datagram) throws Exception {
        Method method = DtlsConnection.class.getDeclaredMethod("onLowerPacket", ByteBuffer.class, long.class);
        method.setAccessible(true);
        method.invoke(transport, ByteBuffer.wrap(datagram), System.nanoTime());
    }

    /// Checks that application data still flows from the client to the server.
    private static void assertCarriesData(DtlsTransportTest.Pair pair) throws Exception {
        var received = new CountDownLatch(1);
        pair.server().applicationData().setReceiver((packet, arrivalNanos) -> received.countDown());
        pair.client().applicationData().send(ByteBuffer.wrap(new byte[]{1, 2, 3}));
        assertTrue(received.await(5, TimeUnit.SECONDS), "application data no longer flows");
    }

    @Nested
    @DisplayName("spoofed epoch-0 records after the handshake")
    class AfterHandshake {
        @ParameterizedTest
        @EnumSource(DtlsVersion.class)
        @DisplayName("ignores a plaintext close_notify or fatal alert")
        void plaintextAlert(DtlsVersion version) throws Exception {
            for (var code : List.of("00", "28")) {
                try (var pair = connect(version)) {
                    pair.link().left.inject(HexFormat.of().parseHex("15fefd0000000000001000" + "0002" + "02" + code));
                    Thread.sleep(100);
                    assertEquals(DtlsState.CONNECTED, pair.server().state(), "alert " + code);
                    assertCarriesData(pair);
                }
            }
        }

        @ParameterizedTest
        @EnumSource(DtlsVersion.class)
        @DisplayName("ignores a plaintext handshake record with an impossible length")
        void plaintextHandshake(DtlsVersion version) throws Exception {
            try (var pair = connect(version)) {
                pair.link().left.inject(HexFormat.of()
                        .parseHex("16fefd0000000000002000" + "000c" + "01ffffff" + "0009" + "000000" + "000000"));
                Thread.sleep(100);
                assertEquals(DtlsState.CONNECTED, pair.server().state());
                assertCarriesData(pair);
            }
        }

        @ParameterizedTest
        @EnumSource(DtlsVersion.class)
        @DisplayName("stays connected through mutated copies of captured records")
        void fuzzEstablished(DtlsVersion version) throws Exception {
            try (var pair = connect(version)) {
                var link = pair.link();
                for (var index = 0; index < 5; index++) {
                    pair.client().applicationData().send(ByteBuffer.wrap(new byte[]{(byte) index, 2, 3}));
                }
                Thread.sleep(100);
                List<byte[]> seeds;
                synchronized (link.left.sent) {
                    seeds = new ArrayList<>(link.left.sent);
                }
                var random = new java.util.Random(25);
                for (var round = 0; round < 20_000; round++) {
                    var datagram = seeds.get(random.nextInt(seeds.size())).clone();
                    switch (random.nextInt(4)) {
                        case 0 -> datagram[random.nextInt(datagram.length)] ^= (byte) (1 << random.nextInt(8));
                        case 1 -> datagram[random.nextInt(datagram.length)] = (byte) random.nextInt(256);
                        case 2 -> datagram = java.util.Arrays.copyOf(datagram, random.nextInt(datagram.length + 1));
                        default -> {
                            datagram[0] = (byte) (20 + random.nextInt(7));
                            datagram[3] = 0;
                            datagram[4] = 0;
                        }
                    }
                    deliver(pair.server(), datagram);
                }
                assertEquals(DtlsState.CONNECTED, pair.server().state());
                assertCarriesData(pair);
            }
        }

        @Test
        @DisplayName("keeps at most two DTLS 1.3 read epochs across many key updates without data")
        void keyUpdateFlood() throws Exception {
            try (var pair = connect(DtlsVersion.DTLS_1_3)) {
                for (var update = 0; update < 20; update++) {
                    DtlsTransportTest.awaitIdle(pair.client());
                    pair.client().updateKeys(false);
                }
                DtlsTransportTest.awaitIdle(pair.client());
                var records = ((DtlsConnection) pair.server()).records();
                assertTrue(records.readEpochCount() <= 3, "read epochs kept: " + records.readEpochCount());
                assertCarriesData(pair);
            }
        }
    }

    @Nested
    @DisplayName("before the handshake completes")
    class BeforeHandshake {
        @ParameterizedTest
        @EnumSource(DtlsVersion.class)
        @DisplayName("drops a malformed epoch-0 fragment instead of failing the handshake")
        void malformedFragment(DtlsVersion version) throws Exception {
            var link = new MemoryLink();
            var server = DtlsTransport.over(link.right, DtlsConfig.of(SERVER).withVersions(Set.of(version)));
            link.left.inject(HexFormat.of().parseHex("16fefd0000000000000000" + "0010" + "01000100" + "0000" + "000000"
                    + "000004" + "aabbccdd"));
            link.left.inject(HexFormat.of().parseHex("16fefd0000000000000001" + "000c" + "01ffffff" + "0000" + "000000"
                    + "000000"));
            var client = DtlsTransport.over(link.left, DtlsConfig.of(CLIENT).withVersions(Set.of(version)));
            var serverError = new AtomicReference<Throwable>();
            var thread = Thread.ofVirtual().start(() -> {
                try {
                    server.handshake(DtlsRole.SERVER, CLIENT.fingerprints(), TIMEOUT);
                } catch (Throwable throwable) {
                    serverError.set(throwable);
                }
            });
            client.handshake(DtlsRole.CLIENT, SERVER.fingerprints(), TIMEOUT);
            thread.join(TIMEOUT.toMillis());
            assertEquals(null, serverError.get());
            assertEquals(DtlsState.CONNECTED, server.state());
            assertTrue(server.statistics().recordsDropped() >= 1);
            client.close();
            server.close();
            link.close();
        }

        @Test
        @DisplayName("buffers only the next message, and no oversized hello, before the peer is verified")
        void preVerificationBound() throws Exception {
            var reassembler = new HandshakeReassembler();
            assertEquals(HandshakeReassembler.Result.DROPPED,
                    reassembler.offer(HandshakeMessage.CERTIFICATE, 100_000, 3, 0, new byte[16], 0));
            assertEquals(HandshakeReassembler.Result.DROPPED,
                    reassembler.offer(HandshakeMessage.CLIENT_HELLO, HandshakeReassembler.MAX_HELLO_LENGTH + 1, 0, 0,
                            new byte[16], 0));
            assertEquals(HandshakeReassembler.Result.ACCEPTED,
                    reassembler.offer(HandshakeMessage.CLIENT_HELLO, 120_000 / 10, 0, 0, new byte[16], 0));
            assertEquals(16, reassembler.bufferedBytes());
            reassembler.relax();
            assertEquals(HandshakeReassembler.Result.ACCEPTED,
                    reassembler.offer(HandshakeMessage.CERTIFICATE, 100_000, 3, 50, new byte[8], 0));
            assertEquals(24, reassembler.bufferedBytes());
        }

        @Test
        @DisplayName("holds only received bytes for overlapping fragments and assembles them in place")
        void lazyBodies() throws Exception {
            var reassembler = new HandshakeReassembler();
            reassembler.relax();
            var body = new byte[64];
            for (var index = 0; index < body.length; index++) {
                body[index] = (byte) index;
            }
            reassembler.offer(HandshakeMessage.CERTIFICATE, 64, 0, 10, java.util.Arrays.copyOfRange(body, 10, 40), 0);
            reassembler.offer(HandshakeMessage.CERTIFICATE, 64, 0, 0, java.util.Arrays.copyOfRange(body, 0, 30), 0);
            reassembler.offer(HandshakeMessage.CERTIFICATE, 64, 0, 0, java.util.Arrays.copyOfRange(body, 0, 30), 0);
            assertEquals(40, reassembler.bufferedBytes());
            assertTrue(reassembler.poll().isEmpty());
            reassembler.offer(HandshakeMessage.CERTIFICATE, 64, 0, 35, java.util.Arrays.copyOfRange(body, 35, 64), 0);
            var message = reassembler.poll().orElseThrow();
            assertTrue(java.util.Arrays.equals(body, message.message().body()));
        }

        @Test
        @DisplayName("sends application data only once connected, failing with ClosedChannelException otherwise")
        void sendBeforeConnected() throws Exception {
            var link = new MemoryLink();
            var transport = DtlsTransport.over(link.left, DtlsConfig.of(CLIENT));
            assertThrows(ClosedChannelException.class,
                    () -> transport.applicationData().send(ByteBuffer.wrap(new byte[]{1})));
            transport.close();
            assertThrows(ClosedChannelException.class,
                    () -> transport.applicationData().send(ByteBuffer.wrap(new byte[]{1})));
            link.close();
        }

        @Test
        @DisplayName("acknowledges a partially received DTLS 1.3 flight before the peer retransmits it")
        void acknowledgesPartialFlight() throws Exception {
            var link = new MemoryLink();
            link.right.maxDatagramSize = 300;
            var serverDatagrams = new AtomicInteger();
            link.right.dropFilter = bytes -> (bytes[0] & 0xE0) == 0x20 && serverDatagrams.incrementAndGet() == 2;
            var config13 = Set.of(DtlsVersion.DTLS_1_3);
            var retransmit = Duration.ofSeconds(2);
            try (var pair = DtlsTransportTest.connect(link,
                    DtlsConfig.of(CLIENT).withVersions(config13).withInitialRetransmit(retransmit).withCookieExchange(false),
                    DtlsConfig.of(SERVER).withVersions(config13).withInitialRetransmit(retransmit).withCookieExchange(false))) {
                var acknowledgements = 0;
                synchronized (link.left.sent) {
                    for (var datagram : link.left.sent) {
                        if ((datagram[0] & 0xE0) == 0x20 && datagram.length < 120) {
                            acknowledgements++;
                        }
                    }
                }
                assertTrue(acknowledgements >= 1, "the client sent no acknowledgement of the partial flight");
                assertEquals(DtlsState.CONNECTED, pair.client().state());
            }
        }
    }

    @Nested
    @DisplayName("threading")
    class Threading {
        @Test
        @DisplayName("delivers application data from two reader threads one at a time")
        void singleDrainer() throws Exception {
            try (var pair = connect(DtlsVersion.DTLS_1_2)) {
                var link = pair.link();
                var mark = link.left.sent.size();
                link.right.setReceiver((packet, arrivalNanos) -> {
                });
                var count = 60;
                for (var index = 0; index < count; index++) {
                    pair.client().applicationData().send(ByteBuffer.wrap(new byte[]{(byte) index}));
                }
                List<byte[]> records;
                synchronized (link.left.sent) {
                    records = new ArrayList<>(link.left.sent.subList(mark, link.left.sent.size()));
                }
                var inFlight = new AtomicInteger();
                var overlap = new AtomicInteger();
                var received = Collections.synchronizedList(new ArrayList<Integer>());
                pair.server().applicationData().setReceiver((packet, arrivalNanos) -> {
                    if (inFlight.incrementAndGet() > 1) {
                        overlap.incrementAndGet();
                    }
                    received.add(packet.get(packet.position()) & 0xFF);
                    try {
                        Thread.sleep(0, 200_000);
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                    }
                    inFlight.decrementAndGet();
                });
                var start = new CountDownLatch(1);
                var threads = new ArrayList<Thread>();
                for (var reader = 0; reader < 2; reader++) {
                    var parity = reader;
                    threads.add(Thread.ofPlatform().start(() -> {
                        try {
                            start.await();
                            for (var index = parity; index < records.size(); index += 2) {
                                deliver(pair.server(), records.get(index));
                            }
                        } catch (Exception exception) {
                            throw new RuntimeException(exception);
                        }
                    }));
                }
                start.countDown();
                for (var thread : threads) {
                    thread.join();
                }
                var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                while (received.size() < count && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
                assertEquals(count, received.size());
                assertEquals(0, overlap.get(), "the receiver ran on two threads at once");
            }
        }

        @Test
        @DisplayName("wakes a blocked handshake on close even after a flood filled the inbound queue")
        void closeAfterFlood() throws Exception {
            var silent = new DatagramTransport() {
                private final List<PacketReceiver> receivers = new CopyOnWriteArrayList<>();

                @Override
                public void send(ByteBuffer datagram) {
                }

                @Override
                public void setReceiver(PacketReceiver receiver) {
                    receivers.add(receiver);
                }

                @Override
                public int maxDatagramSize() {
                    return 1500;
                }

                @Override
                public void close() {
                }
            };
            var server = DtlsTransport.over(silent, DtlsConfig.of(SERVER).withInitialRetransmit(Duration.ofSeconds(30)));
            var failed = new CountDownLatch(1);
            var thread = Thread.ofVirtual().start(() -> {
                try {
                    server.handshake(DtlsRole.SERVER, CLIENT.fingerprints(), Duration.ofSeconds(60));
                } catch (DtlsException | InterruptedException exception) {
                    failed.countDown();
                }
            });
            Thread.sleep(50);
            var garbage = HexFormat.of().parseHex("17fefd000100000000000000020000");
            for (var index = 0; index < 2_000; index++) {
                deliver(server, garbage);
            }
            server.close();
            assertTrue(failed.await(2, TimeUnit.SECONDS), "the handshake did not notice the close");
            thread.join();
            assertFalse(thread.isAlive());
        }
    }

    /// Restarts an association in both roles and versions, the new transport taking the opposite role.
    @ParameterizedTest
    @EnumSource(DtlsVersion.class)
    @DisplayName("restarts in both versions with the roles swapped")
    void restartSwapsRoles(DtlsVersion version) throws Exception {
        try (var pair = connect(version)) {
            var newClient = pair.server().restart();
            var newServer = pair.client().restart();
            var serverKeys = new AtomicReference<DtlsSrtpKeys>();
            var thread = Thread.ofVirtual().start(() -> {
                try {
                    serverKeys.set(newServer.handshake(DtlsRole.SERVER, SERVER.fingerprints(), TIMEOUT));
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
            var clientKeys = newClient.handshake(DtlsRole.CLIENT, CLIENT.fingerprints(), TIMEOUT);
            thread.join(TIMEOUT.toMillis());
            DtlsTransportTest.assertMirrored(clientKeys, serverKeys.get());
            assertEquals(version, newClient.negotiatedVersion().orElseThrow());
            newClient.close();
            newServer.close();
        }
    }
}
