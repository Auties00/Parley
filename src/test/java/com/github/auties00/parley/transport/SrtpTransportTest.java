package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsConfig;
import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.dtls.MemoryLink;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.sdp.SdesCrypto;
import com.github.auties00.srtp.SrtpCryptoSuite;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers [SrtpTransport] keyed with SDES and with DTLS-SRTP over an in-memory link: every suite, in-place and
/// copied protection, per-SSRC contexts, replay and tamper rejection, reduced-size RTCP, cryptex and malformed input.
@DisplayName("SrtpTransport")
class SrtpTransportTest {
    /// The SDES keys of both sides of a suite, mirrored.
    record Keys(byte[] key1, byte[] salt1, byte[] key2, byte[] salt2) {
        static Keys of(SrtpCryptoSuite suite, long seed) {
            var random = new Random(seed);
            var key1 = new byte[suite.masterKeyLength()];
            var salt1 = new byte[suite.masterSaltLength()];
            var key2 = new byte[suite.masterKeyLength()];
            var salt2 = new byte[suite.masterSaltLength()];
            random.nextBytes(key1);
            random.nextBytes(salt1);
            random.nextBytes(key2);
            random.nextBytes(salt2);
            return new Keys(key1, salt1, key2, salt2);
        }

        /// {@return the `a=crypto` line of the first key and salt}
        SdesCrypto first(SrtpCryptoSuite suite) {
            return crypto(suite, key1, salt1);
        }

        /// {@return the `a=crypto` line of the second key and salt}
        SdesCrypto second(SrtpCryptoSuite suite) {
            return crypto(suite, key2, salt2);
        }

        private static SdesCrypto crypto(SrtpCryptoSuite suite, byte[] key, byte[] salt) {
            var material = new byte[key.length + salt.length];
            System.arraycopy(key, 0, material, 0, key.length);
            System.arraycopy(salt, 0, material, key.length, salt.length);
            return new SdesCrypto(1, suite, material);
        }
    }

    /// Two SDES transports over a link, with queues of what each receives.
    record Pair(SrtpTransport left, SrtpTransport right, MemoryLink link, LinkedBlockingQueue<byte[]> rtpAtRight,
                LinkedBlockingQueue<byte[]> rtcpAtRight, LinkedBlockingQueue<byte[]> rtpAtLeft) implements AutoCloseable {
        static Pair sdes(SrtpCryptoSuite suite, SrtpOptions options) {
            var link = new MemoryLink();
            var keys = Keys.of(suite, 42);
            var left = SrtpTransport.sdes(link.left, keys.first(suite), keys.second(suite), options);
            var right = SrtpTransport.sdes(link.right, keys.second(suite), keys.first(suite), options);
            return wire(left, right, link);
        }

        static Pair wire(SrtpTransport left, SrtpTransport right, MemoryLink link) {
            var rtpAtRight = new LinkedBlockingQueue<byte[]>();
            var rtcpAtRight = new LinkedBlockingQueue<byte[]>();
            var rtpAtLeft = new LinkedBlockingQueue<byte[]>();
            right.setRtpReceiver((packet, _) -> rtpAtRight.add(bytes(packet)));
            right.setRtcpReceiver((packet, _) -> rtcpAtRight.add(bytes(packet)));
            left.setRtpReceiver((packet, _) -> rtpAtLeft.add(bytes(packet)));
            return new Pair(left, right, link, rtpAtRight, rtcpAtRight, rtpAtLeft);
        }

        @Override
        public void close() {
            left.close();
            right.close();
            link.close();
        }
    }

    static byte[] rtp(long ssrc, int sequence, int payloadLength) {
        var packet = ByteBuffer.allocate(12 + payloadLength);
        packet.put((byte) 0x80).put((byte) 111).putShort((short) sequence).putInt(sequence * 960).putInt((int) ssrc);
        for (var index = 0; index < payloadLength; index++) {
            packet.put((byte) (index * 7 + sequence));
        }
        return packet.array();
    }

    static byte[] senderReport(long ssrc) {
        return ByteBuffer.allocate(28).put((byte) 0x80).put((byte) 200).putShort((short) 6).putInt((int) ssrc)
                .putLong(0x1122334455667788L).putInt(1234).putInt(5).putInt(500).array();
    }

    static byte[] pli(long sender, long media) {
        return ByteBuffer.allocate(12).put((byte) 0x81).put((byte) 206).putShort((short) 2).putInt((int) sender)
                .putInt((int) media).array();
    }

    static byte[] bytes(ByteBuffer packet) {
        var bytes = new byte[packet.remaining()];
        packet.get(bytes);
        return bytes;
    }

    static ByteBuffer withTailroom(byte[] packet, int tailroom) {
        var buffer = ByteBuffer.allocate(packet.length + tailroom);
        buffer.put(packet).flip();
        return buffer;
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = SrtpCryptoSuite.class, names = {"AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32",
            "AES_256_CM_HMAC_SHA1_80", "AES_256_CM_HMAC_SHA1_32", "AEAD_AES_128_GCM", "AEAD_AES_256_GCM"})
    @DisplayName("round-trips RTP, RTCP and reduced-size RTCP with SDES keys")
    void sdesRoundTrip(SrtpCryptoSuite suite) throws Exception {
        try (var pair = Pair.sdes(suite, SrtpOptions.DEFAULT)) {
            for (var sequence = 0; sequence < 20; sequence++) {
                var packet = rtp(0x1234, 65530 + sequence, 160);
                pair.left().sendRtp(withTailroom(packet, pair.left().protectionOverhead()));
                assertArrayEquals(packet, pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
            }
            var report = senderReport(0x1234);
            pair.left().sendRtcp(withTailroom(report, pair.left().protectionOverhead()));
            assertArrayEquals(report, pair.rtcpAtRight().poll(5, TimeUnit.SECONDS));
            var feedback = pli(0x1234, 0x9999);
            pair.left().sendRtcp(ByteBuffer.wrap(feedback));
            assertArrayEquals(feedback, pair.rtcpAtRight().poll(5, TimeUnit.SECONDS));
            var reply = rtp(0x5678, 1, 20);
            pair.right().sendRtp(ByteBuffer.wrap(reply));
            assertArrayEquals(reply, pair.rtpAtLeft().poll(5, TimeUnit.SECONDS));
            var statistics = pair.right().statistics();
            assertEquals(suite, statistics.suite().orElseThrow());
            assertEquals(20, statistics.rtpPacketsReceived());
            assertEquals(2, statistics.rtcpPacketsReceived());
            assertEquals(0, statistics.authenticationFailures());
        }
    }

    @Nested
    @DisplayName("buffers")
    class Buffers {
        @Test
        @DisplayName("protects in place when the buffer has tailroom, leaving position and limit alone")
        void inPlace() throws Exception {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, SrtpOptions.DEFAULT)) {
                var packet = rtp(1, 1, 100);
                var buffer = withTailroom(packet, pair.left().protectionOverhead());
                pair.left().sendRtp(buffer);
                assertEquals(0, buffer.position());
                assertEquals(packet.length, buffer.limit());
                var wire = pair.link().left.sent.getLast();
                assertEquals(packet.length + 10, wire.length);
                assertArrayEquals(wire, Arrays.copyOf(buffer.array(), wire.length));
                assertArrayEquals(packet, pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
            }
        }

        @Test
        @DisplayName("protects a copy of a read-only or tight buffer and leaves it untouched")
        void copied() throws Exception {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AEAD_AES_128_GCM, SrtpOptions.DEFAULT)) {
                var packet = rtp(1, 1, 100);
                var readOnly = ByteBuffer.wrap(packet.clone()).asReadOnlyBuffer();
                pair.left().sendRtp(readOnly);
                assertArrayEquals(packet, pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
                var tight = ByteBuffer.wrap(rtp(1, 2, 100));
                pair.left().sendRtp(tight);
                assertArrayEquals(rtp(1, 2, 100), tight.array());
                assertArrayEquals(rtp(1, 2, 100), pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
                var direct = ByteBuffer.allocateDirect(112).put(rtp(1, 3, 100)).flip();
                pair.left().sendRtp(direct);
                assertArrayEquals(rtp(1, 3, 100), pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
            }
        }

        @Test
        @DisplayName("rejects packets too short to be RTP or RTCP")
        void tooShort() {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AEAD_AES_128_GCM, SrtpOptions.DEFAULT)) {
                assertThrows(IllegalArgumentException.class, () -> pair.left().sendRtp(ByteBuffer.wrap(new byte[11])));
                assertThrows(IllegalArgumentException.class, () -> pair.left().sendRtcp(ByteBuffer.wrap(new byte[7])));
            }
        }
    }

    @Nested
    @DisplayName("receiving")
    class Receiving {
        @Test
        @DisplayName("keeps one context per SSRC")
        void perSsrc() throws Exception {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, SrtpOptions.DEFAULT)) {
                for (var sequence = 0; sequence < 10; sequence++) {
                    for (var ssrc : new long[]{1, 2, 0xFFFFFFFFL}) {
                        var packet = rtp(ssrc, sequence * 1000, 30);
                        pair.left().sendRtp(ByteBuffer.wrap(packet));
                        assertArrayEquals(packet, pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
                    }
                }
            }
        }

        @Test
        @DisplayName("drops replayed packets and counts them")
        void replay() throws Exception {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AEAD_AES_256_GCM, SrtpOptions.DEFAULT)) {
                pair.left().sendRtp(ByteBuffer.wrap(rtp(7, 1, 40)));
                assertNotNull(pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
                pair.link().left.inject(pair.link().left.sent.getLast());
                assertNull(pair.rtpAtRight().poll(300, TimeUnit.MILLISECONDS));
                assertEquals(1, pair.right().statistics().replayedPackets());
            }
        }

        @Test
        @DisplayName("accepts replays when replay protection is off")
        void replayAllowed() throws Exception {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AEAD_AES_256_GCM, SrtpOptions.DEFAULT.withReplayProtection(false))) {
                pair.left().sendRtp(ByteBuffer.wrap(rtp(7, 1, 40)));
                assertNotNull(pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
                pair.link().left.inject(pair.link().left.sent.getLast());
                assertNotNull(pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
            }
        }

        @Test
        @DisplayName("drops tampered packets and counts them since the last authenticated one")
        void tampered() throws Exception {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, SrtpOptions.DEFAULT)) {
                pair.link().left.dropFilter = _ -> true;
                for (var sequence = 0; sequence < 3; sequence++) {
                    pair.left().sendRtp(ByteBuffer.wrap(rtp(7, sequence, 40)));
                    var wire = pair.link().left.sent.getLast().clone();
                    wire[20] ^= 1;
                    pair.link().left.inject(wire);
                }
                var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                while (pair.right().statistics().authenticationFailures() < 3 && System.nanoTime() < deadline) {
                    Thread.sleep(5);
                }
                assertEquals(3, pair.right().statistics().authenticationFailures());
                assertEquals(3, pair.right().failuresSinceAuthenticated());
                pair.link().left.dropFilter = null;
                pair.left().sendRtp(ByteBuffer.wrap(rtp(7, 10, 40)));
                assertNotNull(pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
                assertEquals(0, pair.right().failuresSinceAuthenticated());
            }
        }

        @Test
        @DisplayName("survives random datagrams")
        void fuzz() throws Exception {
            try (var pair = Pair.sdes(SrtpCryptoSuite.AEAD_AES_128_GCM, SrtpOptions.DEFAULT)) {
                var random = new Random(3);
                for (var index = 0; index < 5000; index++) {
                    var bytes = new byte[random.nextInt(120)];
                    random.nextBytes(bytes);
                    if (bytes.length > 0) {
                        bytes[0] = (byte) (0x80 | (bytes[0] & 0x3F));
                    }
                    pair.link().left.inject(bytes);
                }
                var packet = rtp(9, 9, 9);
                pair.left().sendRtp(ByteBuffer.wrap(packet));
                byte[] received;
                do {
                    received = pair.rtpAtRight().poll(10, TimeUnit.SECONDS);
                    assertNotNull(received);
                } while (!Arrays.equals(packet, received));
                var statistics = pair.right().statistics();
                assertTrue(statistics.authenticationFailures() + statistics.malformedPackets() > 0);
            }
        }
    }

    @Test
    @DisplayName("encrypts header extensions and CSRCs with cryptex")
    void cryptex() throws Exception {
        try (var pair = Pair.sdes(SrtpCryptoSuite.AEAD_AES_128_GCM, SrtpOptions.DEFAULT.withCryptex(true))) {
            var packet = ByteBuffer.allocate(12 + 4 + 8 + 20);
            packet.put((byte) 0x91).put((byte) 96).putShort((short) 5).putInt(900).putInt(0x1234)
                    .putInt(0xCAFEBABE)
                    .putShort((short) 0xBEDE).putShort((short) 1).put((byte) 0x10).put((byte) 0x42).putShort((short) 0);
            for (var index = 0; index < 20; index++) {
                packet.put((byte) index);
            }
            var plain = packet.array();
            pair.left().sendRtp(withTailroom(plain, pair.left().protectionOverhead()));
            assertArrayEquals(plain, pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
            var wire = pair.link().left.sent.getLast();
            assertEquals(0xC0, wire[16] & 0xFF);
            assertEquals(0xDE, wire[17] & 0xFF);
            assertFalse(wire[12] == (byte) 0xCA && wire[13] == (byte) 0xFE, "the CSRC is encrypted");
        }
    }

    @Nested
    @DisplayName("keyed by DTLS-SRTP")
    class DtlsKeyed {
        @ParameterizedTest(name = "{0}")
        @EnumSource(SrtpProfile.class)
        @DisplayName("keys itself after the handshake and carries media both ways")
        void roundTrip(SrtpProfile profile) throws Exception {
            var link = new MemoryLink();
            var clientConfig = DtlsConfig.of(DtlsCertificate.generateEcdsa()).withSrtpProfiles(List.of(profile));
            var serverConfig = DtlsConfig.of(DtlsCertificate.generateEcdsa());
            var client = DtlsTransport.over(link.left, clientConfig);
            var server = DtlsTransport.over(link.right, serverConfig);
            var left = SrtpTransport.dtlsSrtp(client);
            var right = SrtpTransport.dtlsSrtp(server);
            var pair = Pair.wire(left, right, link);
            assertThrows(ClosedChannelException.class, () -> left.sendRtp(ByteBuffer.wrap(rtp(1, 1, 10))));
            assertFalse(left.isKeyed());
            var serverError = new AtomicReference<Throwable>();
            var thread = Thread.ofVirtual().start(() -> {
                try {
                    server.handshake(DtlsRole.SERVER, clientConfig.certificates().getFirst().fingerprints(),
                            Duration.ofSeconds(10));
                } catch (Throwable throwable) {
                    serverError.set(throwable);
                }
            });
            client.handshake(DtlsRole.CLIENT, serverConfig.certificates().getFirst().fingerprints(), Duration.ofSeconds(10));
            thread.join(10_000);
            assertNull(serverError.get());
            assertTrue(left.isKeyed());
            var packet = rtp(0xABCDEF, 100, 200);
            left.sendRtp(ByteBuffer.wrap(packet));
            assertArrayEquals(packet, pair.rtpAtRight().poll(5, TimeUnit.SECONDS));
            var back = rtp(0x123, 7, 50);
            right.sendRtp(ByteBuffer.wrap(back));
            assertArrayEquals(back, pair.rtpAtLeft().poll(5, TimeUnit.SECONDS));
            assertEquals(profile.suite(), left.statistics().suite().orElseThrow());
            pair.close();
            client.close();
            server.close();
        }

        @Test
        @DisplayName("counts media that arrives before the keys")
        void unkeyed() throws Exception {
            var link = new MemoryLink();
            var dtls = DtlsTransport.over(link.right, DtlsConfig.of(DtlsCertificate.generateEcdsa()));
            var srtp = SrtpTransport.dtlsSrtp(dtls);
            var count = new AtomicInteger();
            srtp.setRtpReceiver((_, _) -> count.incrementAndGet());
            link.left.inject(rtp(1, 1, 30));
            var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (srtp.statistics().unkeyedPackets() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            assertEquals(1, srtp.statistics().unkeyedPackets());
            assertEquals(0, count.get());
            dtls.close();
            link.close();
        }
    }

    @Test
    @DisplayName("refuses keys of the wrong length")
    void wrongKeys() {
        var link = new MemoryLink();
        assertThrows(IllegalArgumentException.class, () -> SrtpTransport.sdes(link.left,
                SdesCrypto.generate(1, SrtpCryptoSuite.AEAD_AES_128_GCM), SdesCrypto.generate(1, SrtpCryptoSuite.AEAD_AES_256_GCM)));
        link.close();
    }

    @Test
    @DisplayName("refuses to send after close")
    void closed() {
        try (var pair = Pair.sdes(SrtpCryptoSuite.AEAD_AES_128_GCM, SrtpOptions.DEFAULT)) {
            pair.left().close();
            assertThrows(ClosedChannelException.class, () -> pair.left().sendRtp(ByteBuffer.wrap(rtp(1, 1, 1))));
        }
    }
}
