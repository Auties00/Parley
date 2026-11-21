package com.github.auties00.parley.mdns;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ThreadFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the DNS codec (with compression pointers and fuzzing) and the responder and resolver over an in-memory
/// multicast link.
@DisplayName("mDNS")
class MdnsTest {
    private static final ThreadFactory THREADS = Thread.ofVirtual().name("mdns-test-", 0).factory();

    @Test
    @DisplayName("round-trips questions and address records")
    void codecRoundTrip() throws MdnsFormatException {
        var address = InetAddress.ofLiteral("192.168.1.20");
        var message = new MdnsMessage(7, true,
                List.of(new MdnsMessage.Question("abc.local", MdnsMessage.TYPE_A, true)),
                List.of(MdnsMessage.Answer.address("abc.local", address, 120, true)));
        var decoded = MdnsMessage.decode(message.encode());
        assertEquals(message, decoded);
        assertEquals(address, decoded.answers().getFirst().address());
    }

    @Test
    @DisplayName("follows name compression pointers and rejects pointer loops")
    void compression() throws MdnsFormatException {
        var buffer = ByteBuffer.allocate(64);
        buffer.putShort((short) 0).putShort((short) 0x8400).putShort((short) 1).putShort((short) 1).putInt(0);
        buffer.put((byte) 3).put("abc".getBytes()).put((byte) 5).put("local".getBytes()).put((byte) 0);
        buffer.putShort((short) 1).putShort((short) 1);
        buffer.putShort((short) 0xC00C).putShort((short) 1).putShort((short) 0x8001).putInt(120).putShort((short) 4).put(new byte[]{10, 0, 0, 1});
        var decoded = MdnsMessage.decode(buffer.flip());
        assertEquals("abc.local", decoded.answers().getFirst().name());
        assertTrue(decoded.answers().getFirst().cacheFlush());
        var loop = ByteBuffer.allocate(20);
        loop.putShort((short) 0).putShort((short) 0).putShort((short) 1).putShort((short) 0).putInt(0);
        loop.putShort((short) 0xC00C).putShort((short) 1).putShort((short) 1).flip();
        assertThrowsFormat(loop);
    }

    @Test
    @DisplayName("throws only MdnsFormatException for random and mutated messages")
    void fuzz() {
        var random = new Random(11);
        var valid = new MdnsMessage(1, true, List.of(new MdnsMessage.Question("x.local", 1, false)),
                List.of(MdnsMessage.Answer.address("x.local", InetAddress.ofLiteral("10.0.0.1"), 120, true))).encode();
        for (var i = 0; i < 20_000; i++) {
            ByteBuffer buffer;
            if (random.nextBoolean()) {
                var bytes = new byte[random.nextInt(80)];
                random.nextBytes(bytes);
                buffer = ByteBuffer.wrap(bytes);
            } else {
                buffer = ByteBuffer.allocate(valid.remaining()).put(valid.duplicate()).flip();
                buffer.put(random.nextInt(buffer.remaining()), (byte) random.nextInt(256));
            }
            try {
                MdnsMessage.decode(buffer).answers().forEach(MdnsMessage.Answer::address);
            } catch (MdnsFormatException expected) {
                // Malformed input fails this way only.
            }
        }
    }

    @Test
    @DisplayName("resolves a registered name through the responder, with the unicast-response bit")
    void resolvesRegisteredName() throws Exception {
        var hub = new MemoryMdnsLink();
        try (var responder = new MdnsResponder(hub.channel("10.0.0.2", 5353), THREADS);
             var resolver = new MdnsResolver(hub.channel("10.0.0.3", 50000), THREADS)) {
            var address = InetAddress.ofLiteral("192.168.1.44");
            var name = responder.register(address);
            assertTrue(MdnsResolver.isIceName(name));
            assertEquals(name, responder.register(address));
            assertEquals(Optional.of(address), resolver.resolve(name, Duration.ofSeconds(3)));
            assertEquals(Optional.of(address), resolver.resolve(name.toUpperCase(), Duration.ofMillis(10)));
        }
    }

    @Test
    @DisplayName("resolves an IPv6 registration with an AAAA record")
    void resolvesIpv6() throws Exception {
        var hub = new MemoryMdnsLink();
        try (var responder = new MdnsResponder(hub.channel("10.0.0.2", 5353), THREADS);
             var resolver = new MdnsResolver(hub.channel("10.0.0.3", 50000), THREADS)) {
            var address = InetAddress.ofLiteral("fd00::44");
            var name = responder.register(address);
            assertEquals(Optional.of(address), resolver.resolve(name, Duration.ofSeconds(3)));
        }
    }

    @Test
    @DisplayName("answers a legacy unicast query with the query id and question echoed")
    void legacyUnicast() throws Exception {
        var hub = new MemoryMdnsLink();
        try (var responder = new MdnsResponder(hub.channel("10.0.0.2", 5353), THREADS)) {
            var name = responder.register(InetAddress.ofLiteral("192.168.1.5"));
            var querier = hub.channel("10.0.0.9", 40000);
            var query = new MdnsMessage(0x1234, false, List.of(new MdnsMessage.Question(name, MdnsMessage.TYPE_A, false)), List.of());
            querier.send(query.encode(), MdnsChannel.IPV4_GROUP);
            var buffer = ByteBuffer.allocate(MdnsMessage.MAX_LENGTH);
            querier.receive(buffer);
            var response = MdnsMessage.decode(buffer.flip());
            assertEquals(0x1234, response.id());
            assertEquals(name, response.questions().getFirst().name());
            assertEquals(MdnsResponder.LEGACY_TTL, response.answers().getFirst().ttl());
            assertFalse(response.answers().getFirst().cacheFlush());
        }
    }

    @Test
    @DisplayName("ignores names that are not UUID .local names and unanswered names")
    void ignoresOtherNames() throws Exception {
        var hub = new MemoryMdnsLink();
        try (var resolver = new MdnsResolver(hub.channel("10.0.0.3", 50000), THREADS)) {
            assertEquals(Optional.empty(), resolver.resolve("printer.local", Duration.ofMillis(100)));
            assertEquals(Optional.empty(), resolver.resolve("6b7e9d1c-6c5b-4a36-9a8c-2f2d1c1e3f40.local", Duration.ofMillis(200)));
        }
    }

    @Test
    @DisplayName("resolves nothing when two responders claim one name with different addresses")
    void conflictingAnswers() throws Exception {
        var hub = new MemoryMdnsLink();
        var name = "6b7e9d1c-6c5b-4a36-9a8c-2f2d1c1e3f40.local";
        try (var resolver = new MdnsResolver(hub.channel("10.0.0.3", 50000), THREADS)) {
            var liar = hub.channel("10.0.0.7", 5353);
            Thread.ofVirtual().start(() -> {
                try {
                    var buffer = ByteBuffer.allocate(MdnsMessage.MAX_LENGTH);
                    var source = liar.receive(buffer);
                    var answer = new MdnsMessage(0, true, List.of(), List.of(
                            MdnsMessage.Answer.address(name, InetAddress.ofLiteral("10.0.0.1"), 120, true),
                            MdnsMessage.Answer.address(name, InetAddress.ofLiteral("10.0.0.2"), 120, true)));
                    liar.send(answer.encode(), source);
                } catch (IOException exception) {
                    // The test ended.
                }
            });
            assertEquals(Optional.empty(), resolver.resolve(name, Duration.ofSeconds(2)));
        }
    }

    private static void assertThrowsFormat(ByteBuffer buffer) {
        try {
            MdnsMessage.decode(buffer);
            throw new AssertionError("decoded a malformed message");
        } catch (MdnsFormatException expected) {
            // Expected.
        }
    }
}
