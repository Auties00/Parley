package com.github.auties00.parley.datachannel;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the RFC 8832 message codec: the byte layout of section 5, the mapping between channel types and
/// [DataChannelInit], and the parser's robustness against arbitrary input.
@DisplayName("DCEP messages")
class DcepMessageTest {
    private static byte[] bytes(ByteBuffer buffer) {
        var array = new byte[buffer.remaining()];
        buffer.duplicate().get(array);
        return array;
    }

    @Test
    @DisplayName("encodes DATA_CHANNEL_OPEN with the RFC 8832 section 5.1 layout")
    void openLayout() {
        var open = new DcepMessage.Open(DcepMessage.PARTIAL_RELIABLE_REXMIT | DcepMessage.UNORDERED_BIT, 512, 5,
                "chat", "v1");
        // type 03, channel type 81, priority 0200, reliability 00000005, label length 0004, protocol length 0002
        var expected = HexFormat.of().parseHex("0381020000000005" + "00040002" + "63686174" + "7631");
        assertArrayEquals(expected, bytes(open.encode()));
        assertEquals(open, DcepMessage.parse(ByteBuffer.wrap(expected)).orElseThrow());
    }

    @Test
    @DisplayName("encodes DATA_CHANNEL_ACK as the single byte 0x02")
    void ackLayout() {
        assertArrayEquals(new byte[]{0x02}, bytes(new DcepMessage.Ack().encode()));
        assertInstanceOf(DcepMessage.Ack.class, DcepMessage.parse(ByteBuffer.wrap(new byte[]{0x02})).orElseThrow());
    }

    @Test
    @DisplayName("maps channel options to channel types and back")
    void optionsRoundTrip() {
        var cases = new DataChannelInit[]{
                DataChannelInit.reliable(),
                DataChannelInit.reliable().withOrdered(false),
                DataChannelInit.reliable().withMaxRetransmits(7).withPriority(DataChannelPriority.VERY_LOW),
                DataChannelInit.reliable().withOrdered(false).withMaxPacketLifeTime(Duration.ofMillis(1500))
                        .withProtocol("proto").withPriority(DataChannelPriority.HIGH)
        };
        for (var init : cases) {
            var open = DcepMessage.Open.of("label", init);
            var parsed = (DcepMessage.Open) DcepMessage.parse(open.encode()).orElseThrow();
            assertEquals(init, parsed.toInit());
            assertEquals("label", parsed.label());
        }
        assertEquals(0x00, DcepMessage.Open.of("", DataChannelInit.reliable()).channelType());
        assertEquals(0x82, DcepMessage.Open.of("", DataChannelInit.reliable().withOrdered(false)
                .withMaxPacketLifeTime(Duration.ofMillis(1))).channelType());
    }

    @Test
    @DisplayName("encodes UTF-8 labels and ignores the reliability parameter of reliable channels")
    void utf8AndReliableParameter() {
        var label = "caf\u00e9 \u2603";
        var open = new DcepMessage.Open(DcepMessage.RELIABLE, 256, 0, label, "");
        var encoded = bytes(open.encode());
        assertEquals(12 + label.getBytes(java.nio.charset.StandardCharsets.UTF_8).length, encoded.length);
        encoded[4] = 9;
        var parsed = (DcepMessage.Open) DcepMessage.parse(ByteBuffer.wrap(encoded)).orElseThrow();
        assertEquals(label, parsed.label());
        assertEquals(0, parsed.reliabilityParameter());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "01", "03", "0300", "03000100000000000005000061", "03030100000000000000000000",
            "0300010000000000000100", "03000100000000000001000080"})
    @DisplayName("rejects truncated, unknown or invalid messages")
    void rejects(String hex) {
        assertTrue(DcepMessage.parse(ByteBuffer.wrap(HexFormat.of().parseHex(hex))).isEmpty(), hex);
    }

    @Test
    @DisplayName("does not move the position of the parsed buffer")
    void keepsPosition() {
        var buffer = new DcepMessage.Open(0, 256, 0, "a", "b").encode();
        DcepMessage.parse(buffer);
        assertEquals(0, buffer.position());
    }

    @Test
    @DisplayName("refuses to build messages with out-of-range fields")
    void validation() {
        assertThrows(IllegalArgumentException.class, () -> new DcepMessage.Open(0x03, 256, 0, "", ""));
        assertThrows(IllegalArgumentException.class, () -> new DcepMessage.Open(0, 70_000, 0, "", ""));
        assertThrows(IllegalArgumentException.class, () -> new DcepMessage.Open(0, 256, -1, "", ""));
        assertThrows(IllegalArgumentException.class, () -> new DcepMessage.Open(0, 256, 0, "x".repeat(70_000), ""));
    }

    @RepeatedTest(20)
    @DisplayName("never throws on random input and re-encodes whatever it accepts identically")
    void fuzz(org.junit.jupiter.api.RepetitionInfo repetition) {
        var random = new Random(repetition.getCurrentRepetition() * 7919L);
        for (var iteration = 0; iteration < 2_000; iteration++) {
            var data = new byte[random.nextInt(40)];
            random.nextBytes(data);
            if (data.length > 0 && random.nextBoolean()) {
                data[0] = (byte) (random.nextBoolean() ? DcepMessage.OPEN_TYPE : DcepMessage.ACK_TYPE);
            }
            if (data.length > 1 && random.nextBoolean()) {
                data[1] = (byte) new int[]{0x00, 0x01, 0x02, 0x80, 0x81, 0x82}[random.nextInt(6)];
            }
            var parsed = DcepMessage.parse(ByteBuffer.wrap(data));
            if (parsed.isPresent() && parsed.get() instanceof DcepMessage.Open open) {
                var reparsed = DcepMessage.parse(open.encode()).orElseThrow();
                assertEquals(open, reparsed);
            }
        }
    }

    @Test
    @DisplayName("clamps reliability parameters beyond the 16-bit API range")
    void clamps() {
        var open = new DcepMessage.Open(DcepMessage.PARTIAL_RELIABLE_TIMED, 256, 0xFFFF_FFFFL, "", "");
        assertEquals(Duration.ofMillis(65535), open.toInit().maxPacketLifeTime().orElseThrow());
        assertFalse(open.toInit().negotiated());
    }
}
