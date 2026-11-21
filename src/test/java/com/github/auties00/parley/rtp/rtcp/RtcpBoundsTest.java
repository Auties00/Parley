package com.github.auties00.parley.rtp.rtcp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/// Covers the bounds RTCP parsing puts on peer-chosen counts: transport-wide feedback status counts and repeated NACK
/// sequence numbers, with a fuzz pass over both.
@DisplayName("RTCP parsing bounds")
class RtcpBoundsTest {
    private static final HexFormat HEX = HexFormat.of();

    /// A 24-byte transport-wide feedback claiming `count` statuses in one run-length chunk of lost packets.
    private static ByteBuffer amplifying(int count) {
        return ByteBuffer.allocate(24).put((byte) 0x8F).put((byte) 205).putShort((short) 5).putInt(1).putInt(2)
                .putShort((short) 0).putShort((short) count).putInt(0).putShort((short) 0x1FFF).putShort((short) 0)
                .flip();
    }

    @Test
    @DisplayName("rejects transport-wide feedback reporting more than 0x7FFF packets (correctness-m2 probe)")
    void twccCount() throws RtcpFormatException {
        assertThrows(RtcpFormatException.class, () -> RtcpPacket.parseCompound(amplifying(0xFFFF)));
        assertThrows(RtcpFormatException.class, () -> RtcpPacket.parseCompound(amplifying(0x8000)));
        var parsed = (TransportFeedback) RtcpPacket.parseCompound(amplifying(0x1FFF)).getFirst();
        assertEquals(0x1FFF, parsed.results().size());
    }

    @Test
    @DisplayName("drops repeated NACK sequence numbers so the packet round-trips (correctness-m5 fuzz input)")
    void nackDuplicates() throws RtcpFormatException {
        var nack = (Nack) RtcpPacket.parseCompound(ByteBuffer.wrap(HEX.parseHex("81cd00040000000100000002000100000001"
                + "0000"))).getFirst();
        assertEquals(List.of(1), nack.sequences());
        var again = (Nack) RtcpPacket.parseCompound(RtcpPacket.encodeCompound(List.of(nack), 0)).getFirst();
        assertEquals(nack, again);
    }

    @Test
    @DisplayName("orders NACK sequence numbers in wrap order from the first packet id")
    void nackWrapOrder() throws RtcpFormatException {
        var body = ByteBuffer.allocate(24).put((byte) 0x81).put((byte) 205).putShort((short) 5).putInt(1).putInt(2)
                .putShort((short) 0xFFFE).putShort((short) 0).putShort((short) 1).putShort((short) 0)
                .putShort((short) 0xFFFF).putShort((short) 0x0001).flip();
        var nack = (Nack) RtcpPacket.parseCompound(body).getFirst();
        assertEquals(List.of(0xFFFE, 0xFFFF, 0, 1), nack.sequences());
    }

    @Test
    @DisplayName("parses random feedback without other failures than RtcpFormatException, re-encoding stably")
    void fuzz() throws RtcpFormatException {
        var random = new Random(0x7CC);
        for (var i = 0; i < 20_000; i++) {
            var packet = random.nextBoolean() ? amplifying(random.nextInt(0x10000)) : ByteBuffer.allocate(24)
                    .put((byte) 0x81).put((byte) 205).putShort((short) 5).putInt(1).putInt(2)
                    .putInt(random.nextInt()).putInt(random.nextInt()).putInt(random.nextInt()).flip();
            var bytes = packet.array();
            if (random.nextBoolean()) {
                bytes[12 + random.nextInt(12)] = (byte) random.nextInt();
            }
            try {
                var parsed = RtcpPacket.parseCompound(ByteBuffer.wrap(bytes));
                var again = RtcpPacket.parseCompound(RtcpPacket.encodeCompound(parsed, 0));
                assertEquals(parsed, again);
            } catch (RtcpFormatException expected) {
                // malformed or amplifying input is refused, never anything else
            }
        }
    }
}
