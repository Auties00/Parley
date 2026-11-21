package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers RTX wrapping, RED encoding and decoding, and ULPFEC and FlexFEC recovery under random loss.
@DisplayName("repair formats")
class FecTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final long SSRC = 0x11223344L;

    static RtpPacket media(Random random, int sequence, boolean extension) throws RtpFormatException {
        var payload = new byte[random.nextInt(1, 300)];
        random.nextBytes(payload);
        var writer = RtpPacketWriter.into(ByteBuffer.allocate(512)).payloadType(96).ssrc(SSRC).sequence(sequence)
                .timestamp(90_000L * sequence & 0xFFFFFFFFL).marker(random.nextInt(5) == 0)
                .padding(random.nextInt(6) == 0 ? random.nextInt(1, 20) : 0).payload(ByteBuffer.wrap(payload));
        if (extension) {
            writer.extension(3, ByteBuffer.wrap(new byte[]{(byte) sequence, 7}));
        }
        if (random.nextBoolean()) {
            writer.csrcs(List.of(5L, 6L));
        }
        return RtpPacket.parse(writer.finish()).copy();
    }

    static byte[] bytes(ByteBuffer buffer) {
        var out = new byte[buffer.remaining()];
        buffer.duplicate().get(out);
        return out;
    }

    @Nested
    @DisplayName("RTX")
    class RtxFormat {
        @Test
        @DisplayName("prefixes the original sequence number and restores the original packet")
        void roundTrip() throws RtpFormatException {
            var original = media(new Random(1), 4660, true);
            var payload = Rtx.payloadOf(original);
            assertEquals(0x1234, payload.getShort(0) & 0xFFFF);
            var rtx = RtpPacket.parse(RtpPacketWriter.into(ByteBuffer.allocate(600)).payloadType(97).ssrc(99)
                    .sequence(7).timestamp(original.timestamp()).marker(original.marker())
                    .extension(3, original.extension(3).orElseThrow()).payload(payload).finish());
            assertEquals(4660, Rtx.originalSequence(rtx));
            var restored = Rtx.restore(rtx, 96, SSRC);
            assertEquals(96, restored.payloadType());
            assertEquals(SSRC, restored.ssrc());
            assertEquals(4660, restored.sequence());
            assertEquals(original.timestamp(), restored.timestamp());
            assertArrayEquals(bytes(original.payload()), bytes(restored.payload()));
            assertArrayEquals(bytes(original.extension(3).orElseThrow()), bytes(restored.extension(3).orElseThrow()));
        }

        @Test
        @DisplayName("rejects a payload without the original sequence number")
        void tooShort() throws RtpFormatException {
            var rtx = RtpPacket.parse(RtpPacketWriter.into(ByteBuffer.allocate(64)).payload(ByteBuffer.allocate(1))
                    .finish());
            assertThrows(RtpFormatException.class, () -> Rtx.restore(rtx, 96, 1));
        }
    }

    @Nested
    @DisplayName("RED")
    class RedFormat {
        @Test
        @DisplayName("encodes the RFC 2198 example layout")
        void vector() throws RtpFormatException {
            var payload = Red.encode(List.of(new Red.Redundant(0, 160, ByteBuffer.wrap(new byte[]{1, 2}))), 111,
                    ByteBuffer.wrap(new byte[]{3}));
            assertEquals("80028002" + "6f" + "0102" + "03", HEX.formatHex(bytes(payload)));
            var blocks = Red.decode(payload, 1000);
            assertEquals(2, blocks.size());
            assertEquals(840, blocks.get(0).timestamp());
            assertEquals(0, blocks.get(0).payloadType());
            assertArrayEquals(new byte[]{1, 2}, bytes(blocks.get(0).data()));
            assertTrue(blocks.get(1).primary());
            assertEquals(111, blocks.get(1).payloadType());
            assertArrayEquals(new byte[]{3}, bytes(blocks.get(1).data()));
        }

        @Test
        @DisplayName("repeats the previous frames up to the distance")
        void encoder() throws RtpFormatException {
            var encoder = new RedEncoder(2);
            for (var i = 0; i < 5; i++) {
                var payload = encoder.encode(111, 960L * i, ByteBuffer.wrap(new byte[]{(byte) i}));
                var blocks = Red.decode(payload, 960L * i);
                assertEquals(Math.min(i, 2) + 1, blocks.size());
                for (var b = 0; b < blocks.size(); b++) {
                    var frame = i - (blocks.size() - 1 - b);
                    assertEquals(960L * frame, blocks.get(b).timestamp());
                    assertEquals(frame, blocks.get(b).data().get(0));
                }
            }
        }

        @Test
        @DisplayName("rejects truncated payloads and throws nothing else on random bytes")
        void malformed() {
            assertThrows(RtpFormatException.class, () -> Red.decode(ByteBuffer.wrap(HEX.parseHex("8000")), 0));
            assertThrows(RtpFormatException.class, () -> Red.decode(ByteBuffer.wrap(HEX.parseHex("800003ff6f")), 0));
            assertThrows(RtpFormatException.class, () -> Red.decode(ByteBuffer.allocate(0), 0));
            var random = new Random();
            for (var i = 0; i < 5_000; i++) {
                var data = new byte[random.nextInt(40)];
                random.nextBytes(data);
                try {
                    Red.decode(ByteBuffer.wrap(data), random.nextLong(1L << 32));
                } catch (RtpFormatException expected) {
                    // malformed payloads are reported, never anything else
                }
            }
        }
    }

    @Nested
    @DisplayName("FEC")
    class Fec {
        @ParameterizedTest
        @EnumSource(FecFormat.class)
        @DisplayName("recovers any single loss of a fully protected frame")
        void singleLoss(FecFormat format) throws RtpFormatException {
            var random = new Random(42);
            var packets = new ArrayList<RtpPacket>();
            for (var i = 0; i < 10; i++) {
                packets.add(media(random, 65530 + i & 0xFFFF, i % 2 == 0));
            }
            for (var lost = 0; lost < packets.size(); lost++) {
                var encoder = new FecEncoder(format, SSRC, 10);
                packets.forEach(encoder::add);
                var fec = encoder.flush();
                assertEquals(1, fec.size());
                var decoder = new FecDecoder(format, SSRC);
                var recovered = new ArrayList<RtpPacket>();
                for (var i = 0; i < packets.size(); i++) {
                    if (i != lost) {
                        recovered.addAll(decoder.addMedia(packets.get(i)));
                    }
                }
                recovered.addAll(decoder.addFec(fec.getFirst()));
                assertEquals(1, recovered.size());
                assertArrayEquals(bytes(packets.get(lost).buffer()), bytes(recovered.getFirst().buffer()));
            }
        }

        @ParameterizedTest
        @EnumSource(FecFormat.class)
        @DisplayName("recovers when the FEC packet arrives before the media")
        void fecFirst(FecFormat format) throws RtpFormatException {
            var random = new Random(7);
            var packets = List.of(media(random, 1, false), media(random, 2, true), media(random, 3, false));
            var encoder = new FecEncoder(format, SSRC, 30);
            packets.forEach(encoder::add);
            var fec = encoder.flush();
            assertEquals(1, fec.size());
            var decoder = new FecDecoder(format, SSRC);
            assertTrue(decoder.addFec(fec.getFirst()).isEmpty());
            assertTrue(decoder.addMedia(packets.get(0)).isEmpty());
            var recovered = decoder.addMedia(packets.get(2));
            assertEquals(1, recovered.size());
            assertArrayEquals(bytes(packets.get(1).buffer()), bytes(recovered.getFirst().buffer()));
            assertEquals(1, decoder.recoveredCount());
        }

        @ParameterizedTest
        @EnumSource(FecFormat.class)
        @DisplayName("recovers random losses with full protection across wide frames")
        void randomLoss(FecFormat format) throws RtpFormatException {
            var random = new Random(format.ordinal());
            for (var round = 0; round < 30; round++) {
                var count = random.nextInt(2, format.maxProtected() + 20);
                var base = random.nextInt(65536);
                var packets = new ArrayList<RtpPacket>();
                for (var i = 0; i < count; i++) {
                    packets.add(media(random, (base + i) & 0xFFFF, random.nextBoolean()));
                }
                var encoder = new FecEncoder(format, SSRC, 50);
                packets.forEach(encoder::add);
                var fec = encoder.flush();
                var lost = new HashSet<Integer>();
                for (var i = 0; i < count; i++) {
                    if (random.nextInt(10) == 0) {
                        lost.add(i);
                    }
                }
                var decoder = new FecDecoder(format, SSRC);
                var recovered = new ArrayList<RtpPacket>();
                for (var i = 0; i < count; i++) {
                    if (!lost.contains(i)) {
                        recovered.addAll(decoder.addMedia(packets.get(i)));
                    }
                }
                for (var payload : fec) {
                    recovered.addAll(decoder.addFec(payload));
                }
                for (var packet : recovered) {
                    var index = (packet.sequence() - base) & 0xFFFF;
                    assertTrue(lost.contains(index));
                    assertArrayEquals(bytes(packets.get(index).buffer()), bytes(packet.buffer()));
                }
            }
        }

        @Test
        @DisplayName("ignores FlexFEC draft 03 packets protecting another SSRC")
        void otherSsrc() throws RtpFormatException {
            var random = new Random(3);
            var encoder = new FecEncoder(FecFormat.FLEXFEC_03, 1234, 100);
            var packet = media(random, 1, false);
            encoder.add(packet);
            var decoder = new FecDecoder(FecFormat.FLEXFEC_03, SSRC);
            assertTrue(decoder.addFec(encoder.flush().getFirst()).isEmpty());
        }

        @ParameterizedTest
        @EnumSource(FecFormat.class)
        @DisplayName("throws only RtpFormatException on random FEC payloads")
        void fuzz(FecFormat format) {
            var random = new Random();
            for (var i = 0; i < 5_000; i++) {
                var data = new byte[random.nextInt(60)];
                random.nextBytes(data);
                var decoder = new FecDecoder(format, SSRC);
                try {
                    decoder.addFec(ByteBuffer.wrap(data));
                } catch (RtpFormatException expected) {
                    // malformed payloads are reported, never anything else
                }
            }
        }
    }
}
