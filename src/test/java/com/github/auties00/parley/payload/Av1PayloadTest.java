package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Av1FrameMetadata;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.GenericFrameMetadata;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Random;

import static com.github.auties00.parley.payload.TestPackets.array;
import static com.github.auties00.parley.payload.TestPackets.bytes;
import static com.github.auties00.parley.payload.TestPackets.packet;
import static com.github.auties00.parley.payload.TestPackets.packets;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the AV1 payload format (aggregation header `Z`, `Y`, `W`, `N`, OBU size stripping and restoring,
/// sequence header parsing), the dependency descriptor integration of the video depacketizers, and the passthrough
/// format.
@DisplayName("AV1 and passthrough payload formats")
class Av1PayloadTest {
    /// The format under test.
    private static final Av1Format FORMAT = new Av1Format(Codec.av1());

    /// A sequence header payload declaring a 1280x720 maximum frame size.
    static final byte[] SEQUENCE_HEADER = new TestPackets.BitWriter()
            .bits(0, 3).bits(0, 1).bits(0, 1)
            .bits(0, 1).bits(0, 1).bits(0, 5)
            .bits(0, 12).bits(8, 5).bits(0, 1)
            .bits(10, 4).bits(9, 4).bits(1279, 11).bits(719, 10)
            .bits(0x5A, 8)
            .toBytes();

    /// {@return an OBU in low-overhead format: header, optional extension, size, payload}
    static byte[] obu(int type, int temporalId, int spatialId, boolean extension, byte[] payload) {
        var out = new ByteArrayOutputStream();
        out.write(type << 3 | (extension ? 0x04 : 0) | 0x02);
        if (extension) {
            out.write(temporalId << 5 | spatialId << 3);
        }
        Obus.writeLeb128(out, payload.length);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    /// {@return a payload of a length whose first byte marks a shown key frame (or not)}
    static byte[] framePayload(int length, boolean key, long seed) {
        var data = new byte[length];
        new Random(seed).nextBytes(data);
        data[0] = (byte) (key ? 0x10 : 0x30);
        return data;
    }

    /// {@return the concatenation of byte arrays}
    static byte[] concat(byte[]... parts) {
        var out = new ByteArrayOutputStream();
        for (var part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    @Nested
    @DisplayName("OBU plumbing")
    class Plumbing {
        @ParameterizedTest
        @ValueSource(longs = {0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 0xFFFFFFFFL})
        @DisplayName("round-trips leb128 values in their minimal form")
        void leb128(long value) throws PayloadFormatException {
            var out = new ByteArrayOutputStream();
            Obus.writeLeb128(out, value);
            var bytes = out.toByteArray();
            assertEquals(Obus.leb128Size(value), bytes.length);
            assertEquals(value, Obus.readLeb128(ByteBuffer.wrap(bytes), 0, bytes.length));
        }

        @Test
        @DisplayName("rejects truncated, non-minimal and oversized leb128 values")
        void leb128Errors() {
            assertThrows(PayloadFormatException.class, () -> Obus.readLeb128(bytes(0x80), 0, 1));
            assertThrows(PayloadFormatException.class, () -> Obus.readLeb128(bytes(0x80, 0x00), 0, 2));
            assertThrows(PayloadFormatException.class,
                    () -> Obus.readLeb128(bytes(0xFF, 0xFF, 0xFF, 0xFF, 0x7F), 0, 5));
            assertThrows(PayloadFormatException.class,
                    () -> Obus.readLeb128(bytes(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01), 0, 9));
        }

        @Test
        @DisplayName("reads the maximum frame size of a sequence header")
        void sequenceHeader() {
            var info = Obus.parseSequenceHeader(ByteBuffer.wrap(SEQUENCE_HEADER)).orElseThrow();
            assertFalse(info.reducedStillPictureHeader());
            assertEquals(Optional.of(new Resolution(1280, 720)), info.maxResolution());
            var reduced = new TestPackets.BitWriter().bits(0, 3).bits(1, 1).bits(1, 1).bits(1, 5)
                    .bits(7, 4).bits(7, 4).bits(255, 8).bits(127, 8).toBytes();
            var still = Obus.parseSequenceHeader(ByteBuffer.wrap(reduced)).orElseThrow();
            assertTrue(still.reducedStillPictureHeader());
            assertEquals(Optional.of(new Resolution(256, 128)), still.maxResolution());
            assertTrue(Obus.parseSequenceHeader(bytes(0)).isEmpty());
        }

        @Test
        @DisplayName("parses a temporal unit and rejects malformed ones")
        void temporalUnit() {
            var unit = ByteBuffer.wrap(concat(obu(2, 0, 0, false, new byte[0]), obu(6, 1, 2, true, new byte[]{1, 2})));
            var obus = Obus.parseTemporalUnit(unit);
            assertEquals(2, obus.size());
            assertEquals(1, obus.get(1).temporalId());
            assertEquals(2, obus.get(1).spatialId());
            assertThrows(IllegalArgumentException.class, () -> Obus.parseTemporalUnit(bytes(0x32, 5, 1)));
            assertThrows(IllegalArgumentException.class, () -> Obus.parseTemporalUnit(bytes(0xB2, 0)));
        }
    }

    @Nested
    @DisplayName("packetization")
    class Packetization {
        @ParameterizedTest(name = "max payload {0}")
        @ValueSource(ints = {64, 65, 129, 300, 1100})
        @DisplayName("round-trips a keyframe temporal unit across payload sizes")
        void roundTrip(int maxPayload) throws PayloadFormatException {
            var sequence = obu(1, 0, 0, false, SEQUENCE_HEADER);
            var frame = obu(6, 0, 0, false, framePayload(3000, true, maxPayload));
            var metadata = obu(5, 0, 0, false, new byte[]{1, 2, 3});
            var unit = concat(obu(2, 0, 0, false, new byte[0]), sequence, metadata, frame,
                    obu(15, 0, 0, false, new byte[]{9}));
            var payloads = FORMAT.packetizer(new PacketizerConfig(maxPayload)).packetize(
                    new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(unit), 0, true, Optional.empty(),
                            Av1FrameMetadata.none()));
            for (var payload : payloads) {
                assertTrue(payload.payload().remaining() <= maxPayload);
            }
            assertEquals(0x08, payloads.getFirst().payload().get(0) & 0x08);
            for (var i = 1; i < payloads.size(); i++) {
                assertEquals(0, payloads.get(i).payload().get(0) & 0x08);
            }
            var rtp = packets(payloads, 45, 7, 0);
            var depacketizer = FORMAT.depacketizer();
            assertTrue(depacketizer.inspect(rtp.getFirst()).keyframe());
            assertTrue(depacketizer.inspect(rtp.getFirst()).frameStart());
            assertTrue(FORMAT.isKeyframe(rtp.getFirst().payload()));
            var assembled = depacketizer.assemble(rtp);
            assertArrayEquals(concat(sequence, metadata, frame), assembled.toByteArray());
            assertTrue(assembled.keyframe());
            var read = (Av1FrameMetadata) assembled.metadata();
            assertTrue(read.sequenceHeader());
            assertTrue(read.newCodedVideoSequence());
            assertEquals(Optional.of(new Resolution(1280, 720)), read.resolution());
        }

        @Test
        @DisplayName("aggregates small OBUs with W and fragments large ones with Z and Y")
        void aggregationHeader() {
            var a = obu(6, 0, 0, false, new byte[]{1, 2, 3});
            var b = obu(6, 0, 0, false, new byte[]{4, 5});
            var small = FORMAT.packetizer().packetize(EncodedFrame.of(MediaKind.VIDEO,
                    ByteBuffer.wrap(concat(a, b)), 0, false));
            assertEquals(1, small.size());
            assertArrayEquals(new byte[]{0x20, 4, 0x30, 1, 2, 3, 0x30, 4, 5}, array(small.getFirst().payload()));
            var many = new ArrayList<byte[]>();
            for (var i = 0; i < 5; i++) {
                many.add(obu(6, 0, 0, false, new byte[]{(byte) i}));
            }
            var four = FORMAT.packetizer().packetize(EncodedFrame.of(MediaKind.VIDEO,
                    ByteBuffer.wrap(concat(many.toArray(byte[][]::new))), 0, false));
            assertEquals(0, four.getFirst().payload().get(0) & 0x30);
            var large = FORMAT.packetizer(new PacketizerConfig(64)).packetize(EncodedFrame.of(MediaKind.VIDEO,
                    ByteBuffer.wrap(obu(6, 0, 0, false, new byte[200])), 0, false));
            assertEquals(4, large.size());
            assertEquals(0x40, large.getFirst().payload().get(0) & 0xC0);
            assertEquals(0xC0, large.get(1).payload().get(0) & 0xC0);
            assertEquals(0x80, large.getLast().payload().get(0) & 0xC0);
            assertTrue(large.getLast().marker());
        }

        @Test
        @DisplayName("keeps OBU extension layers and reads them back")
        void layers() throws PayloadFormatException {
            var unit = obu(6, 2, 1, true, framePayload(500, false, 3));
            var rtp = packets(FORMAT.packetizer(new PacketizerConfig(128)).packetize(EncodedFrame.of(MediaKind.VIDEO,
                    ByteBuffer.wrap(unit), 0, false)), 45, 1, 0);
            var depacketizer = FORMAT.depacketizer();
            assertEquals(2, depacketizer.inspect(rtp.getFirst()).temporalId());
            assertEquals(1, depacketizer.inspect(rtp.getFirst()).spatialId());
            var frame = depacketizer.assemble(rtp);
            assertArrayEquals(unit, frame.toByteArray());
            assertFalse(frame.keyframe());
            var metadata = (Av1FrameMetadata) frame.metadata();
            assertEquals(2, metadata.temporalId());
            assertEquals(1, metadata.spatialId());
        }

        @Test
        @DisplayName("rejects broken continuity, mismatched W and empty elements")
        void rejects() {
            var depacketizer = FORMAT.depacketizer();
            assertThrows(PayloadFormatException.class,
                    () -> depacketizer.assemble(List.of(packet(45, true, 1, 0, bytes(0x90, 0x30, 1)))));
            assertThrows(PayloadFormatException.class,
                    () -> depacketizer.assemble(List.of(packet(45, true, 1, 0, bytes(0x50, 0x30, 1)))));
            assertFalse(depacketizer.inspect(packet(45, true, 1, 0, bytes(0x20, 1, 0x30))).valid());
            assertFalse(depacketizer.inspect(packet(45, true, 1, 0, bytes(0x00, 0, 0x30))).valid());
            assertFalse(depacketizer.inspect(packet(45, true, 1, 0, bytes(0x88, 0x30))).valid());
            var first = packet(45, false, 1, 0, bytes(0x50, 0x30, 1));
            var unrelated = packet(45, true, 2, 0, bytes(0x10, 0x30, 1));
            assertThrows(PayloadFormatException.class, () -> depacketizer.assemble(List.of(first, unrelated)));
            assertThrows(IllegalArgumentException.class, () -> FORMAT.packetizer().packetize(
                    EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(obu(2, 0, 0, false, new byte[0])), 0, true)));
        }
    }

    @Nested
    @DisplayName("dependency descriptor")
    class Descriptor {
        /// A reader that decodes a test encoding: flags byte (start, end, structure), 16-bit frame number, then one
        /// frame difference per byte.
        private static final VideoDepacketizer.DescriptorReader READER = (value, latest) -> {
            if (value.remaining() < 3) {
                throw new RtpFormatException("short");
            }
            var position = value.position();
            var flags = value.get(position) & 0xFF;
            var number = value.getShort(position + 1) & 0xFFFF;
            var diffs = new ArrayList<Integer>();
            for (var i = position + 3; i < value.limit(); i++) {
                diffs.add(value.get(i) & 0xFF);
            }
            return new DependencyDescriptor((flags & 0x80) != 0, (flags & 0x40) != 0, 0, number, Optional.empty(),
                    java.util.OptionalLong.empty(), 0, 0, List.of(), diffs, List.of());
        };

        @Test
        @DisplayName("takes boundaries, frame ids and dependencies from the descriptor")
        void boundaries() throws PayloadFormatException {
            var depacketizer = new VideoDepacketizer(new Av1Depacketizer(), 4, READER);
            var unit = obu(6, 0, 0, false, framePayload(10, false, 1));
            var payload = FORMAT.packetizer().packetize(EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(unit), 0,
                    false)).getFirst();
            var start = packet(45, false, 10, 0, 1, payload.payload(), Map.of(4, new byte[]{(byte) 0x80, 0, 9, 1, 3}),
                    List.of());
            var boundaries = depacketizer.inspect(start);
            assertTrue(boundaries.frameStart() && boundaries.explicitStart());
            assertFalse(boundaries.frameEnd());
            var frame = depacketizer.assemble(List.of(start));
            var id = frame.metadata().frameId().orElseThrow();
            assertEquals(List.of(id - 1, id - 3), frame.metadata().dependencies());
            var next = packet(45, true, 11, 0, 1, payload.payload(), Map.of(4, new byte[]{(byte) 0xC0, 0, 10, 1}),
                    List.of());
            assertEquals(OptionalLong.of(id + 1), depacketizer.assemble(List.of(next)).metadata().frameId());
            var malformed = packet(45, true, 12, 0, 1, payload.payload(), Map.of(4, new byte[]{1}), List.of());
            assertFalse(depacketizer.inspect(malformed).explicitStart());
            var bare = packet(45, true, 13, 0, payload.payload());
            assertTrue(depacketizer.inspect(bare).valid());
        }

        @Test
        @DisplayName("lets the passthrough format group frames by descriptor")
        void passthrough() throws PayloadFormatException {
            var generic = new GenericFormat(Codec.of("video/x-custom", 90000));
            var base = generic.depacketizer();
            var wrapped = new VideoDepacketizer(base, 2, READER);
            var start = packet(127, false, 1, 0, 1, bytes(1, 2), Map.of(2, new byte[]{(byte) 0x80, 0, 1}), List.of());
            assertTrue(wrapped.inspect(start).frameStart());
            assertFalse(base.inspect(start).frameStart());
            var frame = wrapped.assemble(List.of(start));
            assertTrue(frame.metadata() instanceof GenericFrameMetadata metadata && metadata.frameId().isPresent());
            assertTrue(generic.depacketizer(DepacketizerConfig.none().withDependencyDescriptorExtensionId(2))
                    instanceof VideoDepacketizer);
        }
    }

    @Test
    @DisplayName("passes opaque frames through, split by the payload size and closed by the marker")
    void generic() throws PayloadFormatException {
        var generic = new GenericFormat(Codec.of("video/x-custom", 90000));
        var data = new byte[2500];
        new Random(1).nextBytes(data);
        var payloads = generic.packetizer().packetize(EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(data), 5, false));
        assertEquals(3, payloads.size());
        assertTrue(payloads.getLast().marker());
        var rtp = packets(payloads, 127, 1, 5);
        assertFalse(generic.depacketizer().inspect(rtp.getFirst()).frameStart());
        assertTrue(generic.depacketizer().inspect(rtp.getLast()).frameEnd());
        assertArrayEquals(data, generic.depacketizer().assemble(rtp).toByteArray());
        assertFalse(generic.isKeyframe(rtp.getFirst().payload()));
        assertTrue(generic.timestampDuration(rtp.getFirst().payload()).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> generic.packetizer().packetize(
                EncodedFrame.of(MediaKind.AUDIO, bytes(1), 0, true)));
    }

    @Test
    @DisplayName("survives random payloads: inspect never throws, assemble only throws PayloadFormatException")
    void fuzz() {
        var random = new Random(1);
        for (var i = 0; i < 5000; i++) {
            var depacketizer = FORMAT.depacketizer();
            var run = new ArrayList<RtpPacket>();
            var count = 1 + random.nextInt(3);
            for (var p = 0; p < count; p++) {
                var data = new byte[random.nextInt(30)];
                random.nextBytes(data);
                run.add(packet(45, p == count - 1, p, 0, ByteBuffer.wrap(data)));
                depacketizer.inspect(run.getLast());
                FORMAT.isKeyframe(ByteBuffer.wrap(data));
            }
            try {
                depacketizer.assemble(run);
            } catch (PayloadFormatException expected) {
                // Malformed input is reported this way and only this way.
            }
        }
    }
}
