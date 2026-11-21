package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.media.Vp9FrameMetadata;
import com.github.auties00.parley.media.Vp9ScalabilityStructure;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Random;

import static com.github.auties00.parley.payload.TestPackets.bytes;
import static com.github.auties00.parley.payload.TestPackets.packet;
import static com.github.auties00.parley.payload.TestPackets.packets;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the VP9 payload format of RFC 9628: flexible and non-flexible descriptors, the scalability structure,
/// layer frames and the picture marker, keyframe size from the uncompressed header, and the forwarding rewriter.
@DisplayName("VP9 payload format")
class Vp9PayloadTest {
    /// The format under test.
    private static final Vp9Format FORMAT = new Vp9Format(Codec.vp9());

    /// A two-layer structure with a two-picture group.
    private static final Vp9ScalabilityStructure STRUCTURE = new Vp9ScalabilityStructure(2,
            List.of(new Resolution(320, 180), new Resolution(640, 360)),
            List.of(new Vp9ScalabilityStructure.PictureGroupEntry(0, false, List.of(2)),
                    new Vp9ScalabilityStructure.PictureGroupEntry(1, true, List.of(1))));

    /// {@return a profile 0 VP9 key frame uncompressed header of a size, followed by filler}
    static byte[] keyframe(int width, int height, int length) {
        var header = new TestPackets.BitWriter()
                .bits(2, 2).bits(0, 1).bits(0, 1)
                .bits(0, 1).bits(0, 1).bits(1, 1).bits(0, 1)
                .bits(0x498342, 24)
                .bits(1, 3).bits(0, 1)
                .bits(width - 1, 16).bits(height - 1, 16)
                .toBytes();
        var data = new byte[Math.max(length, header.length)];
        System.arraycopy(header, 0, data, 0, header.length);
        return data;
    }

    @Nested
    @DisplayName("descriptor")
    class Descriptor {
        @Test
        @DisplayName("parses a flexible descriptor with layer indices and three reference differences")
        void flexible() throws PayloadFormatException {
            var descriptor = Vp9Descriptor.parse(bytes(0xFC, 0x81, 0x02, 0x53, 0x03, 0x05, 0x0E, 0xAA));
            assertTrue(descriptor.interPicturePredicted());
            assertTrue(descriptor.flexible());
            assertTrue(descriptor.begin());
            assertTrue(descriptor.end());
            assertEquals(OptionalInt.of(0x0102), descriptor.pictureId());
            assertEquals(2, descriptor.temporalId());
            assertTrue(descriptor.switchingUpPoint());
            assertEquals(1, descriptor.spatialId());
            assertTrue(descriptor.interLayerPredicted());
            assertEquals(List.of(1, 2, 7), descriptor.referenceDiffs());
            assertTrue(descriptor.tl0PicIndex().isEmpty());
            assertEquals(7, descriptor.size());
        }

        @Test
        @DisplayName("parses a non-flexible descriptor with TL0PICIDX and a scalability structure")
        void nonFlexible() throws PayloadFormatException {
            var out = ByteBuffer.allocate(64);
            out.put((byte) 0xAA).put((byte) 0x05).put((byte) 0x00).put((byte) 0x31);
            Vp9Descriptor.writeStructure(out, STRUCTURE);
            out.put((byte) 0x99).flip();
            var descriptor = Vp9Descriptor.parse(out);
            assertFalse(descriptor.flexible());
            assertEquals(OptionalInt.of(5), descriptor.pictureId());
            assertFalse(descriptor.longPictureId());
            assertEquals(OptionalInt.of(0x31), descriptor.tl0PicIndex());
            assertEquals(Optional.of(STRUCTURE), descriptor.structure());
            assertEquals(out.limit() - 1, descriptor.size());
            assertEquals(Vp9Descriptor.sizeOf(STRUCTURE), descriptor.size() - 4);
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "80", "8080", "a0", "20", "5000", "5001", "50030507090b", "02", "0200",
                "021000", "0208", "02080102"})
        @DisplayName("rejects truncated or inconsistent descriptors")
        void rejects(String hex) {
            var data = java.util.HexFormat.of().parseHex(hex);
            assertThrows(PayloadFormatException.class, () -> Vp9Descriptor.parse(ByteBuffer.wrap(data)));
        }
    }

    @Nested
    @DisplayName("packetization")
    class Packetization {
        @ParameterizedTest(name = "max payload {0}")
        @ValueSource(ints = {64, 77, 200, 1100})
        @DisplayName("round-trips a keyframe with a scalability structure across payload sizes")
        void roundTrip(int maxPayload) throws PayloadFormatException {
            var data = keyframe(320, 180, 3000);
            var metadata = new Vp9FrameMetadata(OptionalInt.of(77), OptionalInt.empty(), OptionalInt.of(0),
                    OptionalInt.of(0), false, false, false, false, true, List.of(), Optional.of(STRUCTURE), false,
                    Optional.empty(), OptionalLong.empty(), List.of());
            var frame = new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), 9000, true, Optional.empty(), metadata);
            var payloads = FORMAT.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(maxPayload)).packetize(frame);
            for (var payload : payloads) {
                assertTrue(payload.payload().remaining() <= maxPayload);
                assertFalse(payload.marker());
            }
            var rtp = packets(payloads, 98, 100, 9000);
            var depacketizer = FORMAT.depacketizer();
            var boundaries = depacketizer.inspect(rtp.getFirst());
            assertTrue(boundaries.frameStart() && boundaries.keyframe() && boundaries.explicitStart());
            assertTrue(depacketizer.inspect(rtp.getLast()).frameEnd());
            assertTrue(FORMAT.isKeyframe(rtp.getFirst().payload()));
            var assembled = depacketizer.assemble(rtp);
            assertArrayEquals(data, assembled.toByteArray());
            assertTrue(assembled.keyframe());
            var read = (Vp9FrameMetadata) assembled.metadata();
            assertEquals(OptionalInt.of(77), read.pictureId());
            assertEquals(Optional.of(STRUCTURE), read.scalabilityStructure());
            assertEquals(Optional.of(new Resolution(320, 180)), read.resolution());
            assertFalse(read.endOfPicture());
        }

        @Test
        @DisplayName("sends the upper spatial layer with D, the picture's id and the marker")
        void upperLayer() throws PayloadFormatException {
            var packetizer = FORMAT.packetizer();
            var depacketizer = FORMAT.depacketizer();
            var base = layer(0, false, false);
            var upper = layer(1, true, true);
            var baseRtp = packets(packetizer.packetize(base), 98, 1, 0);
            var upperRtp = packets(packetizer.packetize(upper), 98, baseRtp.size() + 1, 0);
            var baseFrame = depacketizer.assemble(baseRtp);
            var upperFrame = depacketizer.assemble(upperRtp);
            var baseMetadata = (Vp9FrameMetadata) baseFrame.metadata();
            var upperMetadata = (Vp9FrameMetadata) upperFrame.metadata();
            assertEquals(baseMetadata.pictureId(), upperMetadata.pictureId());
            assertTrue(upperMetadata.interLayerPredicted());
            assertFalse(upperFrame.keyframe());
            assertTrue(upperMetadata.endOfPicture());
            assertTrue(upperRtp.getLast().marker());
            assertFalse(baseRtp.getLast().marker());
            assertEquals(1, depacketizer.inspect(upperRtp.getFirst()).spatialId());
            assertEquals(Optional.of(new Resolution(640, 360)), upperMetadata.resolution());
            var next = packetizer.packetize(layer(0, false, false));
            var nextMetadata = (Vp9FrameMetadata) depacketizer.assemble(packets(next, 98, 50, 3000)).metadata();
            assertEquals((baseMetadata.pictureId().orElseThrow() + 1) & 0x7FFF, nextMetadata.pictureId().orElseThrow());
        }

        @Test
        @DisplayName("sends a frame without metadata as flexible, referencing the previous picture")
        void defaults() throws PayloadFormatException {
            var frame = EncodedFrame.of(MediaKind.VIDEO, bytes(1, 2, 3), 0, false);
            var metadata = (Vp9FrameMetadata) FORMAT.depacketizer()
                    .assemble(packets(FORMAT.packetizer().packetize(frame), 98, 1, 0)).metadata();
            assertTrue(metadata.flexibleMode());
            assertTrue(metadata.interPicturePredicted());
            assertEquals(List.of(1), metadata.referenceDiffs());
            assertTrue(metadata.endOfPicture());
            var predicted = new Vp9FrameMetadata(OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(),
                    OptionalInt.empty(), false, false, true, false, true, List.of(), Optional.empty(), true,
                    Optional.empty(), OptionalLong.empty(), List.of());
            assertThrows(IllegalArgumentException.class, () -> FORMAT.packetizer().packetize(
                    new EncodedFrame(MediaKind.VIDEO, bytes(1), 0, false, Optional.empty(), predicted)));
        }

        @Test
        @DisplayName("reads the size of profile 0 to 3 key frames")
        void keyframeSizes() {
            assertEquals(Optional.of(new Resolution(1920, 1080)), Vp9Depacketizer.keyframeResolution(
                    keyframe(1920, 1080, 20)));
            var profile1 = new TestPackets.BitWriter()
                    .bits(2, 2).bits(1, 1).bits(0, 1)
                    .bits(0, 1).bits(0, 1).bits(1, 1).bits(0, 1)
                    .bits(0x498342, 24)
                    .bits(2, 3).bits(0, 1).bits(1, 1).bits(0, 1).bits(0, 1)
                    .bits(639, 16).bits(479, 16)
                    .toBytes();
            assertEquals(Optional.of(new Resolution(640, 480)), Vp9Depacketizer.keyframeResolution(profile1));
            assertTrue(Vp9Depacketizer.keyframeResolution(new byte[]{(byte) 0x84, 0, 0, 0}).isEmpty());
            assertTrue(Vp9Depacketizer.keyframeResolution(new byte[]{(byte) 0x80}).isEmpty());
        }

        @Test
        @DisplayName("rejects layer frames without their beginning or end")
        void rejects() {
            var middle = packet(98, false, 1, 0, bytes(0x80, 0x01, 0xAA));
            assertThrows(PayloadFormatException.class, () -> FORMAT.depacketizer().assemble(List.of(middle)));
            var unfinished = packet(98, false, 1, 0, bytes(0x88, 0x01, 0xAA));
            assertThrows(PayloadFormatException.class, () -> FORMAT.depacketizer().assemble(List.of(unfinished)));
        }

        /// {@return a non-flexible layer frame of a two-layer stream}
        private static EncodedFrame layer(int spatial, boolean interLayer, boolean endOfPicture) {
            var metadata = new Vp9FrameMetadata(OptionalInt.empty(), OptionalInt.empty(), OptionalInt.of(spatial),
                    OptionalInt.of(0), false, interLayer, false, false, false, List.of(),
                    spatial == 0 ? Optional.of(STRUCTURE) : Optional.empty(), endOfPicture, Optional.empty(),
                    OptionalLong.empty(), List.of());
            return new EncodedFrame(MediaKind.VIDEO, bytes(1, 2, 3, 4), 0, spatial == 0, Optional.empty(), metadata);
        }
    }

    @Test
    @DisplayName("rewrites picture ids and TL0PICIDX continuously across a source switch")
    void rewriter() throws PayloadFormatException {
        var rewriter = new Vp9PayloadRewriter();
        var first = bytes(0xA8, 0x80 | 0x01, 0x00, 0x00, 0x10, 0x11);
        rewriter.rewrite(first);
        rewriter.switchSource();
        var second = bytes(0xA8, 0x80 | 0x20, 0x00, 0x00, 0x77, 0x11);
        rewriter.rewrite(second);
        var descriptor = Vp9Descriptor.parse(second);
        assertEquals(OptionalInt.of(0x0101), descriptor.pictureId());
        assertEquals(OptionalInt.of(0x11), descriptor.tl0PicIndex());
    }

    @Test
    @DisplayName("survives random payloads: inspect never throws, assemble only throws PayloadFormatException")
    void fuzz() {
        var random = new Random(9628);
        for (var i = 0; i < 5000; i++) {
            var data = new byte[random.nextInt(40)];
            random.nextBytes(data);
            var rtp = packet(98, random.nextBoolean(), i & 0xFFFF, 0, ByteBuffer.wrap(data));
            var depacketizer = FORMAT.depacketizer();
            depacketizer.inspect(rtp);
            FORMAT.isKeyframe(ByteBuffer.wrap(data));
            try {
                depacketizer.assemble(List.of(rtp));
            } catch (PayloadFormatException expected) {
                // Malformed input is reported this way and only this way.
            }
        }
    }
}
