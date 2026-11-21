package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.media.Vp8FrameMetadata;
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

import static com.github.auties00.parley.payload.TestPackets.array;
import static com.github.auties00.parley.payload.TestPackets.bytes;
import static com.github.auties00.parley.payload.TestPackets.packet;
import static com.github.auties00.parley.payload.TestPackets.packets;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the VP8 payload format of RFC 7741: the payload descriptor examples, packetization round trips across
/// payload sizes, keyframe detection and size, temporal layer fields, and the forwarding rewriter.
@DisplayName("VP8 payload format")
class Vp8PayloadTest {
    /// The format under test.
    private static final Vp8Format FORMAT = new Vp8Format(Codec.vp8());

    /// {@return the first bytes of a VP8 key frame of a size: frame tag, start code, dimensions}
    static byte[] keyframe(int width, int height, int length) {
        var data = new byte[length];
        data[0] = 0x10;
        data[3] = (byte) 0x9D;
        data[4] = 0x01;
        data[5] = 0x2A;
        data[6] = (byte) width;
        data[7] = (byte) (width >>> 8);
        data[8] = (byte) height;
        data[9] = (byte) (height >>> 8);
        for (var i = 10; i < length; i++) {
            data[i] = (byte) (i * 7);
        }
        return data;
    }

    @Nested
    @DisplayName("descriptor")
    class Descriptor {
        @Test
        @DisplayName("parses the RFC 7741 examples: 7-bit and 15-bit picture ids, TL0PICIDX, TID/Y/KEYIDX")
        void parses() throws PayloadFormatException {
            var minimal = Vp8Descriptor.parse(bytes(0x10, 0x00));
            assertTrue(minimal.startOfPartition());
            assertEquals(1, minimal.size());
            assertTrue(minimal.pictureId().isEmpty());
            var shortId = Vp8Descriptor.parse(bytes(0x90, 0x80, 0x11, 0x00));
            assertEquals(OptionalInt.of(0x11), shortId.pictureId());
            assertFalse(shortId.longPictureId());
            var full = Vp8Descriptor.parse(bytes(0xB4, 0xF0, 0x81, 0x23, 0x45, 0x67, 0x00));
            assertTrue(full.nonReference());
            assertTrue(full.startOfPartition());
            assertEquals(4, full.partitionIndex());
            assertEquals(OptionalInt.of(0x0123), full.pictureId());
            assertTrue(full.longPictureId());
            assertEquals(OptionalInt.of(0x45), full.tl0PicIndex());
            assertEquals(OptionalInt.of(1), full.temporalId());
            assertTrue(full.layerSync());
            assertEquals(OptionalInt.of(7), full.keyIndex());
            assertEquals(6, full.size());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "80", "8080", "808081", "8040", "8020", "10"})
        @DisplayName("rejects truncated descriptors and descriptors without data")
        void truncated(String hex) {
            var data = java.util.HexFormat.of().parseHex(hex);
            assertThrows(PayloadFormatException.class, () -> Vp8Descriptor.parse(ByteBuffer.wrap(data)));
        }
    }

    @Nested
    @DisplayName("packetization")
    class Packetization {
        @ParameterizedTest(name = "max payload {0}")
        @ValueSource(ints = {64, 65, 100, 512, 1100, 1500})
        @DisplayName("round-trips a keyframe across payload sizes")
        void roundTrip(int maxPayload) throws PayloadFormatException {
            var data = keyframe(1280, 720, 4000);
            var frame = new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), 3000, true, Optional.empty(),
                    Vp8FrameMetadata.none().withPictureId(0x7FFE, OptionalInt.empty()));
            var payloads = FORMAT.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(maxPayload)).packetize(frame);
            for (var payload : payloads) {
                assertTrue(payload.payload().remaining() <= maxPayload);
            }
            assertTrue(payloads.getLast().marker());
            assertEquals(1, payloads.stream().filter(PacketizedPayload::marker).count());
            var rtp = packets(payloads, 96, 65530, 3000);
            var depacketizer = FORMAT.depacketizer();
            var first = depacketizer.inspect(rtp.getFirst());
            assertTrue(first.frameStart() && first.explicitStart() && first.keyframe());
            assertTrue(depacketizer.inspect(rtp.getLast()).frameEnd());
            if (rtp.size() > 1) {
                assertFalse(depacketizer.inspect(rtp.get(1)).frameStart());
            }
            var assembled = depacketizer.assemble(rtp);
            assertArrayEquals(data, assembled.toByteArray());
            assertTrue(assembled.keyframe());
            var metadata = (Vp8FrameMetadata) assembled.metadata();
            assertEquals(OptionalInt.of(0x7FFE), metadata.pictureId());
            assertEquals(Optional.of(new Resolution(1280, 720)), metadata.resolution());
            assertTrue(FORMAT.isKeyframe(rtp.getFirst().payload()));
        }

        @Test
        @DisplayName("numbers pictures when the metadata has none, wrapping at 15 bits")
        void numbersPictures() throws PayloadFormatException {
            var packetizer = FORMAT.packetizer();
            var depacketizer = FORMAT.depacketizer();
            var first = picture(depacketizer, packetizer.packetize(delta(0)));
            var second = picture(depacketizer, packetizer.packetize(delta(3000)));
            assertEquals((first + 1) & 0x7FFF, second);
            var fixed = new EncodedFrame(MediaKind.VIDEO, bytes(1, 2, 3), 6000, false, Optional.empty(),
                    Vp8FrameMetadata.none().withPictureId(0x7FFF, OptionalInt.empty()));
            assertEquals(0x7FFF, picture(depacketizer, packetizer.packetize(fixed)));
            assertEquals(0, picture(depacketizer, packetizer.packetize(delta(9000))));
        }

        @Test
        @DisplayName("writes temporal layer fields and generates TL0PICIDX on base layer frames")
        void temporalLayers() throws PayloadFormatException {
            var packetizer = FORMAT.packetizer();
            var depacketizer = FORMAT.depacketizer();
            Integer previous = null;
            var layers = new int[]{0, 2, 1, 2, 0};
            for (var i = 0; i < layers.length; i++) {
                var frame = new EncodedFrame(MediaKind.VIDEO, bytes(1, 2, 3), i * 3000L, false, Optional.empty(),
                        Vp8FrameMetadata.ofTemporalLayer(layers[i], layers[i] == 2));
                var rtp = packets(packetizer.packetize(frame), 96, i, i * 3000L);
                var metadata = (Vp8FrameMetadata) depacketizer.assemble(rtp).metadata();
                assertEquals(OptionalInt.of(layers[i]), metadata.temporalId());
                assertEquals(layers[i] == 2, metadata.layerSync());
                var tl0 = metadata.tl0PicIndex().orElseThrow();
                if (previous != null) {
                    assertEquals(layers[i] == 0 ? (previous + 1) & 0xFF : previous, tl0);
                }
                previous = tl0;
                assertEquals(layers[i], depacketizer.inspect(rtp.getFirst()).temporalId());
            }
        }

        @Test
        @DisplayName("keeps a non-reference flag and key index")
        void flags() throws PayloadFormatException {
            var metadata = new Vp8FrameMetadata(OptionalInt.of(5), 15, OptionalInt.of(9), OptionalInt.of(1), false,
                    OptionalInt.of(17), true, Optional.empty(), OptionalLong.empty(), List.of());
            var frame = new EncodedFrame(MediaKind.VIDEO, bytes(1, 2, 3), 0, false, Optional.empty(), metadata);
            var assembled = FORMAT.depacketizer().assemble(packets(FORMAT.packetizer().packetize(frame), 96, 1, 0));
            assertEquals(metadata, assembled.metadata());
        }

        @Test
        @DisplayName("rejects frames that do not start at partition 0, and inspects garbage as invalid")
        void rejects() {
            var middle = packet(96, true, 1, 0, bytes(0x00, 0x01));
            assertThrows(PayloadFormatException.class, () -> FORMAT.depacketizer().assemble(List.of(middle)));
            assertFalse(FORMAT.depacketizer().inspect(packet(96, true, 1, 0, bytes(0x80))).valid());
            assertFalse(FORMAT.isKeyframe(bytes(0x80)));
            assertFalse(FORMAT.isKeyframe(bytes(0x10, 0x01)));
            assertThrows(IllegalArgumentException.class,
                    () -> FORMAT.packetizer().packetize(EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.allocate(0), 0, true)));
        }

        /// {@return a delta frame without metadata}
        private static EncodedFrame delta(long timestamp) {
            return EncodedFrame.of(MediaKind.VIDEO, bytes(1, 2, 3), timestamp, false);
        }

        /// {@return the picture id of a packetized frame}
        private static int picture(Depacketizer depacketizer, List<PacketizedPayload> payloads)
                throws PayloadFormatException {
            var metadata = (Vp8FrameMetadata) depacketizer.assemble(packets(payloads, 96, 1, 0)).metadata();
            return metadata.pictureId().orElseThrow();
        }
    }

    @Nested
    @DisplayName("forwarding rewriter")
    class Rewriter {
        @Test
        @DisplayName("keeps picture ids and TL0PICIDX continuous across a source switch")
        void switches() throws PayloadFormatException {
            var rewriter = new Vp8PayloadRewriter();
            assertEquals(new int[]{100, 7}[0], rewrite(rewriter, 100, 7)[0]);
            assertEquals(101, rewrite(rewriter, 101, 8)[0]);
            rewriter.switchSource();
            var switched = rewrite(rewriter, 5000, 200);
            assertEquals(102, switched[0]);
            assertEquals(9, switched[1]);
            var next = rewrite(rewriter, 5001, 201);
            assertEquals(103, next[0]);
            assertEquals(10, next[1]);
            assertEquals(103, rewrite(rewriter, 5001, 201)[0]);
        }

        @Test
        @DisplayName("wraps a 7-bit picture id and leaves payloads without one alone")
        void shortIds() throws PayloadFormatException {
            var rewriter = new Vp8PayloadRewriter();
            var payload = bytes(0x90, 0x80, 0x7F, 0x00);
            rewriter.rewrite(payload);
            assertEquals(0x7F, payload.get(2));
            rewriter.switchSource();
            var other = bytes(0x90, 0x80, 0x10, 0x00);
            rewriter.rewrite(other);
            assertEquals(0x00, other.get(2));
            var bare = bytes(0x10, 0x00);
            rewriter.rewrite(bare);
            assertArrayEquals(new byte[]{0x10, 0x00}, array(bare));
            assertThrows(java.nio.ReadOnlyBufferException.class,
                    () -> rewriter.rewrite(bytes(0x90, 0x80, 0x01, 0x00).asReadOnlyBuffer()));
        }

        /// {@return the rewritten picture id and TL0PICIDX of a packet with a 15-bit id}
        private static int[] rewrite(Vp8PayloadRewriter rewriter, int pictureId, int tl0)
                throws PayloadFormatException {
            var payload = ByteBuffer.allocate(6);
            Vp8Descriptor.write(payload, false, true, OptionalInt.of(pictureId), false, OptionalInt.of(tl0),
                    OptionalInt.empty(), false, OptionalInt.empty());
            payload.put((byte) 0).flip();
            rewriter.rewrite(payload);
            var descriptor = Vp8Descriptor.parse(payload);
            return new int[]{descriptor.pictureId().orElseThrow(), descriptor.tl0PicIndex().orElseThrow()};
        }
    }

    @Test
    @DisplayName("survives random payloads: inspect never throws, assemble only throws PayloadFormatException")
    void fuzz() {
        var random = new Random(7741);
        for (var i = 0; i < 5000; i++) {
            var data = new byte[random.nextInt(24)];
            random.nextBytes(data);
            var rtp = packet(96, random.nextBoolean(), i & 0xFFFF, 0, ByteBuffer.wrap(data));
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
