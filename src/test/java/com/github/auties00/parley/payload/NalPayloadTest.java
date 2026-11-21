package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.H264FrameMetadata;
import com.github.auties00.parley.media.H265FrameMetadata;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.rtp.RtpPacket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

import static com.github.auties00.parley.payload.TestPackets.array;
import static com.github.auties00.parley.payload.TestPackets.bytes;
import static com.github.auties00.parley.payload.TestPackets.packet;
import static com.github.auties00.parley.payload.TestPackets.packets;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the NAL-unit payload formats: H.264 (RFC 6184 single NAL unit, STAP-A, FU-A, packetization modes,
/// parameter set insertion, `sprop-parameter-sets`, SPS resolution) and H.265 (RFC 7798 AP and FU, IRAP keyframes,
/// SPS resolution).
@DisplayName("NAL-unit payload formats")
class NalPayloadTest {
    /// A 640x480 Constrained Baseline SPS.
    static final byte[] SPS_640 = h264Sps(66, 0xE0, 640, 480, 0);

    /// A PPS.
    static final byte[] PPS = {0x68, (byte) 0xCE, 0x3C, (byte) 0x80};

    /// {@return an H.264 SPS of a profile and size, cropping `cropBottom` chroma rows off the bottom}
    static byte[] h264Sps(int profile, int constraints, int width, int height, int cropBottom) {
        var writer = new TestPackets.BitWriter().bits(0x67, 8).bits(profile, 8).bits(constraints, 8).bits(31, 8).ue(0);
        if (profile == 100) {
            writer.ue(1).ue(0).ue(0).bits(0, 1).bits(1, 1);
            writer.bits(1, 1);
            for (var j = 0; j < 16; j++) {
                writer.se(j % 2 == 0 ? 3 : -2);
            }
            for (var i = 1; i < 8; i++) {
                writer.bits(0, 1);
            }
            writer.ue(0).ue(0).ue(2);
        } else {
            writer.ue(0).ue(2);
        }
        writer.ue(1).bits(0, 1).ue(width / 16 - 1).ue((height + 15) / 16 - 1).bits(1, 1).bits(1, 1);
        if (cropBottom > 0) {
            writer.bits(1, 1).ue(0).ue(0).ue(0).ue(cropBottom);
        } else {
            writer.bits(0, 1);
        }
        writer.bits(0, 1);
        return writer.toBytesWithStopBit();
    }

    /// {@return an H.265 SPS of a size with `subLayers` sub-layers and a conformance window bottom crop}
    static byte[] h265Sps(int width, int height, int cropBottom, int subLayers) {
        var writer = new TestPackets.BitWriter().bits(0x42, 8).bits(0x01, 8)
                .bits(0, 4).bits(subLayers - 1, 3).bits(1, 1)
                .bits(0x01, 8).bits(0x60000000L, 32).bits(0, 32).bits(0, 16).bits(93, 8);
        for (var i = 0; i < subLayers - 1; i++) {
            writer.bits(1, 1).bits(1, 1);
        }
        if (subLayers > 1) {
            for (var i = subLayers - 1; i < 8; i++) {
                writer.bits(0, 2);
            }
        }
        for (var i = 0; i < subLayers - 1; i++) {
            writer.bits(0, 32).bits(0, 32).bits(0, 24).bits(90, 8);
        }
        writer.ue(0).ue(1).ue(width).ue(height);
        if (cropBottom > 0) {
            writer.bits(1, 1).ue(0).ue(0).ue(0).ue(cropBottom);
        } else {
            writer.bits(0, 1);
        }
        return writer.toBytesWithStopBit();
    }

    /// {@return an Annex B stream of NAL units, alternating three- and four-byte start codes}
    static ByteBuffer annexB(byte[]... nals) {
        var out = new ByteArrayOutputStream();
        for (var i = 0; i < nals.length; i++) {
            if (i % 2 == 0) {
                out.write(0);
            }
            out.writeBytes(new byte[]{0, 0, 1});
            out.writeBytes(nals[i]);
        }
        return ByteBuffer.wrap(out.toByteArray());
    }

    /// {@return a NAL unit of a header followed by `length - header.length` pseudo-random bytes without zeros}
    static byte[] nal(int length, int... header) {
        var data = new byte[length];
        var random = new Random(length * 31L + header[0]);
        for (var i = 0; i < length; i++) {
            data[i] = (byte) (1 + random.nextInt(255));
        }
        for (var i = 0; i < header.length; i++) {
            data[i] = (byte) header[i];
        }
        return data;
    }

    /// {@return the NAL units of an Annex B buffer as arrays}
    static List<byte[]> units(ByteBuffer stream) {
        return NalUnits.splitAnnexB(stream).stream().map(TestPackets::array).toList();
    }

    @Nested
    @DisplayName("NAL unit plumbing")
    class Plumbing {
        @Test
        @DisplayName("splits Annex B streams with mixed start codes and trailing zeros")
        void splits() {
            var stream = bytes(0, 0, 0, 1, 0x67, 1, 2, 0, 0, 0, 1, 0x68, 3, 0, 0, 1, 0x65, 4, 0, 0);
            var nals = units(stream);
            assertEquals(3, nals.size());
            assertArrayEquals(new byte[]{0x67, 1, 2}, nals.get(0));
            assertArrayEquals(new byte[]{0x68, 3}, nals.get(1));
            assertArrayEquals(new byte[]{0x65, 4}, nals.get(2));
            assertThrows(IllegalArgumentException.class, () -> NalUnits.splitAnnexB(bytes(0x67, 0, 0, 1, 0x68)));
            assertThrows(IllegalArgumentException.class, () -> NalUnits.splitAnnexB(bytes(0, 0, 1, 0, 0, 1, 0x68)));
            assertThrows(IllegalArgumentException.class, () -> NalUnits.splitAnnexB(bytes(0, 0, 0)));
        }

        @Test
        @DisplayName("removes emulation prevention bytes")
        void unescapes() {
            assertArrayEquals(new byte[]{0x67, 0, 0, 1, 0, 0, 3},
                    NalUnits.unescape(bytes(0x67, 0, 0, 3, 1, 0, 0, 3, 3), 100));
        }

        @Test
        @DisplayName("reads H.264 SPS sizes, with High profile scaling lists and cropping")
        void h264Sizes() {
            assertEquals(Optional.of(new Resolution(640, 480)), NalUnits.h264Resolution(ByteBuffer.wrap(SPS_640)));
            assertEquals(Optional.of(new Resolution(1920, 1080)),
                    NalUnits.h264Resolution(ByteBuffer.wrap(h264Sps(100, 0, 1920, 1088, 4))));
            assertEquals(Optional.of(new Resolution(1280, 720)),
                    NalUnits.h264Resolution(ByteBuffer.wrap(h264Sps(66, 0xC0, 1280, 720, 0))));
            assertTrue(NalUnits.h264Resolution(bytes(0x67, 66)).isEmpty());
        }

        @Test
        @DisplayName("reads H.265 SPS sizes, with sub-layers and a conformance window")
        void h265Sizes() {
            assertEquals(Optional.of(new Resolution(1920, 1080)),
                    NalUnits.h265Resolution(ByteBuffer.wrap(h265Sps(1920, 1088, 4, 1))));
            assertEquals(Optional.of(new Resolution(640, 360)),
                    NalUnits.h265Resolution(ByteBuffer.wrap(h265Sps(640, 360, 0, 3))));
            assertTrue(NalUnits.h265Resolution(bytes(0x42, 0x01, 0x01)).isEmpty());
        }
    }

    @Nested
    @DisplayName("H.264")
    class H264 {
        /// Packetization mode 1.
        private final H264Format format = new H264Format(Codec.h264());

        @ParameterizedTest(name = "max payload {0}")
        @ValueSource(ints = {64, 100, 1100, 1400})
        @DisplayName("round-trips an IDR access unit across payload sizes with STAP-A and FU-A")
        void roundTrip(int maxPayload) throws PayloadFormatException {
            var idr = nal(5000, 0x65, 0x88);
            var payloads = format.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(maxPayload)).packetize(frame(annexB(SPS_640, PPS, idr)));
            for (var payload : payloads) {
                assertTrue(payload.payload().remaining() <= maxPayload);
            }
            assertEquals(H264Packetizer.STAP_A, payloads.getFirst().payload().get(0) & 0x1F);
            assertEquals(H264Packetizer.FU_A, payloads.getLast().payload().get(0) & 0x1F);
            var rtp = packets(payloads, 102, 65000, 900);
            var depacketizer = format.depacketizer();
            var first = depacketizer.inspect(rtp.getFirst());
            assertTrue(first.frameStart() && first.keyframe());
            assertFalse(first.explicitStart());
            assertTrue(depacketizer.inspect(rtp.getLast()).frameEnd());
            assertTrue(format.isKeyframe(rtp.getFirst().payload()));
            assertTrue(format.isKeyframe(rtp.getLast().payload()));
            var assembled = depacketizer.assemble(rtp);
            var nals = units(assembled.data());
            assertEquals(3, nals.size());
            assertArrayEquals(SPS_640, nals.get(0));
            assertArrayEquals(PPS, nals.get(1));
            assertArrayEquals(idr, nals.get(2));
            assertTrue(assembled.keyframe());
            var metadata = (H264FrameMetadata) assembled.metadata();
            assertTrue(metadata.idr());
            assertEquals(List.of(7, 8, 5), metadata.nalUnitTypes());
            assertEquals(Optional.of(new Resolution(640, 480)), metadata.resolution());
        }

        @Test
        @DisplayName("aggregates the max-size STAP-A exactly and sends single NAL units as slices")
        void aggregation() {
            var small = nal(100, 0x41, 0x80);
            var payloads = format.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(1 + 2 * (2 + 100))).packetize(frame(annexB(small, small)));
            assertEquals(1, payloads.size());
            var single = format.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(100)).packetize(frame(annexB(small)));
            assertEquals(1, single.size());
            assertArrayEquals(small, array(single.getFirst().payload()));
            assertTrue(single.getFirst().payload().isReadOnly());
        }

        @Test
        @DisplayName("sends only single NAL units in packetization mode 0, rejecting oversized ones")
        void modeZero() {
            var mode0 = new H264Format(Codec.of("video/H264", 90000));
            assertEquals(0, mode0.packetizationMode());
            var payloads = mode0.packetizer().packetize(frame(annexB(SPS_640, PPS, nal(200, 0x65, 0x88))));
            assertEquals(3, payloads.size());
            assertThrows(IllegalArgumentException.class,
                    () -> mode0.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(100)).packetize(frame(annexB(nal(200, 0x65)))));
            var mode2 = new H264Format(Codec.h264().withFormatParameters(Map.of("packetization-mode", "2")));
            assertThrows(IllegalArgumentException.class, mode2::packetizer);
        }

        @Test
        @DisplayName("inserts remembered SPS and PPS before an IDR picture on both sides")
        void parameterSetInsertion() throws PayloadFormatException {
            var packetizer = format.packetizer();
            packetizer.packetize(frame(annexB(SPS_640, PPS, nal(50, 0x65, 0x88))));
            var withSets = format.depacketizer().assemble(packets(packetizer.packetize(frame(annexB(nal(50, 0x65,
                    0x88)))), 102, 1, 0));
            assertEquals(List.of(7, 8, 5), ((H264FrameMetadata) withSets.metadata()).nalUnitTypes());
            var depacketizer = format.depacketizer();
            var plain = format.packetizer();
            var lonely = depacketizer.assemble(packets(plain.packetize(frame(annexB(nal(50, 0x65, 0x88)))), 102, 1, 0));
            assertFalse(lonely.keyframe());
            depacketizer.assemble(packets(plain.packetize(frame(annexB(SPS_640, PPS, nal(50, 0x65, 0x88)))), 102, 2, 0));
            var later = depacketizer.assemble(packets(format.packetizer().packetize(frame(annexB(nal(50, 0x65, 0x88)))),
                    102, 5, 3000));
            assertTrue(later.keyframe());
            assertEquals(List.of(7, 8, 5), ((H264FrameMetadata) later.metadata()).nalUnitTypes());
            assertEquals(Optional.of(new Resolution(640, 480)), ((H264FrameMetadata) later.metadata()).resolution());
        }

        @Test
        @DisplayName("seeds parameter sets from sprop-parameter-sets")
        void sprop() throws PayloadFormatException {
            var encoder = Base64.getEncoder();
            var codec = Codec.h264().withFormatParameters(Map.of("packetization-mode", "1",
                    "sprop-parameter-sets", encoder.encodeToString(SPS_640) + "," + encoder.encodeToString(PPS) + ",%%"));
            var seeded = new H264Format(codec);
            assertEquals(2, seeded.spropParameterSets().size());
            var frame = seeded.depacketizer().assemble(packets(format.packetizer().packetize(frame(annexB(nal(40, 0x65,
                    0x88)))), 102, 1, 0));
            assertTrue(frame.keyframe());
            assertEquals(Optional.of(new Resolution(640, 480)), ((H264FrameMetadata) frame.metadata()).resolution());
            var payloads = seeded.packetizer().packetize(frame(annexB(nal(40, 0x65, 0x88))));
            assertEquals(H264Packetizer.STAP_A, payloads.getFirst().payload().get(0) & 0x1F);
        }

        @Test
        @DisplayName("tells slice starts from continuation slices")
        void sliceStarts() {
            var depacketizer = format.depacketizer();
            assertTrue(depacketizer.inspect(packet(102, false, 1, 0, bytes(0x41, 0x80, 1))).frameStart());
            assertFalse(depacketizer.inspect(packet(102, false, 1, 0, bytes(0x41, 0x40, 1))).frameStart());
            assertTrue(depacketizer.inspect(packet(102, false, 1, 0, bytes(0x09, 0xF0))).frameStart());
            assertFalse(depacketizer.inspect(packet(102, false, 1, 0, bytes(0x7C, 0x05, 1))).frameStart());
            assertTrue(depacketizer.inspect(packet(102, false, 1, 0, bytes(0x7C, 0x85, 0x80))).frameStart());
            assertFalse(format.isKeyframe(bytes(0x41, 0x80)));
            assertTrue(format.isKeyframe(bytes(0x78, 0, 2, 0x67, 0x42, 0, 2, 0x65, 0x88)));
        }

        @Test
        @DisplayName("rejects broken fragments and interleaved-mode packets")
        void rejects() {
            var depacketizer = format.depacketizer();
            var middle = packet(102, true, 1, 0, bytes(0x7C, 0x05, 1, 2));
            assertThrows(PayloadFormatException.class, () -> depacketizer.assemble(List.of(middle)));
            var unfinished = packet(102, true, 1, 0, bytes(0x7C, 0x85, 1, 2));
            assertThrows(PayloadFormatException.class, () -> depacketizer.assemble(List.of(unfinished)));
            var both = packet(102, true, 1, 0, bytes(0x7C, 0xC5, 1, 2));
            assertFalse(depacketizer.inspect(both).valid());
            for (var type : new int[]{0, 25, 26, 27, 29, 30, 31}) {
                assertFalse(depacketizer.inspect(packet(102, true, 1, 0, bytes(type, 1, 2))).valid());
            }
            assertFalse(depacketizer.inspect(packet(102, true, 1, 0, bytes(0x78, 0, 9, 1))).valid());
            assertFalse(depacketizer.inspect(packet(102, true, 1, 0, ByteBuffer.allocate(0))).valid());
            assertThrows(IllegalArgumentException.class, () -> format.packetizer().packetize(frame(bytes(0x65, 1))));
        }

        /// {@return a video frame}
        private static EncodedFrame frame(ByteBuffer data) {
            return new EncodedFrame(MediaKind.VIDEO, data, 900, false, Optional.empty(), H264FrameMetadata.none());
        }
    }

    @Nested
    @DisplayName("H.265")
    class H265 {
        /// The format.
        private final H265Format format = new H265Format(Codec.h265());

        /// A VPS.
        private static final byte[] VPS = nal(24, 0x40, 0x01);

        /// A PPS.
        private static final byte[] H265_PPS = nal(8, 0x44, 0x01);

        @ParameterizedTest(name = "max payload {0}")
        @ValueSource(ints = {64, 300, 1100})
        @DisplayName("round-trips an IRAP access unit across payload sizes with AP and FU")
        void roundTrip(int maxPayload) throws PayloadFormatException {
            var sps = h265Sps(1280, 720, 0, 1);
            var idr = nal(4000, 19 << 1, 0x01, 0x80);
            var payloads = format.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(maxPayload)).packetize(
                    new EncodedFrame(MediaKind.VIDEO, annexB(VPS, sps, H265_PPS, idr), 0, true, Optional.empty(),
                            H265FrameMetadata.none()));
            for (var payload : payloads) {
                assertTrue(payload.payload().remaining() <= maxPayload);
            }
            var rtp = packets(payloads, 103, 10, 0);
            var depacketizer = format.depacketizer();
            assertTrue(depacketizer.inspect(rtp.getFirst()).frameStart());
            assertTrue(depacketizer.inspect(rtp.getFirst()).keyframe() || maxPayload < 100);
            assertTrue(format.isKeyframe(rtp.getLast().payload()));
            var assembled = depacketizer.assemble(rtp);
            var nals = units(assembled.data());
            assertEquals(4, nals.size());
            assertArrayEquals(idr, nals.get(3));
            assertTrue(assembled.keyframe());
            var metadata = (H265FrameMetadata) assembled.metadata();
            assertTrue(metadata.irap());
            assertEquals(List.of(32, 33, 34, 19), metadata.nalUnitTypes());
            assertEquals(Optional.of(new Resolution(1280, 720)), metadata.resolution());
            if (maxPayload == 1100) {
                assertEquals(H265Packetizer.AP, (payloads.getFirst().payload().get(0) >>> 1) & 0x3F);
            }
        }

        @Test
        @DisplayName("reads the temporal id and rejects PACI, forbidden bits and decoding order numbers")
        void details() throws PayloadFormatException {
            var depacketizer = format.depacketizer();
            var trail = packet(103, true, 1, 0, bytes(0x02, 0x03, 0x80, 1));
            assertEquals(2, depacketizer.inspect(trail).temporalId());
            assertEquals(2, ((H265FrameMetadata) depacketizer.assemble(List.of(trail)).metadata()).temporalId());
            assertFalse(depacketizer.inspect(packet(103, true, 1, 0, bytes(50 << 1, 1, 0, 0))).valid());
            assertFalse(depacketizer.inspect(packet(103, true, 1, 0, bytes(0x82, 1, 0, 0))).valid());
            assertFalse(depacketizer.inspect(packet(103, true, 1, 0, bytes(49 << 1, 1, 0xD3))).valid());
            var don = new H265Format(Codec.h265().withFormatParameters(Map.of("sprop-max-don-diff", "2")));
            assertDoesNotThrow(() -> don.depacketizer());
            assertThrows(IllegalArgumentException.class, don::packetizer);
            assertEquals(1, format.profileId());
            assertEquals(0, format.tierFlag());
            assertEquals(93, format.levelId());
        }

        @Test
        @DisplayName("seeds VPS, SPS and PPS from the sprop parameters")
        void sprop() throws PayloadFormatException {
            var encoder = Base64.getEncoder();
            var codec = Codec.h265().withFormatParameters(Map.of("sprop-vps", encoder.encodeToString(VPS),
                    "sprop-sps", encoder.encodeToString(h265Sps(640, 360, 0, 1)),
                    "sprop-pps", encoder.encodeToString(H265_PPS)));
            var seeded = new H265Format(codec);
            var idr = nal(60, 19 << 1, 0x01, 0x80);
            var rtp = packets(format.packetizer().packetize(new EncodedFrame(MediaKind.VIDEO, annexB(idr), 0, true,
                    Optional.empty(), H265FrameMetadata.none())), 103, 1, 0);
            var frame = seeded.depacketizer().assemble(rtp);
            assertTrue(frame.keyframe());
            assertEquals(4, units(frame.data()).size());
        }
    }

    @Test
    @DisplayName("survives random payloads in both NAL formats")
    void fuzz() {
        var random = new Random(6184);
        var formats = List.<PayloadFormat>of(new H264Format(Codec.h264()), new H265Format(Codec.h265()));
        for (var format : formats) {
            for (var i = 0; i < 5000; i++) {
                var depacketizer = format.depacketizer();
                var run = new ArrayList<RtpPacket>();
                var count = 1 + random.nextInt(3);
                for (var p = 0; p < count; p++) {
                    var data = new byte[random.nextInt(30)];
                    random.nextBytes(data);
                    run.add(packet(102, p == count - 1, p, 0, ByteBuffer.wrap(data)));
                    depacketizer.inspect(run.getLast());
                    format.isKeyframe(ByteBuffer.wrap(data));
                }
                try {
                    depacketizer.assemble(run);
                } catch (PayloadFormatException expected) {
                    // Malformed input is reported this way and only this way.
                }
            }
        }
    }
}
