package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.RtpPacket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.Stream;

import static com.github.auties00.parley.payload.TestPackets.packets;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Property tests: random frames of every video format survive packetize then depacketize unchanged, at random
/// payload sizes, with every payload within the size and exactly one marker at the end, and every packet inspected
/// as valid with the first one starting the frame.
@DisplayName("video round trips")
class VideoRoundTripTest {
    /// One format with its frame generator.
    ///
    /// @param name      the display name
    /// @param format    the format
    /// @param generator makes a frame's bytes from a random source
    /// @param expected  the bytes the depacketizer returns for those bytes
    private record Case(String name, PayloadFormat format, Function<Random, byte[]> generator,
                        Function<byte[], byte[]> expected) {
    }

    @TestFactory
    @DisplayName("random frames at random payload sizes")
    Stream<DynamicTest> roundTrips() {
        var cases = List.of(
                new Case("VP8", new Vp8Format(Codec.vp8()), random -> randomBytes(random, 1 + random.nextInt(6000)),
                        Function.identity()),
                new Case("VP9", new Vp9Format(Codec.vp9()), random -> randomBytes(random, 1 + random.nextInt(6000)),
                        Function.identity()),
                new Case("H.264", new H264Format(Codec.h264()), VideoRoundTripTest::annexB,
                        VideoRoundTripTest::canonicalAnnexB),
                new Case("H.265", new H265Format(Codec.h265()), VideoRoundTripTest::annexB265,
                        VideoRoundTripTest::canonicalAnnexB),
                new Case("AV1", new Av1Format(Codec.av1()), VideoRoundTripTest::temporalUnit, Function.identity()),
                new Case("passthrough", new GenericFormat(Codec.of("video/x-test", 90000)),
                        random -> randomBytes(random, 1 + random.nextInt(6000)), Function.identity()));
        return cases.stream().map(test -> DynamicTest.dynamicTest(test.name(), () -> {
            var random = new Random(test.name().hashCode());
            for (var iteration = 0; iteration < 300; iteration++) {
                var maxPayload = PacketizerConfig.MIN_PAYLOAD_SIZE + random.nextInt(1400);
                var data = test.generator().apply(random);
                var frame = EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(data), random.nextLong(1L << 32),
                        random.nextBoolean());
                var payloads = test.format().packetizer(new PacketizerConfig(maxPayload)).packetize(frame);
                for (var i = 0; i < payloads.size(); i++) {
                    assertTrue(payloads.get(i).payload().remaining() <= maxPayload);
                    assertEquals(i == payloads.size() - 1, payloads.get(i).marker());
                }
                List<RtpPacket> rtp = packets(payloads, 96, random.nextInt(65536), frame.rtpTimestamp());
                var depacketizer = test.format().depacketizer();
                for (var i = 0; i < rtp.size(); i++) {
                    var boundaries = depacketizer.inspect(rtp.get(i));
                    assertTrue(boundaries.valid());
                    assertEquals(i == rtp.size() - 1, boundaries.frameEnd());
                }
                if (!(test.format() instanceof GenericFormat)) {
                    assertTrue(depacketizer.inspect(rtp.getFirst()).frameStart(), test.name());
                }
                var assembled = depacketizer.assemble(rtp);
                assertArrayEquals(test.expected().apply(data), assembled.toByteArray());
                assertEquals(frame.rtpTimestamp(), assembled.rtpTimestamp());
            }
        }));
    }

    /// {@return random bytes}
    private static byte[] randomBytes(Random random, int length) {
        var data = new byte[length];
        random.nextBytes(data);
        return data;
    }

    /// {@return an H.264 access unit: an access unit delimiter then random slices without zero bytes}
    private static byte[] annexB(Random random) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{0, 0, 0, 1, 0x09, (byte) 0xF0});
        var count = 1 + random.nextInt(5);
        for (var i = 0; i < count; i++) {
            out.writeBytes(new byte[]{0, 0, 1});
            var nal = nonZero(random, 2 + random.nextInt(3000));
            nal[0] = (byte) 0x41;
            out.writeBytes(nal);
        }
        return out.toByteArray();
    }

    /// {@return an H.265 access unit: an access unit delimiter then random slices without zero bytes}
    private static byte[] annexB265(Random random) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(new byte[]{0, 0, 0, 1, 0x46, 0x01, 0x50});
        var count = 1 + random.nextInt(5);
        for (var i = 0; i < count; i++) {
            out.writeBytes(new byte[]{0, 0, 0, 1});
            var nal = nonZero(random, 3 + random.nextInt(3000));
            nal[0] = 0x02;
            nal[1] = 0x01;
            out.writeBytes(nal);
        }
        return out.toByteArray();
    }

    /// {@return an AV1 temporal unit of random frame OBUs in low-overhead format, without temporal delimiter}
    private static byte[] temporalUnit(Random random) {
        var out = new ByteArrayOutputStream();
        var count = 1 + random.nextInt(4);
        for (var i = 0; i < count; i++) {
            var payload = randomBytes(random, 1 + random.nextInt(2500));
            var extension = random.nextBoolean();
            out.writeBytes(Av1PayloadTest.obu(6, random.nextInt(8), random.nextInt(4), extension, payload));
        }
        return out.toByteArray();
    }

    /// {@return bytes from 1 to 255}
    private static byte[] nonZero(Random random, int length) {
        var data = new byte[length];
        for (var i = 0; i < length; i++) {
            data[i] = (byte) (1 + random.nextInt(255));
        }
        return data;
    }

    /// {@return an Annex B stream rewritten with four-byte start codes, as depacketizers write it}
    private static byte[] canonicalAnnexB(byte[] stream) {
        var out = new ByteArrayOutputStream();
        var units = new ArrayList<>(NalUnits.splitAnnexB(ByteBuffer.wrap(stream)));
        for (var unit : units) {
            NalUnits.appendAnnexB(out, unit);
        }
        return out.toByteArray();
    }
}
