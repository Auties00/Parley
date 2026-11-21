package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.H264FrameMetadata;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.media.Vp9FrameMetadata;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.PacketizerConfig;
import com.github.auties00.parley.payload.Packetizer;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.payload.TestPackets;
import com.github.auties00.parley.rtp.RtpPacket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers [VideoFrameAssembler] on a manual clock: frame grouping, reordering, NACK and recovery, giving up and
/// keyframe requests, per-format references (VP8 temporal layers, VP9 spatial layers, H.264 continuity, passthrough
/// independence), statistics, and the blocking API.
@DisplayName("VideoFrameAssembler")
class VideoFrameAssemblerTest {
    /// The manual time.
    private final AtomicLong now = new AtomicLong(5_000_000_000L);

    /// The clock reading `now`.
    private final MonotonicClock clock = now::get;

    /// The feedback the assembler sent.
    private final RecordingSink sink = new RecordingSink();

    /// The next sequence number to send.
    private int sequence = 65500;

    /// Records feedback.
    private static final class RecordingSink implements FeedbackSink {
        /// The NACKed sequence numbers, in request order.
        private final List<Integer> nacked = Collections.synchronizedList(new ArrayList<>());

        /// The keyframe requests.
        private final AtomicLong keyframes = new AtomicLong();

        @Override
        public void requestKeyframe() {
            keyframes.incrementAndGet();
        }

        @Override
        public void requestRetransmission(List<Integer> sequences) {
            nacked.addAll(sequences);
        }
    }

    /// {@return an assembler for a codec on the manual clock}
    private VideoFrameAssembler assembler(Codec codec) {
        return VideoFrameAssembler.create(PayloadFormat.of(codec), VideoAssemblerConfig.defaults().withClock(clock),
                sink);
    }

    /// {@return the packets of a frame, numbered from the running sequence number}
    private List<RtpPacket> send(Packetizer packetizer, EncodedFrame frame) {
        var payloads = packetizer.packetize(frame);
        var packets = TestPackets.packets(payloads, 96, sequence & 0xFFFF, frame.rtpTimestamp());
        sequence += payloads.size();
        return packets;
    }

    /// {@return a VP8 frame of a picture id, keyframe or delta, of `length` bytes}
    private static EncodedFrame vp8(int pictureId, boolean key, int length, Vp8FrameMetadata metadata) {
        var data = new byte[length];
        data[0] = (byte) (key ? 0x10 : 0x11);
        return new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), pictureId * 3000L, key, Optional.empty(),
                metadata.withPictureId(pictureId, metadata.tl0PicIndex()));
    }

    /// {@return the frames released now}
    private static List<EncodedFrame> drain(VideoFrameAssembler assembler) {
        var result = new ArrayList<EncodedFrame>();
        Optional<EncodedFrame> frame;
        while ((frame = assembler.poll()).isPresent()) {
            result.add(frame.get());
        }
        return result;
    }

    /// Advances the manual clock.
    private void advance(long millis) {
        now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis));
    }

    @Test
    @DisplayName("releases in-order VP8 frames with picture id references")
    void inOrder() {
        var assembler = assembler(Codec.vp8());
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer(new PacketizerConfig(200));
        var released = new ArrayList<EncodedFrame>();
        for (var i = 0; i < 10; i++) {
            for (var packet : send(packetizer, vp8(100 + i, i == 0, 700, Vp8FrameMetadata.none()))) {
                assembler.insert(packet, now.get());
            }
            advance(33);
            released.addAll(drain(assembler));
        }
        assertEquals(10, released.size());
        for (var i = 0; i < 10; i++) {
            var metadata = released.get(i).metadata();
            if (i == 0) {
                assertTrue(released.get(i).keyframe());
                assertTrue(metadata.dependencies().isEmpty());
            } else {
                var id = metadata.frameId().orElseThrow();
                assertEquals(List.of(id - 1), metadata.dependencies());
            }
        }
        var statistics = assembler.statistics();
        assertEquals(10, statistics.framesReceived());
        assertEquals(10, statistics.jitterBufferEmittedCount());
        assertEquals(1, statistics.keyframesReleased());
        assertEquals(0, statistics.nackCount());
        assertEquals(0, sink.keyframes.get());
    }

    @Test
    @DisplayName("reorders packets across frames and drops duplicates")
    void reorders() {
        var assembler = assembler(Codec.vp8());
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer(new PacketizerConfig(100));
        var packets = new ArrayList<RtpPacket>();
        for (var i = 0; i < 4; i++) {
            packets.addAll(send(packetizer, vp8(i, i == 0, 250, Vp8FrameMetadata.none())));
        }
        Collections.shuffle(packets, new Random(4585));
        assembler.insert(packets.getFirst(), now.get());
        for (var packet : packets) {
            assembler.insert(packet, now.get());
        }
        var released = drain(assembler);
        assertEquals(4, released.size());
        for (var i = 1; i < released.size(); i++) {
            assertTrue(released.get(i).metadata().frameId().orElseThrow()
                    > released.get(i - 1).metadata().frameId().orElseThrow());
        }
        assertEquals(1, assembler.statistics().packetsDiscarded());
    }

    @Test
    @DisplayName("asks for a lost packet, retries every round trip, and releases once it arrives")
    void recovers() {
        var assembler = assembler(Codec.vp8());
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer(new PacketizerConfig(100));
        var key = send(packetizer, vp8(0, true, 250, Vp8FrameMetadata.none()));
        var second = send(packetizer, vp8(1, false, 250, Vp8FrameMetadata.none()));
        var third = send(packetizer, vp8(2, false, 250, Vp8FrameMetadata.none()));
        key.forEach(packet -> assembler.insert(packet, now.get()));
        assertEquals(1, drain(assembler).size());
        var lost = second.get(1);
        for (var packet : second) {
            if (packet != lost) {
                assembler.insert(packet, now.get());
            }
        }
        third.forEach(packet -> assembler.insert(packet, now.get()));
        assertEquals(List.of(lost.sequence()), sink.nacked);
        assertTrue(drain(assembler).isEmpty());
        advance(100);
        assertTrue(drain(assembler).isEmpty());
        assertEquals(List.of(lost.sequence(), lost.sequence()), sink.nacked);
        assembler.insert(lost, now.get());
        var released = drain(assembler);
        assertEquals(2, released.size());
        var statistics = assembler.statistics();
        assertEquals(1, statistics.packetsRecovered());
        assertEquals(2, statistics.nackCount());
        assertEquals(0, sink.keyframes.get());
    }

    @Test
    @DisplayName("gives up after the wait budget, asks for a keyframe, and resumes at it")
    void keyframeRequest() {
        var assembler = assembler(Codec.vp8());
        assembler.updateRtt(Duration.ofMillis(50));
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer(new PacketizerConfig(100));
        send(packetizer, vp8(0, true, 250, Vp8FrameMetadata.none())).forEach(packet -> assembler.insert(packet, now.get()));
        drain(assembler);
        var lostFrame = send(packetizer, vp8(1, false, 250, Vp8FrameMetadata.none()));
        lostFrame.stream().skip(1).forEach(packet -> assembler.insert(packet, now.get()));
        send(packetizer, vp8(2, false, 250, Vp8FrameMetadata.none())).forEach(packet -> assembler.insert(packet, now.get()));
        advance(149);
        assertTrue(drain(assembler).isEmpty());
        assertEquals(0, sink.keyframes.get());
        advance(2);
        drain(assembler);
        advance(160);
        assertTrue(drain(assembler).isEmpty());
        assertEquals(1, sink.keyframes.get());
        send(packetizer, vp8(3, true, 250, Vp8FrameMetadata.none())).forEach(packet -> assembler.insert(packet, now.get()));
        var released = drain(assembler);
        assertEquals(1, released.size());
        assertTrue(released.getFirst().keyframe());
        var statistics = assembler.statistics();
        assertEquals(1, statistics.packetsLost());
        assertTrue(statistics.framesDropped() >= 1);
        assertEquals(1, statistics.keyframeRequests());
    }

    @Test
    @DisplayName("lets a lost upper temporal layer frame go without blocking the base layer")
    void temporalLayers() {
        var assembler = assembler(Codec.vp8());
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer(new PacketizerConfig(100));
        var layers = new int[]{0, 2, 1, 2, 0, 2};
        var tl0 = new int[]{5, 5, 5, 5, 6, 6};
        var frames = new ArrayList<List<RtpPacket>>();
        for (var i = 0; i < layers.length; i++) {
            var metadata = Vp8FrameMetadata.ofTemporalLayer(layers[i], layers[i] == 2)
                    .withPictureId(10 + i, OptionalInt.of(tl0[i]));
            var data = new byte[150];
            data[0] = (byte) (i == 0 ? 0x10 : 0x11);
            frames.add(send(packetizer, new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), i * 3000L, i == 0,
                    Optional.empty(), metadata)));
        }
        for (var i = 0; i < frames.size(); i++) {
            for (var packet : frames.get(i)) {
                if (i != 1) {
                    assembler.insert(packet, now.get());
                }
            }
        }
        assertEquals(1, drain(assembler).size());
        advance(400);
        var released = drain(assembler);
        assertEquals(4, released.size());
        var ids = released.stream().map(frame -> frame.metadata().frameId().orElseThrow()).toList();
        var base = ids.getFirst() - 2;
        assertEquals(List.of(base), released.getFirst().metadata().dependencies());
        assertTrue(released.get(1).metadata().dependencies().contains(base));
        assertEquals(0, sink.keyframes.get());
    }

    @Test
    @DisplayName("resolves VP9 inter-layer references within a picture")
    void spatialLayers() {
        var assembler = assembler(Codec.vp9());
        var packetizer = PayloadFormat.of(Codec.vp9()).packetizer(new PacketizerConfig(100));
        var released = new ArrayList<EncodedFrame>();
        for (var picture = 0; picture < 3; picture++) {
            for (var spatial = 0; spatial < 2; spatial++) {
                var metadata = new Vp9FrameMetadata(OptionalInt.of(picture), OptionalInt.empty(),
                        OptionalInt.of(spatial), OptionalInt.of(0), false, spatial == 1, picture > 0, false, true,
                        picture > 0 ? List.of(1) : List.of(), Optional.empty(), spatial == 1, Optional.empty(),
                        OptionalLong.empty(), List.of());
                var frame = new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(new byte[120]), picture * 3000L,
                        picture == 0 && spatial == 0, Optional.empty(), metadata);
                send(packetizer, frame).forEach(packet -> assembler.insert(packet, now.get()));
            }
            released.addAll(drain(assembler));
        }
        assertEquals(6, released.size());
        var baseId = released.getFirst().metadata().frameId().orElseThrow();
        assertEquals(List.of(baseId), released.get(1).metadata().dependencies());
        assertEquals(List.of(baseId), released.get(2).metadata().dependencies());
        assertEquals(List.of(baseId + 8 + 0, baseId + 1).stream().sorted().toList(),
                released.get(3).metadata().dependencies().stream().sorted().toList());
    }

    @Test
    @DisplayName("decodes H.264 strictly in sequence and asks for a keyframe after a lost frame")
    void continuity() {
        var assembler = assembler(Codec.h264());
        var packetizer = PayloadFormat.of(Codec.h264()).packetizer(new PacketizerConfig(100));
        var sps = new byte[]{0x67, 0x42, (byte) 0xE0, 0x1F, (byte) 0x8C, 0x68, 0x04};
        var pps = new byte[]{0x68, (byte) 0xCE, 0x3C, (byte) 0x80};
        var idr = h264(new byte[][]{sps, pps, nal(0x65, 300)}, 0);
        send(packetizer, idr).forEach(packet -> assembler.insert(packet, now.get()));
        var first = drain(assembler);
        assertEquals(1, first.size());
        assertTrue(first.getFirst().keyframe());
        var lostFrame = send(packetizer, h264(new byte[][]{nal(0x41, 250)}, 3000));
        var after = send(packetizer, h264(new byte[][]{nal(0x41, 250)}, 6000));
        lostFrame.forEach(packet -> {
            if (packet != lostFrame.get(1)) {
                assembler.insert(packet, now.get());
            }
        });
        after.forEach(packet -> assembler.insert(packet, now.get()));
        assertTrue(drain(assembler).isEmpty());
        advance(301);
        drain(assembler);
        advance(301);
        assertTrue(drain(assembler).isEmpty());
        assertEquals(1, sink.keyframes.get());
        var resumed = send(packetizer, h264(new byte[][]{nal(0x65, 120)}, 9000));
        resumed.forEach(packet -> assembler.insert(packet, now.get()));
        var released = drain(assembler);
        assertEquals(1, released.size());
        assertTrue(released.getFirst().keyframe());
    }

    @Test
    @DisplayName("releases passthrough frames independently despite loss")
    void independent() {
        var codec = Codec.of("video/x-custom", 90000);
        var assembler = assembler(codec);
        var packetizer = PayloadFormat.of(codec).packetizer(new PacketizerConfig(100));
        var first = send(packetizer, EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(new byte[150]), 0, false));
        var second = send(packetizer, EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(new byte[150]), 3000, false));
        var third = send(packetizer, EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(new byte[150]), 6000, false));
        first.forEach(packet -> assembler.insert(packet, now.get()));
        assembler.insert(second.getLast(), now.get());
        third.forEach(packet -> assembler.insert(packet, now.get()));
        advance(400);
        var released = drain(assembler);
        assertEquals(1, released.size());
        assertEquals(6000, released.getLast().rtpTimestamp());
        assertEquals(0, sink.keyframes.get());
    }

    @Test
    @DisplayName("counts a freeze when releases stall")
    void freezes() {
        var assembler = assembler(Codec.vp8());
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer(new PacketizerConfig(1100));
        for (var i = 0; i < 12; i++) {
            send(packetizer, vp8(i, i == 0, 100, Vp8FrameMetadata.none())).forEach(packet -> assembler.insert(packet,
                    now.get()));
            drain(assembler);
            advance(i == 9 ? 600 : 33);
        }
        var statistics = assembler.statistics();
        assertEquals(1, statistics.freezeCount());
        assertTrue(statistics.totalFreezesDuration().toMillis() >= 600);
    }

    @Test
    @DisplayName("requests a keyframe when the packet limit overflows, and validates its inputs")
    void limits() throws InterruptedException {
        var config = new VideoAssemblerConfig(clock, false, Duration.ofMillis(100), Duration.ZERO,
                Duration.ofMillis(500), Duration.ofMillis(500), 10, 8, com.github.auties00.parley.payload
                .DepacketizerConfig.none());
        var assembler = VideoFrameAssembler.create(PayloadFormat.of(Codec.vp8()), config, sink);
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer(new PacketizerConfig(64));
        send(packetizer, vp8(0, false, 1000, Vp8FrameMetadata.none())).forEach(packet -> assembler.insert(packet,
                now.get()));
        assertEquals(1, sink.keyframes.get());
        assertTrue(sink.nacked.isEmpty());
        assertTrue(assembler.next(Duration.ofMillis(10)).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> assembler.updateRtt(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> VideoFrameAssembler.create(PayloadFormat.of(Codec.opus()),
                VideoAssemblerConfig.defaults(), FeedbackSink.NONE));
        assembler.close();
        assertThrows(IllegalStateException.class, assembler::next);
        assertFalse(assembler.statistics().packetsReceived() == 0);
    }

    @Test
    @DisplayName("hands a frame to a thread blocked in next")
    void blocking() throws Exception {
        var assembler = VideoFrameAssembler.create(PayloadFormat.of(Codec.vp8()), VideoAssemblerConfig.defaults(),
                FeedbackSink.NONE);
        var packetizer = PayloadFormat.of(Codec.vp8()).packetizer();
        var result = new java.util.concurrent.atomic.AtomicReference<EncodedFrame>();
        var consumer = Thread.ofVirtual().start(() -> {
            try {
                result.set(assembler.next());
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        });
        Thread.sleep(20);
        send(packetizer, vp8(1, true, 50, Vp8FrameMetadata.none())).forEach(packet -> assembler.insert(packet,
                System.nanoTime()));
        consumer.join(5000);
        assertTrue(result.get() != null && result.get().keyframe());
    }

    /// {@return an H.264 access unit of NAL units}
    private static EncodedFrame h264(byte[][] nals, long timestamp) {
        var out = new java.io.ByteArrayOutputStream();
        for (var nal : nals) {
            out.writeBytes(new byte[]{0, 0, 0, 1});
            out.writeBytes(nal);
        }
        return new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(out.toByteArray()), timestamp, false,
                Optional.empty(), H264FrameMetadata.none());
    }

    /// {@return a slice NAL unit of a header and a length, starting a picture}
    private static byte[] nal(int header, int length) {
        var data = new byte[length];
        java.util.Arrays.fill(data, (byte) 0x55);
        data[0] = (byte) header;
        data[1] = (byte) 0x88;
        return data;
    }
}
