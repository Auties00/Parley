package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.media.Vp9FrameMetadata;
import com.github.auties00.parley.media.Vp9ScalabilityStructure;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.DepacketizerConfig;
import com.github.auties00.parley.payload.OpusFormat;
import com.github.auties00.parley.payload.PacketizerConfig;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.payload.TestPackets;
import com.github.auties00.parley.rtp.NtpTime;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.session.NtpRtpMapping;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the timing the jitter buffers add to frames: capture times from `abs-capture-time` and sender reports,
/// `playout-delay` bounds, lip sync through [SyncGroup], and the picture id and group-of-pictures references of
/// [ReferenceFinder]. Everything runs on a manual clock.
@DisplayName("playout timing and references")
class PlayoutTimingTest {
    /// 20 ms in nanoseconds.
    private static final long FRAME_NANOS = TimeUnit.MILLISECONDS.toNanos(20);
    /// The extension id of `abs-capture-time` in these tests.
    private static final int ABS_CAPTURE_TIME = 5;
    /// The extension id of `playout-delay` in these tests.
    private static final int PLAYOUT_DELAY = 6;
    /// The capture time of the first frame.
    private static final Instant CAPTURE = Instant.parse("2026-11-21T10:00:00Z");

    /// The manual time.
    private final AtomicLong now = new AtomicLong(1_000_000_000L);
    /// The clock reading `now`.
    private final MonotonicClock clock = now::get;

    /// {@return the Opus packet of frame `index`, with header extensions}
    private static RtpPacket opus(int index, Map<Integer, byte[]> extensions) {
        return TestPackets.packet(111, index == 0, index, index * 960L, 1, ByteBuffer.wrap(
                new byte[]{(byte) 0xF8, (byte) index, 1, 2}), extensions, List.of());
    }

    /// {@return an `abs-capture-time` value}
    private static byte[] absCaptureTime(Instant capture) {
        return ByteBuffer.allocate(8).putLong(NtpTime.fromInstant(capture)).array();
    }

    /// {@return a `playout-delay` value in units of 10 ms}
    private static byte[] playoutDelay(int minimum, int maximum) {
        return new byte[]{(byte) (minimum >>> 4), (byte) ((minimum & 0x0F) << 4 | maximum >>> 8), (byte) maximum};
    }

    /// {@return an Opus buffer on the manual clock that reads both timing extensions}
    private AudioPlayoutBuffer buffer(Duration minimum) {
        return AudioPlayoutBuffer.create(OpusFormat.defaults(), 48000, AudioPlayoutConfig.defaults()
                .withClock(clock).withDelayRange(minimum, Duration.ofSeconds(2))
                .withDepacketizer(DepacketizerConfig.none().withAbsCaptureTimeExtensionId(ABS_CAPTURE_TIME)
                        .withPlayoutDelayExtensionId(PLAYOUT_DELAY)));
    }

    /// {@return the frames played while feeding `count` packets made by `packet`, one per 20 ms}
    private List<EncodedFrame> play(AudioPlayoutBuffer buffer, int count,
                                    java.util.function.IntFunction<RtpPacket> packet) {
        var frames = new ArrayList<EncodedFrame>();
        for (var index = 0; index < count; index++) {
            buffer.insert(packet.apply(index), now.get());
            for (var step = 0; step < 20; step++) {
                now.addAndGet(TimeUnit.MILLISECONDS.toNanos(1));
                buffer.poll().ifPresent(outcome -> {
                    if (outcome instanceof AudioPlayout.Frame(var frame, var ignored)) {
                        frames.add(frame);
                    }
                });
            }
        }
        return frames;
    }

    @Nested
    @DisplayName("audio")
    class Audio {
        @Test
        @DisplayName("dates frames from abs-capture-time, extrapolated along the RTP clock between values")
        void absCaptureTimeFrames() {
            var buffer = buffer(Duration.ofMillis(40));
            var frames = play(buffer, 20, index -> opus(index,
                    index % 5 == 0 ? Map.of(ABS_CAPTURE_TIME, absCaptureTime(CAPTURE.plusMillis(index * 20L)))
                            : Map.of()));
            assertTrue(frames.size() > 10);
            for (var frame : frames) {
                var expected = CAPTURE.plusMillis(frame.rtpTimestamp() / 48);
                var actual = frame.captureTime().orElseThrow();
                assertTrue(Math.abs(Duration.between(expected, actual).toNanos()) < 1_000, actual.toString());
            }
            var estimated = buffer.statistics().estimatedPlayoutTimestamp().orElseThrow();
            var last = frames.getLast().captureTime().orElseThrow();
            assertTrue(!estimated.isBefore(last) && estimated.isBefore(last.plusMillis(25)), estimated.toString());
        }

        @Test
        @DisplayName("dates frames from the sender report clock when the stream carries no abs-capture-time")
        void senderClock() {
            var buffer = buffer(Duration.ofMillis(40));
            assertTrue(play(buffer, 3, index -> opus(index, Map.of())).stream()
                    .allMatch(frame -> frame.captureTime().isEmpty()));
            assertTrue(buffer.statistics().estimatedPlayoutTimestamp().isEmpty());
            buffer.setSenderClock(new NtpRtpMapping(NtpTime.fromInstant(CAPTURE), 0, 48000, now.get()));
            var frames = play(buffer, 10, index -> opus(index + 3, Map.of()));
            assertTrue(frames.size() > 5);
            for (var frame : frames) {
                var expected = CAPTURE.plusNanos(frame.rtpTimestamp() * 1_000_000_000L / 48000);
                var actual = frame.captureTime().orElseThrow();
                assertTrue(Math.abs(Duration.between(expected, actual).toNanos()) < 1_000, actual.toString());
            }
        }

        @Test
        @DisplayName("keeps the target delay within the playout-delay bounds")
        void playoutDelayBounds() {
            var buffer = buffer(Duration.ZERO);
            play(buffer, 5, index -> opus(index, Map.of(PLAYOUT_DELAY, playoutDelay(25, 40))));
            assertEquals(Duration.ofMillis(250), buffer.targetDelay());
            var capped = buffer(Duration.ofMillis(500));
            play(capped, 5, index -> opus(index, Map.of(PLAYOUT_DELAY, playoutDelay(0, 10))));
            assertEquals(Duration.ofMillis(100), capped.targetDelay(), "the maximum caps the configured minimum");
        }

        @Test
        @DisplayName("sets and clears the jitter buffer target, and the config copies set and clear it")
        void jitterBufferTarget() {
            var config = AudioPlayoutConfig.defaults().withJitterBufferTarget(Duration.ofMillis(300));
            assertEquals(Optional.of(Duration.ofMillis(300)), config.jitterBufferTarget());
            assertTrue(config.withoutJitterBufferTarget().jitterBufferTarget().isEmpty());
            var buffer = buffer(Duration.ZERO);
            buffer.setJitterBufferTarget(Duration.ofMillis(120));
            assertEquals(Duration.ofMillis(120), buffer.targetDelay());
            buffer.clearJitterBufferTarget();
            assertEquals(Duration.ZERO, buffer.targetDelay());
        }
    }

    @Nested
    @DisplayName("lip sync")
    class Sync {
        @Test
        @DisplayName("delays the stream that plays earlier until both play the same capture instant")
        void aligns() {
            var early = buffer(Duration.ofMillis(40));
            var late = buffer(Duration.ofMillis(200));
            var mapping = new NtpRtpMapping(NtpTime.fromInstant(CAPTURE), 0, 48000, now.get());
            early.setSenderClock(mapping);
            late.setSenderClock(mapping);
            var group = SyncGroup.create();
            group.add(early);
            group.add(late);
            assertEquals(2, group.size());
            for (var index = 0; index < 300; index++) {
                early.insert(opus(index, Map.of()), now.get());
                late.insert(opus(index, Map.of()), now.get());
                for (var step = 0; step < 20; step++) {
                    now.addAndGet(TimeUnit.MILLISECONDS.toNanos(1));
                    early.poll();
                    late.poll();
                }
            }
            assertEquals(Duration.ZERO, group.delayOf(late));
            var added = group.delayOf(early);
            assertTrue(added.toMillis() >= 140 && added.toMillis() <= 180, added.toString());
            assertTrue(early.targetDelay().toMillis() >= 180, early.targetDelay().toString());
            assertEquals(added, early.statistics().synchronizationDelay());
            group.remove(early);
            assertEquals(Duration.ZERO, group.delayOf(early));
            assertEquals(Duration.ZERO, early.statistics().synchronizationDelay());
            assertEquals(1, group.size());
        }
    }

    @Nested
    @DisplayName("video")
    class Video {
        /// {@return an assembler for VP8 on the manual clock that reads both timing extensions}
        private VideoFrameAssembler assembler() {
            return VideoFrameAssembler.create(PayloadFormat.of(Codec.vp8()), VideoAssemblerConfig.defaults()
                    .withClock(clock).withDepacketizer(DepacketizerConfig.none()
                            .withAbsCaptureTimeExtensionId(ABS_CAPTURE_TIME)
                            .withPlayoutDelayExtensionId(PLAYOUT_DELAY)), FeedbackSink.NONE);
        }

        /// {@return the single packet of a small VP8 frame, with header extensions}
        private static RtpPacket frame(int index, Vp8FrameMetadata metadata, Map<Integer, byte[]> extensions) {
            var data = new byte[]{(byte) (index == 0 ? 0x10 : 0x11), 1, 2, 3};
            var payloads = PayloadFormat.of(Codec.vp8()).packetizer(PacketizerConfig.defaults()).packetize(
                    new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), index * 3000L, index == 0,
                            Optional.empty(), metadata));
            assertEquals(1, payloads.size());
            return TestPackets.packet(96, true, index & 0xFFFF, index * 3000L, 1, payloads.getFirst().payload(),
                    extensions, List.of());
        }

        @Test
        @DisplayName("dates frames and holds each one for the playout-delay minimum after its arrival")
        void captureTimeAndMinimumDelay() {
            var assembler = assembler();
            assembler.insert(frame(0, Vp8FrameMetadata.none().withPictureId(0, OptionalInt.empty()), Map.of(
                    ABS_CAPTURE_TIME, absCaptureTime(CAPTURE), PLAYOUT_DELAY, playoutDelay(10, 50))), now.get());
            assertTrue(assembler.poll().isEmpty(), "held for the 100 ms minimum");
            now.addAndGet(TimeUnit.MILLISECONDS.toNanos(99));
            assertTrue(assembler.poll().isEmpty());
            now.addAndGet(TimeUnit.MILLISECONDS.toNanos(1));
            var released = assembler.poll().orElseThrow();
            assertEquals(Optional.of(CAPTURE), released.captureTime());
            assertEquals(Optional.of(CAPTURE), assembler.statistics().estimatedPlayoutTimestamp());
            assertEquals(java.util.OptionalDouble.of(1), assembler.statistics().framesPerSecond());
        }

        @Test
        @DisplayName("releases VP8 frames whose 7-bit picture ids wrap, in order and without a stall")
        void shortPictureIds() {
            var assembler = assembler();
            var released = new ArrayList<EncodedFrame>();
            for (var index = 0; index < 40; index++) {
                var metadata = Vp8FrameMetadata.none().withShortPictureId((100 + index) % 128);
                assembler.insert(frame(index, metadata, Map.of()), now.get());
                now.addAndGet(FRAME_NANOS);
                assembler.poll().ifPresent(released::add);
            }
            assertEquals(40, released.size());
            for (var index = 0; index < released.size(); index++) {
                var metadata = assertInstanceOf(Vp8FrameMetadata.class, released.get(index).metadata());
                assertEquals(7, metadata.pictureIdBits());
                assertEquals(OptionalInt.of((100 + index) % 128), metadata.pictureId());
                if (index > 0) {
                    var previous = released.get(index - 1).metadata().frameId().orElseThrow();
                    assertEquals(List.of(previous), metadata.dependencies());
                }
            }
        }
    }

    @Nested
    @DisplayName("VP9 non-flexible references")
    class Vp9GroupOfPictures {
        /// {@return the metadata of a non-flexible VP9 picture}
        private static Vp9FrameMetadata picture(int pictureId, int temporal, boolean key,
                                                Optional<Vp9ScalabilityStructure> structure) {
            return new Vp9FrameMetadata(OptionalInt.of(pictureId), OptionalInt.of(pictureId / 2),
                    OptionalInt.of(0), OptionalInt.of(temporal), false, false, !key, false, false, List.of(),
                    structure, true, Optional.empty(), OptionalLong.empty(), List.of());
        }

        @Test
        @DisplayName("takes the references of each picture from the group of pictures of the scalability structure")
        void groupOfPictures() {
            var finder = new ReferenceFinder(PayloadFormat.of(Codec.vp9()));
            var structure = new Vp9ScalabilityStructure(1, List.of(), List.of(
                    new Vp9ScalabilityStructure.PictureGroupEntry(0, false, List.of(4)),
                    new Vp9ScalabilityStructure.PictureGroupEntry(2, false, List.of(1)),
                    new Vp9ScalabilityStructure.PictureGroupEntry(1, false, List.of(2)),
                    new Vp9ScalabilityStructure.PictureGroupEntry(2, false, List.of(1, 3))));
            var temporal = new int[]{0, 2, 1, 2, 0, 2, 1, 2};
            var ids = new ArrayList<Long>();
            var references = new ArrayList<List<Long>>();
            for (var index = 0; index < temporal.length; index++) {
                var metadata = picture(20 + index, temporal[index], index == 0,
                        index == 0 ? Optional.of(structure) : Optional.empty());
                var frame = new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(new byte[]{1}), index * 3000L,
                        index == 0, Optional.empty(), metadata);
                var identity = finder.identify(frame, index, index);
                ids.add(identity.id());
                references.add(finder.references(identity).orElseThrow());
            }
            assertEquals(List.of(), references.get(0));
            assertEquals(List.of(ids.get(0)), references.get(1));
            assertEquals(List.of(ids.get(0)), references.get(2));
            assertEquals(List.of(ids.get(2), ids.get(0)), references.get(3));
            assertEquals(List.of(ids.get(0)), references.get(4), "the base layer references four pictures back");
            assertEquals(List.of(ids.get(4)), references.get(5));
            assertEquals(List.of(ids.get(4)), references.get(6));
            assertEquals(List.of(ids.get(6), ids.get(4)), references.get(7));
        }
    }
}
