package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.OpusFormat;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.payload.TestPackets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers [AudioPlayoutBuffer] on a manual clock: steady playout, loss, reordering, late packets, DTX silence,
/// adaptation to jitter, the `jitterBufferTarget` floor, statistics and closing.
@DisplayName("AudioPlayoutBuffer")
class AudioPlayoutBufferTest {
    /// 20 ms in nanoseconds.
    private static final long FRAME_NANOS = TimeUnit.MILLISECONDS.toNanos(20);

    /// A 20 ms CELT fullband Opus packet.
    private static final byte TOC_20MS = (byte) 0xF8;

    /// The manual time.
    private final AtomicLong now = new AtomicLong(1_000_000_000L);

    /// The clock reading `now`.
    private final MonotonicClock clock = now::get;

    /// {@return a buffer for Opus with a manual clock}
    private AudioPlayoutBuffer opus(AudioPlayoutConfig config) {
        return AudioPlayoutBuffer.create(OpusFormat.defaults(), 48000, config.withClock(clock));
    }

    /// {@return the Opus packet of frame `index`}
    private static com.github.auties00.parley.rtp.RtpPacket frame(int index, boolean marker) {
        return TestPackets.packet(111, marker, index & 0xFFFF, index * 960L,
                ByteBuffer.wrap(new byte[]{TOC_20MS, (byte) index, 1, 2}));
    }

    /// {@return the outcomes due while advancing the clock by `frames` frame durations, polling each millisecond}
    private List<AudioPlayout> drain(AudioPlayoutBuffer buffer, int frames) {
        var result = new ArrayList<AudioPlayout>();
        for (var step = 0; step < frames * 20; step++) {
            now.addAndGet(TimeUnit.MILLISECONDS.toNanos(1));
            Optional<AudioPlayout> outcome;
            while ((outcome = buffer.poll()).isPresent()) {
                result.add(outcome.get());
            }
        }
        return result;
    }

    @Test
    @DisplayName("plays a steady stream in order, one frame per 20 ms, after the minimum delay")
    void steady() {
        var buffer = opus(AudioPlayoutConfig.defaults().withDelayRange(Duration.ofMillis(40), Duration.ofSeconds(1)));
        buffer.insert(frame(0, true), now.get());
        assertTrue(buffer.poll().isEmpty());
        var outcomes = new ArrayList<AudioPlayout>();
        for (var i = 1; i <= 50; i++) {
            now.addAndGet(FRAME_NANOS);
            buffer.insert(frame(i, false), now.get());
            buffer.poll().ifPresent(outcomes::add);
        }
        assertEquals(49, outcomes.size());
        for (var i = 0; i < outcomes.size(); i++) {
            var played = assertInstanceOf(AudioPlayout.Frame.class, outcomes.get(i));
            assertEquals(i * 960L, played.frame().rtpTimestamp());
            assertEquals(Duration.ofMillis(20), played.duration());
        }
        var statistics = buffer.statistics();
        assertEquals(51, statistics.packetsReceived());
        assertEquals(49, statistics.jitterBufferEmittedCount());
        assertEquals(0, statistics.concealedSamples());
        assertEquals(Duration.ofMillis(40), statistics.targetDelay());
        assertEquals(Duration.ZERO, statistics.jitter());
    }

    @Test
    @DisplayName("reports a lost frame as missing and a late one as discarded")
    void lossAndLate() {
        var buffer = opus(AudioPlayoutConfig.defaults().withDelayRange(Duration.ofMillis(20), Duration.ofSeconds(1)));
        var outcomes = new ArrayList<AudioPlayout>();
        for (var i = 0; i < 10; i++) {
            if (i != 4) {
                buffer.insert(frame(i, i == 0), now.get());
            }
            now.addAndGet(FRAME_NANOS);
            buffer.poll().ifPresent(outcomes::add);
            if (i == 6) {
                buffer.insert(frame(4, false), now.get());
            }
        }
        var missing = outcomes.stream().filter(AudioPlayout.Missing.class::isInstance).toList();
        assertEquals(4 * 960L, ((AudioPlayout.Missing) missing.getFirst()).rtpTimestamp());
        var statistics = buffer.statistics();
        assertEquals(1, statistics.packetsLate());
        assertEquals(1 + statistics.insertedSamplesForDeceleration() / 960, missing.size());
        assertEquals(960 + statistics.insertedSamplesForDeceleration(), statistics.concealedSamples());
        var frames = outcomes.stream().filter(AudioPlayout.Frame.class::isInstance)
                .map(outcome -> ((AudioPlayout.Frame) outcome).frame().rtpTimestamp() / 960).toList();
        assertEquals(List.of(0L, 1L, 2L, 3L, 5L, 6L), frames.subList(0, 6));
    }

    @Test
    @DisplayName("reorders packets that arrive within the delay")
    void reorder() {
        var buffer = opus(AudioPlayoutConfig.defaults().withDelayRange(Duration.ofMillis(60), Duration.ofSeconds(1)));
        var order = new int[]{0, 2, 1, 3, 5, 4, 6, 7, 8, 9, 10, 11};
        var outcomes = new ArrayList<AudioPlayout>();
        for (var index : order) {
            buffer.insert(frame(index, index == 0), now.get());
            now.addAndGet(FRAME_NANOS);
            buffer.poll().ifPresent(outcomes::add);
        }
        outcomes.addAll(drain(buffer, 2));
        var timestamps = outcomes.stream().filter(AudioPlayout.Frame.class::isInstance)
                .map(outcome -> ((AudioPlayout.Frame) outcome).frame().rtpTimestamp()).toList();
        assertEquals(timestamps.size(), outcomes.size());
        for (var i = 0; i < timestamps.size(); i++) {
            assertEquals(i * 960L, timestamps.get(i));
        }
        assertTrue(timestamps.size() >= 10);
        assertEquals(0, buffer.statistics().packetsLate());
    }

    @Test
    @DisplayName("fills a DTX pause with silence and restarts at the next talkspurt")
    void dtx() {
        var buffer = opus(AudioPlayoutConfig.defaults().withDelayRange(Duration.ofMillis(20), Duration.ofSeconds(1)));
        var outcomes = new ArrayList<AudioPlayout>();
        for (var i = 0; i < 5; i++) {
            buffer.insert(frame(i, i == 0), now.get());
            now.addAndGet(FRAME_NANOS);
            buffer.poll().ifPresent(outcomes::add);
        }
        buffer.insert(TestPackets.packet(111, false, 5, 5 * 960L, ByteBuffer.wrap(new byte[]{TOC_20MS})), now.get());
        outcomes.addAll(drain(buffer, 10));
        var silence = outcomes.stream().filter(AudioPlayout.Silence.class::isInstance).count();
        assertTrue(silence >= 5, "silence outcomes: " + silence);
        assertEquals(0, outcomes.stream().filter(AudioPlayout.Missing.class::isInstance).count());
        buffer.insert(TestPackets.packet(111, true, 6, 15 * 960L, ByteBuffer.wrap(new byte[]{TOC_20MS, 1, 2, 3})),
                now.get());
        var resumed = drain(buffer, 3).stream().filter(AudioPlayout.Frame.class::isInstance).toList();
        assertEquals(15 * 960L, ((AudioPlayout.Frame) resumed.getFirst()).frame().rtpTimestamp());
        assertTrue(buffer.statistics().silentConcealedSamples() > 0);
    }

    @Test
    @DisplayName("grows the target with jitter and never goes below jitterBufferTarget")
    void adapts() {
        var buffer = opus(AudioPlayoutConfig.defaults());
        var random = new java.util.Random(3550);
        for (var i = 0; i < 100; i++) {
            buffer.insert(frame(i, i == 0), now.get() + random.nextInt(60) * 1_000_000L);
            now.addAndGet(FRAME_NANOS);
            buffer.poll();
        }
        var jittered = buffer.targetDelay();
        assertTrue(jittered.toMillis() >= 40, "target " + jittered);
        assertTrue(buffer.statistics().jitter().toMillis() > 5);
        buffer.setJitterBufferTarget(Duration.ofMillis(500));
        assertEquals(Duration.ofMillis(500), buffer.targetDelay());
        buffer.clearJitterBufferTarget();
        assertEquals(jittered, buffer.targetDelay());
        assertThrows(IllegalArgumentException.class,
                () -> buffer.setJitterBufferTarget(Duration.ofMillis(4001)));
    }

    @Test
    @DisplayName("skips a frame when the buffer holds far more than the target")
    void accelerates() {
        var buffer = opus(AudioPlayoutConfig.defaults().withDelayRange(Duration.ofMillis(20), Duration.ofSeconds(1)));
        buffer.insert(frame(0, true), now.get());
        for (var i = 1; i < 30; i++) {
            buffer.insert(frame(i, false), now.get());
        }
        var frames = drain(buffer, 30).stream().filter(AudioPlayout.Frame.class::isInstance).count();
        var removed = buffer.statistics().removedSamplesForAcceleration();
        assertTrue(removed > 0);
        assertEquals(30 - removed / 960, frames);
    }

    @Test
    @DisplayName("stops after an outage longer than the maximum delay and drops malformed packets")
    void outage() {
        var buffer = opus(AudioPlayoutConfig.defaults().withDelayRange(Duration.ZERO, Duration.ofMillis(100)));
        buffer.insert(frame(0, true), now.get());
        var outcomes = drain(buffer, 20);
        assertEquals(1, outcomes.stream().filter(AudioPlayout.Frame.class::isInstance).count());
        assertTrue(outcomes.size() <= 7, "outcomes " + outcomes.size());
        buffer.insert(TestPackets.packet(111, false, 9, 0, ByteBuffer.allocate(0)), now.get());
        assertEquals(1, buffer.statistics().packetsDiscarded());
    }

    @Test
    @DisplayName("blocks in next until the playout instant on the system clock, and fails once closed")
    void blocking() throws InterruptedException {
        var buffer = AudioPlayoutBuffer.create(PayloadFormat.of(Codec.pcmu()), 8000,
                AudioPlayoutConfig.defaults().withDelayRange(Duration.ofMillis(30), Duration.ofSeconds(1)));
        var start = System.nanoTime();
        buffer.insert(TestPackets.packet(0, true, 1, 160, ByteBuffer.allocate(160)), start);
        var outcome = buffer.next();
        assertTrue(System.nanoTime() - start >= TimeUnit.MILLISECONDS.toNanos(25));
        assertEquals(Duration.ofMillis(20), assertInstanceOf(AudioPlayout.Frame.class, outcome).duration());
        buffer.close();
        assertThrows(IllegalStateException.class, buffer::next);
        assertThrows(IllegalStateException.class, buffer::poll);
        assertThrows(IllegalArgumentException.class, () -> AudioPlayoutBuffer.create(PayloadFormat.of(Codec.vp8()),
                90000, AudioPlayoutConfig.defaults()));
        assertFalse(AudioPlayoutConfig.defaults().jitterBufferTarget().isPresent());
    }
}
