package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.PacketSink;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Drives the pacer with a simulated clock through its process step, so rates and wake-up times are exact; one
/// test runs its real thread.
@DisplayName("Pacer")
class PacerTest {
    private static final long MS = 1_000_000L;

    private record Sent(long atNanos, int size, Priority priority, boolean probe) {
    }

    private final FakeClock clock = new FakeClock(0);
    private final List<Sent> sent = new ArrayList<>();

    private PacketSink sink(Priority priority) {
        return packet -> sent.add(new Sent(clock.nanos(), packet.remaining(), priority, Pacer.PROBE.isBound()));
    }

    private void run(Pacer pacer, long untilNanos) {
        while (clock.nanos() <= untilNanos) {
            var next = pacer.process(clock.nanos());
            clock.set(Math.max(clock.nanos() + 1, Math.min(next, untilNanos + 1)));
        }
    }

    private Pacer pacer(long rateBps) {
        return new Pacer(clock, rateBps, Duration.ofSeconds(2).toNanos(), false, null);
    }

    @Test
    @DisplayName("releases packets at the pacing rate")
    void rate() {
        var pacer = pacer(800_000);
        for (var index = 0; index < 100; index++) {
            pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, sink(Priority.VIDEO));
        }
        run(pacer, 1_000 * MS);
        assertEquals(100, sent.size());
        var last = sent.getLast().atNanos();
        assertEquals(990 * MS, last, 2 * MS, "100 packets of 8,000 bits at 800 kbit/s span 990 ms");
        assertEquals(0, pacer.queuedPackets());
        assertEquals(100_000, pacer.sentBytes());
    }

    @Test
    @DisplayName("sends higher priorities first and audio without waiting for the budget")
    void priorities() {
        var pacer = pacer(80_000);
        pacer.schedule(ByteBuffer.allocate(1000), Priority.PADDING, 1, sink(Priority.PADDING));
        pacer.schedule(ByteBuffer.allocate(1000), Priority.FEC, 1, sink(Priority.FEC));
        pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, sink(Priority.VIDEO));
        pacer.schedule(ByteBuffer.allocate(1000), Priority.RETRANSMISSION, 1, sink(Priority.RETRANSMISSION));
        pacer.schedule(ByteBuffer.allocate(100), Priority.AUDIO, 1, sink(Priority.AUDIO));
        pacer.process(0);
        assertEquals(List.of(Priority.AUDIO), sent.stream().map(Sent::priority).toList(),
                "the audio packet leaves at once and its bytes count against the budget");
        pacer.schedule(ByteBuffer.allocate(100), Priority.AUDIO, 1, sink(Priority.AUDIO));
        pacer.process(MS);
        assertEquals(List.of(Priority.AUDIO, Priority.AUDIO), sent.stream().map(Sent::priority).toList(),
                "audio is not held back by the debt");
        run(pacer, 2_000 * MS);
        assertEquals(List.of(Priority.AUDIO, Priority.AUDIO, Priority.RETRANSMISSION, Priority.VIDEO, Priority.FEC,
                Priority.PADDING), sent.stream().map(Sent::priority).toList());
    }

    @Test
    @DisplayName("paces audio too when configured to")
    void pacedAudio() {
        var pacer = new Pacer(clock, 80_000, Duration.ofSeconds(2).toNanos(), true, null);
        pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, sink(Priority.VIDEO));
        pacer.schedule(ByteBuffer.allocate(100), Priority.VIDEO, 1, sink(Priority.VIDEO));
        pacer.process(0);
        pacer.schedule(ByteBuffer.allocate(100), Priority.AUDIO, 1, sink(Priority.AUDIO));
        pacer.process(MS);
        assertEquals(1, sent.size());
        run(pacer, 200 * MS);
        assertEquals(Priority.AUDIO, sent.get(1).priority());
    }

    @Test
    @DisplayName("raises its rate so no packet waits longer than the queue time bound")
    void queueTimeLimit() {
        var pacer = new Pacer(clock, 100_000, Duration.ofMillis(500).toNanos(), false, null);
        for (var index = 0; index < 100; index++) {
            pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, sink(Priority.VIDEO));
        }
        run(pacer, 3_000 * MS);
        assertEquals(100, sent.size());
        assertTrue(sent.getLast().atNanos() <= 520 * MS, "drained by " + sent.getLast().atNanos() / MS + " ms");
    }

    @Test
    @DisplayName("sends probe clusters at their rate, filling with padding when the queue is empty")
    void probes() {
        var pacer = pacer(300_000);
        var padding = new ArrayList<Integer>();
        pacer.setPaddingSource(bytes -> {
            padding.add(bytes);
            return List.of(new PaddingPacket(ByteBuffer.allocate(Math.min(bytes, 500)), 2, sink(Priority.PADDING)));
        });
        pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, sink(Priority.VIDEO));
        var cluster = ProbeCluster.of(0, 4_000_000, 0);
        pacer.addProbe(cluster);
        run(pacer, 100 * MS);
        var probes = sent.stream().filter(Sent::probe).toList();
        assertTrue(probes.size() >= cluster.minPackets(), "probe packets: " + probes.size());
        assertEquals(Priority.VIDEO, probes.getFirst().priority(), "queued media goes first");
        var bytes = probes.stream().mapToInt(Sent::size).sum();
        assertTrue(bytes >= cluster.minBytes());
        var span = probes.getLast().atNanos() - probes.getFirst().atNanos();
        var rate = (bytes - probes.getLast().size()) * 8e9 / span;
        assertEquals(4_000_000, rate, 600_000, "probe sent at its rate");
        assertTrue(!padding.isEmpty());
    }

    @Test
    @DisplayName("drops a probe it cannot fill")
    void unfillableProbe() {
        var pacer = pacer(300_000);
        pacer.addProbe(ProbeCluster.of(0, 4_000_000, 0));
        run(pacer, 100 * MS);
        assertTrue(sent.isEmpty());
        pacer.setPaddingSource(_ -> List.of());
        pacer.addProbe(ProbeCluster.of(1, 4_000_000, 0));
        run(pacer, 200 * MS);
        assertTrue(sent.isEmpty());
    }

    @Test
    @DisplayName("keeps up the padding rate once media flowed")
    void paddingRate() {
        var pacer = pacer(1_000_000);
        pacer.setPaddingSource(bytes -> List.of(new PaddingPacket(ByteBuffer.allocate(bytes), 2, sink(Priority.PADDING))));
        pacer.setPaddingRate(400_000);
        run(pacer, 100 * MS);
        assertTrue(sent.isEmpty(), "no padding before the first media packet");
        pacer.schedule(ByteBuffer.allocate(100), Priority.VIDEO, 1, sink(Priority.VIDEO));
        run(pacer, 1_100 * MS);
        var paddingBytes = sent.stream().filter(packet -> packet.priority() == Priority.PADDING).mapToInt(Sent::size).sum();
        assertEquals(50_000, paddingBytes, 3_000, "400 kbit/s of padding over one second");
    }

    @Test
    @DisplayName("counts packets whose sink fails and drops what is queued at close")
    void failuresAndClose() {
        var pacer = pacer(1_000_000);
        pacer.schedule(ByteBuffer.allocate(100), Priority.VIDEO, 1, _ -> {
            throw new IOException("unreachable");
        });
        pacer.process(0);
        assertEquals(1, pacer.failedPackets());
        for (var index = 0; index < 10; index++) {
            pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, sink(Priority.VIDEO));
        }
        assertEquals(10_000, pacer.queuedBytes());
        clock.advanceMillis(50);
        assertEquals(Duration.ofMillis(50), pacer.queueDelay());
        pacer.close();
        assertEquals(0, pacer.queuedPackets());
        assertEquals(Long.MAX_VALUE, pacer.process(clock.nanos()));
        pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, sink(Priority.VIDEO));
        assertEquals(0, pacer.queuedPackets());
    }

    @Test
    @Timeout(10)
    @DisplayName("runs on its own thread from the thread factory")
    void thread() throws Exception {
        var pacer = new Pacer(System::nanoTime, 8_000_000, Duration.ofSeconds(2).toNanos(), false,
                Thread.ofVirtual().name("test-pacer-", 0).factory());
        try {
            var latch = new CountDownLatch(50);
            var threads = new ArrayList<String>();
            for (var index = 0; index < 50; index++) {
                pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, _ -> {
                    threads.add(Thread.currentThread().getName());
                    latch.countDown();
                });
            }
            assertTrue(latch.await(5, TimeUnit.SECONDS));
            assertTrue(threads.stream().allMatch(name -> name.startsWith("test-pacer-")), threads.toString());
        } finally {
            pacer.close();
        }
    }
}
