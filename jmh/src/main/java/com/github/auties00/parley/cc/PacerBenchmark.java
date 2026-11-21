package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.PacketSink;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

/// The pacer driven by its process step on a manual clock: one 1,200-byte video packet scheduled and released per
/// operation at 10 Mbit/s.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class PacerBenchmark {
    private long now = 1_000_000_000L;
    private final MonotonicClock clock = () -> now;
    private Pacer pacer;
    private ByteBuffer packet;
    private PacketSink sink;

    @Setup
    public void setup(Blackhole blackhole) {
        pacer = new Pacer(clock, 10_000_000, 2_000_000_000L, false, null, _ -> {
        });
        packet = ByteBuffer.allocate(1200);
        sink = buffer -> blackhole.consume(buffer.remaining());
    }

    /// Schedules a packet and runs the pacer until it leaves.
    @Benchmark
    public void scheduleAndSend() {
        pacer.schedule(packet.duplicate(), Priority.VIDEO, 0x1234, sink);
        while (pacer.queuedPackets() > 0) {
            var next = pacer.process(now);
            now = Math.max(now + 1, next);
        }
    }
}
