package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority;
import com.github.auties00.parley.rtp.session.SentPacket;
import org.openjdk.jmh.annotations.*;

import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.TimeUnit;

/// Google congestion control per transport-wide feedback: 20 sent packets of 1,200 bytes 5 ms apart, then the
/// feedback reporting them received with a little jitter.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class GccBenchmark {
    private static final long MS = 1_000_000L;

    private long now = 1_000 * MS;
    private final MonotonicClock clock = () -> now;
    private GoogleCongestionController controller;
    private int sequence;
    private int feedbackCount;
    private long referenceMicros;

    @Setup
    public void setup() {
        controller = new GoogleCongestionController(CongestionConfig.defaults().withClock(clock), false);
    }

    @TearDown
    public void tearDown() {
        controller.close();
    }

    /// Reports 20 sent packets, then their feedback.
    @Benchmark
    public void feedback() {
        var base = sequence & 0xFFFF;
        var results = new ArrayList<TransportFeedback.PacketResult>(20);
        for (var index = 0; index < 20; index++) {
            var seq = sequence++ & 0xFFFF;
            controller.onPacketSent(new SentPacket(seq, 1200, now, Priority.VIDEO, false, 1, seq));
            results.add(new TransportFeedback.PacketResult(seq,
                    OptionalLong.of(index == 0 ? 0 : 5000 + (index % 3) * 250)));
            now += 5 * MS;
        }
        referenceMicros += 100_000;
        controller.onTransportFeedback(new TransportFeedback(2, 1, base, referenceMicros / 64_000,
                feedbackCount++ & 0xFF, List.copyOf(results)), now);
    }
}
