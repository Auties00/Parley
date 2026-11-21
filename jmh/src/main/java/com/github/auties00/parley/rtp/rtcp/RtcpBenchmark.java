package com.github.auties00.parley.rtp.rtcp;

import org.openjdk.jmh.annotations.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.TimeUnit;

/// RTCP compound packets as a video sender and receiver exchange them: a sender report with two reception reports,
/// SDES CNAME, a NACK and a transport-wide feedback of 50 packets.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class RtcpBenchmark {
    private List<RtcpPacket> packets;
    private ByteBuffer encoded;

    @Setup
    public void setup() {
        var reports = List.of(new ReceptionReport(0x1111, 3, 10, 70_000, 40, 0x12345678L, 6000),
                new ReceptionReport(0x2222, 0, 0, 80_000, 12, 0x12345678L, 6000));
        var results = new ArrayList<TransportFeedback.PacketResult>();
        for (var index = 0; index < 50; index++) {
            results.add(new TransportFeedback.PacketResult(1000 + index, index % 10 == 9 ? OptionalLong.empty()
                    : OptionalLong.of(index * 250L)));
        }
        packets = List.of(
                new SenderReport(0x33333333L, 0xE1234567_89ABCDEFL, 123456, 1000, 1_000_000, reports),
                SourceDescription.ofCname(0x33333333L, "abcdefghijklmnop"),
                new Nack(0x33333333L, 0x1111, List.of(100, 101, 102, 140)),
                new TransportFeedback(0x33333333L, 0x1111, 1000, 12345, 7, results));
        encoded = RtcpPacket.encodeCompound(packets, 0);
    }

    /// Encodes the compound packet.
    @Benchmark
    public ByteBuffer encode() {
        return RtcpPacket.encodeCompound(packets, 0);
    }

    /// Parses the compound packet.
    @Benchmark
    public List<RtcpPacket> parse() throws RtcpFormatException {
        return RtcpPacket.parseCompound(encoded);
    }
}
