package com.github.auties00.parley.rtp;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/// RTP packet parsing, writing with one-byte header extensions (MID, RID, transport-wide sequence, abs-send-time),
/// and extension lookups.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class RtpBenchmark {
    private ByteBuffer payload;
    private ByteBuffer destination;
    private ByteBuffer encoded;
    private ByteBuffer mid;
    private ByteBuffer rid;
    private ByteBuffer twcc;
    private ByteBuffer absSendTime;
    private int sequence;

    @Setup
    public void setup() {
        payload = ByteBuffer.allocate(1100);
        destination = ByteBuffer.allocate(1500);
        mid = ByteBuffer.wrap("0".getBytes(StandardCharsets.US_ASCII));
        rid = ByteBuffer.wrap("hi".getBytes(StandardCharsets.US_ASCII));
        twcc = ByteBuffer.allocate(2);
        absSendTime = ByteBuffer.allocate(3);
        encoded = write();
        var copy = ByteBuffer.allocate(encoded.remaining()).put(encoded.duplicate()).flip();
        encoded = copy;
    }

    private ByteBuffer write() {
        destination.clear();
        return RtpPacketWriter.into(destination).payloadType(96).marker(true).sequence(sequence++ & 0xFFFF)
                .timestamp(90_000).ssrc(0x11223344L).extension(1, mid.duplicate()).extension(2, rid.duplicate())
                .extension(3, twcc.duplicate()).extension(4, absSendTime.duplicate()).payload(payload.duplicate())
                .finish();
    }

    /// Writes a packet with four extensions into a reused buffer.
    @Benchmark
    public ByteBuffer writeWithExtensions() {
        return write();
    }

    /// Parses a packet with four extensions.
    @Benchmark
    public RtpPacket parse() throws RtpFormatException {
        return RtpPacket.parse(encoded);
    }

    /// Parses a packet and reads its header fields and two extensions.
    @Benchmark
    public void parseAndReadExtensions(Blackhole blackhole) throws RtpFormatException {
        var packet = RtpPacket.parse(encoded);
        blackhole.consume(packet.sequence());
        blackhole.consume(packet.timestamp());
        blackhole.consume(packet.ssrc());
        blackhole.consume(packet.extensionOffset(3));
        blackhole.consume(packet.extension(1));
        blackhole.consume(packet.payloadLength());
    }
}
