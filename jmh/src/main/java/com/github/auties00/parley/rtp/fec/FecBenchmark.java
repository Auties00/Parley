package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/// ULPFEC and FlexFEC over a block of ten 1,100-byte media packets at 50% protection: encoding the repair packets,
/// and recovering one lost packet from them.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class FecBenchmark {
    private static final long SSRC = 0x55667788L;

    @Param({"ULPFEC", "FLEXFEC"})
    public String format;

    private FecFormat fecFormat;
    private List<RtpPacket> media;
    private List<ByteBuffer> repairs;

    @Setup
    public void setup() throws RtpFormatException {
        fecFormat = FecFormat.valueOf(format);
        media = new ArrayList<>();
        var random = new Random(9);
        for (var sequence = 0; sequence < 10; sequence++) {
            var payload = new byte[1100 - sequence * 3];
            random.nextBytes(payload);
            media.add(RtpPacket.parse(RtpPacketWriter.into(ByteBuffer.allocate(1200)).payloadType(96).ssrc(SSRC)
                    .sequence(sequence).timestamp(3000L * (sequence / 5)).marker(sequence % 5 == 4)
                    .payload(ByteBuffer.wrap(payload)).finish()));
        }
        repairs = encodeBlock();
    }

    private List<ByteBuffer> encodeBlock() {
        var encoder = FecEncoder.create(fecFormat, SSRC, 50);
        for (var index = 0; index < media.size(); index++) {
            encoder.add(media.get(index));
        }
        return encoder.flush();
    }

    /// Encodes the repair packets of the block.
    @Benchmark
    public List<ByteBuffer> encode() {
        return encodeBlock();
    }

    /// Recovers the third packet of the block from the other nine and the repair packets.
    @Benchmark
    public void recover(Blackhole blackhole) throws RtpFormatException {
        var decoder = new FecDecoder(fecFormat, SSRC);
        for (var index = 0; index < media.size(); index++) {
            if (index != 2) {
                blackhole.consume(decoder.addMedia(media.get(index)));
            }
        }
        for (var index = 0; index < repairs.size(); index++) {
            blackhole.consume(decoder.addFec(repairs.get(index).duplicate()));
        }
    }
}
