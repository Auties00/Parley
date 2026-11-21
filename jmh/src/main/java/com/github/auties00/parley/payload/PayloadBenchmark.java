package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Av1FrameMetadata;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.H264FrameMetadata;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/// Packetizing and depacketizing one frame: a 160-byte Opus frame, or a 5,000-byte VP8, H.264 (two slices in
/// Annex B) or AV1 (a temporal delimiter and a frame OBU) frame split at the default payload size.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class PayloadBenchmark {
    @Param({"opus", "vp8", "h264", "av1"})
    public String codec;

    private Packetizer packetizer;
    private Depacketizer depacketizer;
    private EncodedFrame frame;
    private List<RtpPacket> packets;

    static byte[] nonZero(int length, long seed) {
        var bytes = new byte[length];
        new Random(seed).nextBytes(bytes);
        for (var index = 0; index < length; index++) {
            if (bytes[index] == 0) {
                bytes[index] = 1;
            }
        }
        return bytes;
    }

    static void leb128(ByteArrayOutputStream out, int value) {
        do {
            var b = value & 0x7F;
            value >>>= 7;
            out.write(value != 0 ? b | 0x80 : b);
        } while (value != 0);
    }

    @Setup
    public void setup() throws RtpFormatException {
        var format = switch (codec) {
            case "opus" -> PayloadFormat.of(Codec.opus());
            case "vp8" -> PayloadFormat.of(Codec.vp8());
            case "h264" -> PayloadFormat.of(Codec.h264());
            case "av1" -> PayloadFormat.of(Codec.of("video/AV1", 90_000));
            default -> throw new IllegalArgumentException(codec);
        };
        frame = switch (codec) {
            case "opus" -> {
                var data = nonZero(160, 1);
                data[0] = (byte) 0x78;
                yield EncodedFrame.of(MediaKind.AUDIO, ByteBuffer.wrap(data), 960, true);
            }
            case "vp8" -> {
                var data = nonZero(5000, 2);
                data[0] = 0x10;
                yield new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), 3000, false, Optional.empty(),
                        Vp8FrameMetadata.none().withPictureId(7, Vp8FrameMetadata.none().tl0PicIndex()));
            }
            case "h264" -> {
                var out = new ByteArrayOutputStream();
                out.writeBytes(new byte[]{0, 0, 0, 1, 0x41});
                out.writeBytes(nonZero(2500, 3));
                out.writeBytes(new byte[]{0, 0, 1, 0x41});
                out.writeBytes(nonZero(2500, 4));
                yield new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(out.toByteArray()), 3000, false,
                        Optional.empty(), H264FrameMetadata.none());
            }
            case "av1" -> {
                var out = new ByteArrayOutputStream();
                out.write(2 << 3 | 0x02);
                leb128(out, 0);
                var payload = nonZero(5000, 5);
                payload[0] = 0x30;
                out.write(6 << 3 | 0x02);
                leb128(out, payload.length);
                out.writeBytes(payload);
                yield new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(out.toByteArray()), 3000, false,
                        Optional.empty(), Av1FrameMetadata.none());
            }
            default -> throw new IllegalArgumentException(codec);
        };
        packetizer = format.packetizer();
        depacketizer = format.depacketizer();
        var payloads = packetizer.packetize(frame);
        packets = new ArrayList<>();
        var sequence = 100;
        for (var payload : payloads) {
            var buffer = RtpPacketWriter.into(ByteBuffer.allocate(1500)).payloadType(96).sequence(sequence++)
                    .timestamp(frame.rtpTimestamp()).ssrc(0x11223344L).marker(payload.marker())
                    .payload(payload.payload()).finish();
            packets.add(RtpPacket.parse(buffer));
        }
    }

    /// Splits the frame into payloads.
    @Benchmark
    public List<PacketizedPayload> packetize() {
        return packetizer.packetize(frame);
    }

    /// Inspects every packet of the frame and reassembles it.
    @Benchmark
    public EncodedFrame depacketize(Blackhole blackhole) throws PayloadFormatException {
        for (var index = 0; index < packets.size(); index++) {
            blackhole.consume(depacketizer.inspect(packets.get(index)));
        }
        return depacketizer.assemble(packets);
    }
}
