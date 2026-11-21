package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.OpusFormat;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/// The jitter buffers on a manual clock: the audio playout buffer fed one 20 ms Opus packet per operation and
/// polled as the clock advances 20 ms, and the video frame assembler fed the five packets of a 5,000-byte VP8 frame
/// and polled for the frame.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class JitterBenchmark {
    private static final long FRAME_NANOS = 20_000_000L;

    private long now = 1_000_000_000L;
    private final MonotonicClock clock = () -> now;
    private AudioPlayoutBuffer audio;
    private VideoFrameAssembler video;
    private ByteBuffer audioPacket;
    private ByteBuffer audioPayload;
    private ByteBuffer[] videoPackets;
    private int audioSequence;
    private int videoSequence;
    private long videoTimestamp;
    private int pictureId;

    @Setup
    public void setup() {
        audio = AudioPlayoutBuffer.create(OpusFormat.defaults(), 48_000, AudioPlayoutConfig.defaults()
                .withClock(clock));
        video = VideoFrameAssembler.create(PayloadFormat.of(Codec.vp8()), VideoAssemblerConfig.defaults()
                .withClock(clock), FeedbackSink.NONE);
        audioPacket = ByteBuffer.allocate(200);
        audioPayload = ByteBuffer.wrap(new byte[]{(byte) 0xF8, 1, 2, 3, 4, 5, 6, 7});
        videoPackets = new ByteBuffer[5];
        for (var index = 0; index < videoPackets.length; index++) {
            videoPackets[index] = ByteBuffer.allocate(1500);
        }
    }

    /// Inserts one Opus packet and polls the playout outcomes due after 20 ms.
    @Benchmark
    public void audioInsertPoll(Blackhole blackhole) throws RtpFormatException {
        var sequence = audioSequence++;
        audioPacket.clear();
        var packet = RtpPacketWriter.into(audioPacket).payloadType(111).sequence(sequence & 0xFFFF)
                .timestamp(sequence * 960L & 0xFFFFFFFFL).ssrc(0x1234L).marker(false)
                .payload(audioPayload.duplicate()).finish();
        audio.insert(RtpPacket.parse(packet), now);
        now += FRAME_NANOS;
        Optional<AudioPlayout> outcome;
        while ((outcome = audio.poll()).isPresent()) {
            blackhole.consume(outcome.get());
        }
    }

    /// Inserts the five packets of a VP8 frame and polls the assembled frame.
    @Benchmark
    public void videoInsertPoll(Blackhole blackhole) throws RtpFormatException {
        var id = pictureId++ & 0x7FFF;
        videoTimestamp += 3000;
        for (var index = 0; index < 5; index++) {
            var buffer = videoPackets[index].clear();
            buffer.put((byte) 0x80).put((byte) (index == 4 ? 0x80 | 96 : 96)).putShort((short) videoSequence++)
                    .putInt((int) videoTimestamp).putInt(0x5678);
            // VP8 descriptor: X, and S on the first packet; I with a 15-bit picture id
            buffer.put((byte) (index == 0 ? 0x90 : 0x80)).put((byte) 0x80).put((byte) (0x80 | id >>> 8))
                    .put((byte) id);
            if (index == 0) {
                buffer.put((byte) (id == 0 ? 0x10 : 0x11));
            }
            buffer.position(1012);
            video.insert(RtpPacket.parse(buffer.flip()), now);
        }
        now += 33_000_000L;
        Optional<EncodedFrame> frame;
        while ((frame = video.poll()).isPresent()) {
            blackhole.consume(frame.get());
        }
    }
}
