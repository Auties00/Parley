package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.payload.Packetizer;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.sdp.SdesCrypto;
import com.github.auties00.parley.transport.SrtpTransport;
import com.github.auties00.srtp.SrtpCryptoSuite;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.SplittableRandom;
import java.util.concurrent.TimeUnit;

/// The media path of two RTP sessions, synchronously and on one thread: packetizing a frame, the send stream
/// (header extensions with MID, transport-wide sequence number and abs-send-time, NACK history, optionally ULPFEC
/// in RED), SRTP (AES-128-GCM), the receiving SRTP transport, BUNDLE demultiplexing, the receive stream with its
/// statistics, NACK tracking and transport-wide feedback bookkeeping, and the stream's packet receiver. With
/// `-prof gc`, the allocation per operation is the allocation per frame of the whole path.
///
/// - `audio`: one 160-byte Opus frame, one packet.
/// - `video`: one 5,000-byte VP8 frame, five packets.
/// - `videoUlpfec`: the VP8 frame with ULPFEC at 50% in RED.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class MediaPipelineBenchmark {
    @Param({"audio", "video", "videoUlpfec"})
    public String media;

    private RtpSession sender;
    private RtpSession receiver;
    private RtpSendStream stream;
    private Packetizer packetizer;
    private byte[] data;
    private long timestamp;
    private int pictureId;
    private long received;
    private long now = 1_000_000_000L;

    /// A path whose send calls the peer's receiver on the sending thread.
    static final class End implements DatagramTransport {
        PacketReceiver receiver = (_, _) -> { };
        End peer;

        @Override
        public void send(ByteBuffer datagram) {
            peer.receiver.receive(datagram, 0);
        }

        @Override
        public void setReceiver(PacketReceiver receiver) {
            this.receiver = receiver;
        }

        @Override
        public int maxDatagramSize() {
            return 1500;
        }

        @Override
        public void close() {
        }
    }

    static SdesCrypto crypto(long seed) {
        var suite = SrtpCryptoSuite.AEAD_AES_128_GCM;
        var material = new byte[suite.masterKeyLength() + suite.masterSaltLength()];
        new Random(seed).nextBytes(material);
        return new SdesCrypto(1, suite, material);
    }

    @Setup
    public void setup() {
        var left = new End();
        var right = new End();
        left.peer = right;
        right.peer = left;
        var a = crypto(1);
        var b = crypto(2);
        var leftSrtp = SrtpTransport.sdes(left, a, b);
        var rightSrtp = SrtpTransport.sdes(right, b, a);
        var extensions = HeaderExtensionMap.of(Map.of(1, HeaderExtensionUris.MID, 3,
                HeaderExtensionUris.TRANSPORT_WIDE_CC, 4, HeaderExtensionUris.ABS_SEND_TIME));
        sender = RtpSession.builder(leftSrtp).clock(() -> now).manualTimers().random(new SplittableRandom(1))
                .localSsrc(0x1000).cname("sender").extensions(extensions).build();
        receiver = RtpSession.builder(rightSrtp).clock(() -> now).manualTimers().random(new SplittableRandom(2))
                .localSsrc(0x2000).cname("receiver").extensions(extensions).build();
        var audio = media.equals("audio");
        var payloadType = audio ? 111 : 96;
        var clockRate = audio ? 48_000 : 90_000;
        var config = SendStreamConfig.builder("0", 0x11223344L, payloadType, clockRate).extensions(extensions)
                .feedback(audio ? Set.of(FeedbackMechanism.TRANSPORT_CC)
                        : Set.of(FeedbackMechanism.NACK, FeedbackMechanism.PLI, FeedbackMechanism.TRANSPORT_CC));
        var receiveConfig = ReceiveStreamConfig.builder(payloadType, clockRate).mid("0").ssrc(0x11223344L)
                .extensions(extensions).feedback(audio ? Set.of(FeedbackMechanism.TRANSPORT_CC)
                        : Set.of(FeedbackMechanism.NACK, FeedbackMechanism.PLI, FeedbackMechanism.TRANSPORT_CC));
        if (media.equals("videoUlpfec")) {
            var fec = new FecConfig.Ulpfec(100, 101, 50);
            config.fec(fec);
            receiveConfig.redPayloadType(100).fec(fec);
        }
        stream = sender.createSendStream(config.build());
        var receiveStream = receiver.createReceiveStream(receiveConfig.build());
        receiveStream.setPacketReceiver(_ -> received++);
        packetizer = PayloadFormat.of(audio ? Codec.opus() : Codec.vp8()).packetizer();
        data = new byte[audio ? 160 : 5000];
        new Random(3).nextBytes(data);
    }

    @TearDown
    public void tearDown() {
        sender.close();
        receiver.close();
    }

    /// Sends one frame through both sessions.
    @Benchmark
    public long sendReceive() throws IOException {
        now += 1_000_000L;
        EncodedFrame frame;
        if (media.equals("audio")) {
            timestamp += 960;
            data[0] = 0x78;
            frame = EncodedFrame.of(MediaKind.AUDIO, ByteBuffer.wrap(data), timestamp & 0xFFFFFFFFL, true);
        } else {
            timestamp += 3000;
            var id = pictureId++ & 0x7FFF;
            data[0] = (byte) (id == 0 ? 0x10 : 0x11);
            frame = new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), timestamp & 0xFFFFFFFFL, id == 0,
                    Optional.empty(), Vp8FrameMetadata.none().withPictureId(id,
                    Vp8FrameMetadata.none().tl0PicIndex()));
        }
        var payloads = new ArrayList<RtpSendStream.Payload>();
        for (var payload : packetizer.packetize(frame)) {
            payloads.add(new RtpSendStream.Payload(payload.header(), payload.body(), payload.marker(),
                    payload.extensions()));
        }
        stream.send(payloads, frame.rtpTimestamp(), frame.kind() == MediaKind.AUDIO
                ? OutgoingPacketScheduler.Priority.AUDIO : OutgoingPacketScheduler.Priority.VIDEO);
        return received;
    }
}
