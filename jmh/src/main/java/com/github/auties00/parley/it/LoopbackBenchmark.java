package com.github.auties00.parley.it;

import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.peer.Bitrates;
import com.github.auties00.parley.peer.Configuration;
import com.github.auties00.parley.peer.LocalTrack;
import com.github.auties00.parley.peer.PeerConnection;
import com.github.auties00.parley.peer.PeerConnectionEvent;
import com.github.auties00.parley.peer.PeerConnectionState;
import com.github.auties00.parley.peer.RemoteTrack;
import com.github.auties00.parley.peer.RemoteTrackMode;
import com.github.auties00.parley.ice.IceGatheringState;
import org.openjdk.jmh.annotations.*;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/// The whole path of two peer connections over loopback UDP, from writing an encoded frame into a local track to
/// reading it from the remote track: packetizing, RTP, pacing, SRTP, ICE, sockets, SRTP, demultiplexing, receive
/// statistics and the remote track's packet stream or jitter buffer. With `-prof gc` the allocation rate per
/// operation covers both peers' threads.
///
/// - `audioPacket`: one 160-byte Opus frame (one packet), read as a raw packet.
/// - `videoPackets`: one 5,000-byte VP8 frame (five packets), read as raw packets.
/// The time per operation is mostly the hand-offs between the threads (and, for video, pacing); the allocation
/// per operation is the figure of merit. [com.github.auties00.parley.rtp.session.MediaPipelineBenchmark] measures the
/// CPU of the same path on one thread.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class LoopbackBenchmark {
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    @Param({"audioPacket", "videoPackets"})
    public String path;

    private PeerConnection sender;
    private PeerConnection receiver;
    private LocalTrack track;
    private EventStream<RemoteTrack.Packet> packets;
    private byte[] data;
    private long timestamp;
    private int pictureId;
    private int packetsPerFrame;
    private boolean settling;

    private static PeerConnection peer(RemoteTrackMode mode) {
        return PeerConnection.create(Configuration.builder()
                .loopbackCandidates(true)
                .tcpCandidates(false)
                .remoteTrackMode(mode)
                .bitrates(new Bitrates(30_000, 50_000_000, 100_000_000))
                .build());
    }

    private static void awaitGathered(PeerConnection pc) throws InterruptedException, TimeoutException {
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (pc.iceGatheringState() != IceGatheringState.COMPLETE) {
            if (System.nanoTime() > deadline) {
                throw new TimeoutException("gathering did not complete");
            }
            Thread.sleep(10);
        }
    }

    @Setup(Level.Trial)
    public void setup() throws Exception {
        var audio = path.equals("audioPacket");
        sender = peer(RemoteTrackMode.JITTER_BUFFERED);
        receiver = peer(RemoteTrackMode.RAW_PACKETS);
        var tracks = new LinkedBlockingQueue<RemoteTrack>();
        var states = new LinkedBlockingQueue<PeerConnectionState>();
        receiver.addListener(event -> {
            if (event instanceof PeerConnectionEvent.Track trackEvent) {
                tracks.add(trackEvent.receiver().track());
            } else if (event instanceof PeerConnectionEvent.ConnectionStateChanged changed) {
                states.add(changed.state());
            }
        });
        track = audio ? LocalTrack.audio("mic") : LocalTrack.video("cam");
        sender.addTrack(track, List.of("stream"));
        sender.setLocalDescription(sender.createOffer());
        awaitGathered(sender);
        receiver.setRemoteDescription(sender.localDescription().orElseThrow());
        receiver.setLocalDescription(receiver.createAnswer());
        awaitGathered(receiver);
        sender.setRemoteDescription(receiver.localDescription().orElseThrow());
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        PeerConnectionState state;
        do {
            state = states.poll(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            if (state == null) {
                throw new TimeoutException("not connected");
            }
        } while (state != PeerConnectionState.CONNECTED);
        var remote = tracks.poll(TIMEOUT.toNanos(), TimeUnit.NANOSECONDS);
        if (remote == null) {
            throw new TimeoutException("no remote track");
        }
        packets = remote.packets();
        data = new byte[audio ? 160 : 5000];
        new Random(1).nextBytes(data);
        data[0] = (byte) (audio ? 0x78 : 0x10);
        packetsPerFrame = audio ? 1 : -1;
        // The first frames wait for the transport to settle; send key frames until one arrives
        settling = true;
        for (var index = 0; index < 50; index++) {
            write();
            if (read(Duration.ofMillis(100))) {
                break;
            }
        }
        settling = false;
        drain();
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        sender.close();
        receiver.close();
    }

    private void write() {
        if (track.kind() == MediaKind.AUDIO) {
            timestamp += 960;
            track.write(EncodedFrame.of(MediaKind.AUDIO, ByteBuffer.wrap(data), timestamp & 0xFFFFFFFFL, true));
        } else {
            timestamp += 3000;
            var id = pictureId++ & 0x7FFF;
            // A key frame every 60 frames, and every frame until the first one arrives
            var key = settling || id % 60 == 0;
            data[0] = (byte) (key ? 0x10 : 0x11);
            track.write(new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), timestamp & 0xFFFFFFFFL, key,
                    Optional.empty(), Vp8FrameMetadata.none().withPictureId(id,
                    Vp8FrameMetadata.none().tl0PicIndex())));
        }
    }

    /// Reads one frame's worth of packets: up to the one with the marker bit.
    private boolean read(Duration timeout) throws InterruptedException {
        while (true) {
            var packet = packets.next(timeout);
            if (packet.isEmpty()) {
                return false;
            }
            if (packet.get().packet().marker() || packetsPerFrame == 1) {
                return true;
            }
        }
    }

    private void drain() throws InterruptedException {
        while (read(Duration.ofMillis(50))) {
            // discard what the warm-up left queued
        }
    }

    /// Writes one frame and waits until the remote track delivers it.
    @Benchmark
    public void sendReceive() throws InterruptedException, TimeoutException {
        write();
        if (!read(TIMEOUT)) {
            throw new TimeoutException("the frame did not arrive");
        }
    }
}
