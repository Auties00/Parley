package com.github.auties00.parley.it;

import com.github.auties00.parley.datachannel.DataChannelMessage;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.peer.LocalTrack;
import com.github.auties00.parley.peer.PeerConnectionEvent;
import com.github.auties00.parley.peer.PeerConnectionState;
import com.github.auties00.parley.peer.SignalingState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.github.auties00.parley.it.Loopback.connect;
import static com.github.auties00.parley.it.Loopback.peer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Two peer connections in one JVM over loopback: ICE, DTLS, SRTP, RTP and SCTP end to end.
@DisplayName("loopback peer connections")
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class PeerConnectionLoopbackTest {
    static EncodedFrame opusFrame(long timestamp) {
        var payload = new byte[60];
        payload[0] = (byte) 0x78;
        for (var index = 1; index < payload.length; index++) {
            payload[index] = (byte) (timestamp + index);
        }
        return EncodedFrame.of(MediaKind.AUDIO, ByteBuffer.wrap(payload), timestamp, true);
    }

    @Test
    @DisplayName("opens a data channel created before the offer and carries text and binary both ways")
    void dataChannel() throws Exception {
        try (var a = peer(); var b = peer()) {
            var channel = a.pc.createDataChannel("chat");
            connect(a, b);
            var remote = b.await(PeerConnectionEvent.DataChannel.class, event -> true).channel();
            channel.awaitOpen(Loopback.TIMEOUT);
            channel.send("hello");
            assertEquals(new DataChannelMessage.Text("hello"), remote.receive(Loopback.TIMEOUT).orElseThrow());
            remote.send(ByteBuffer.wrap(new byte[]{1, 2, 3}));
            var binary = (DataChannelMessage.Binary) channel.receive(Loopback.TIMEOUT).orElseThrow();
            assertEquals(3, binary.value().remaining());
            assertEquals("chat", remote.label());
        }
    }

    @Test
    @DisplayName("sends audio frames that come out of the remote track in order")
    void audio() throws Exception {
        try (var a = peer(); var b = peer()) {
            var track = LocalTrack.audio("mic");
            a.pc.addTrack(track, List.of("stream"));
            connect(a, b);
            var event = b.await(PeerConnectionEvent.Track.class, e -> true);
            assertEquals(List.of("stream"), event.streams());
            var remote = event.receiver().track();
            var writer = Thread.ofVirtual().start(() -> {
                for (var index = 0; index < 150 && !Thread.currentThread().isInterrupted(); index++) {
                    track.write(opusFrame(index * 960L));
                    try {
                        Thread.sleep(20);
                    } catch (InterruptedException exception) {
                        return;
                    }
                }
            });
            var received = 0;
            var last = -1L;
            var deadline = System.nanoTime() + Loopback.TIMEOUT.toNanos();
            while (received < 20 && System.nanoTime() < deadline) {
                var frame = remote.read(Duration.ofSeconds(2));
                if (frame.isEmpty()) {
                    continue;
                }
                assertTrue(frame.get().rtpTimestamp() > last, "frames arrive in timestamp order");
                last = frame.get().rtpTimestamp();
                received++;
            }
            writer.interrupt();
            assertTrue(received >= 20, "received " + received + " frames");
            assertTrue(b.pc.getReceivers().getFirst().getSynchronizationSources().size() == 1);
            var stats = a.pc.getStats();
            assertTrue(stats.stream(com.github.auties00.parley.stats.OutboundRtpStreamStats.class)
                    .anyMatch(outbound -> outbound.packetsSent() > 0));
            assertTrue(b.pc.getStats().stream(com.github.auties00.parley.stats.InboundRtpStreamStats.class)
                    .anyMatch(inbound -> inbound.packetsReceived() > 0));
            var transport = stats.all(com.github.auties00.parley.stats.TransportStats.class).getFirst();
            var pair = transport.selectedCandidatePairId().flatMap(id -> stats.get(id,
                    com.github.auties00.parley.stats.IceCandidatePairStats.class)).orElseThrow();
            assertTrue(pair.nominated());
            assertTrue(transport.dtlsCipher().isPresent() && transport.srtpCipher().isPresent());
            assertEquals(SignalingState.STABLE, a.pc.signalingState());
            assertEquals(PeerConnectionState.CONNECTED, a.pc.connectionState());
        }
    }
}
