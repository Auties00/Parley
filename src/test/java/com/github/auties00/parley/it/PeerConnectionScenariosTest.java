package com.github.auties00.parley.it;

import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelMessage;
import com.github.auties00.parley.dtls.DtlsVersion;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.ice.IceServer;
import com.github.auties00.parley.ice.IceTransportPolicy;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.peer.Encoding;
import com.github.auties00.parley.peer.LocalTrack;
import com.github.auties00.parley.peer.LocalTrackEvent;
import com.github.auties00.parley.peer.LocalVideoTrack;
import com.github.auties00.parley.peer.PeerConnectionEvent;
import com.github.auties00.parley.peer.PeerConnectionState;
import com.github.auties00.parley.peer.RemoteTrackMode;
import com.github.auties00.parley.peer.SignalingState;
import com.github.auties00.parley.peer.TransceiverDirection;
import com.github.auties00.parley.peer.TransceiverInit;
import com.github.auties00.parley.stats.InboundRtpStreamStats;
import com.github.auties00.parley.stats.IceCandidateStats;
import com.github.auties00.parley.stats.TransportStats;
import com.github.auties00.parley.turn.TestCertificates;
import com.github.auties00.parley.turn.TestTurnServer;
import com.github.auties00.parley.turn.TurnTransport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.github.auties00.parley.it.Loopback.connect;
import static com.github.auties00.parley.it.Loopback.negotiate;
import static com.github.auties00.parley.it.Loopback.peer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// End-to-end scenarios between two peer connections in one JVM: simulcast, renegotiation, glare, ICE restarts,
/// TURN relays over UDP, TCP and TLS, an ICE-lite peer, both DTLS versions, the SRTP profiles, DTMF and a lossy path
/// that exercises NACK, RTX and congestion control.
@DisplayName("loopback scenarios")
@Timeout(value = 90, unit = TimeUnit.SECONDS)
class PeerConnectionScenariosTest {
    /// Writes frames to a track on a virtual thread until stopped.
    static final class Writer implements AutoCloseable {
        private final AtomicBoolean running = new AtomicBoolean(true);
        private final Thread thread;

        Writer(Runnable step, Duration interval) {
            thread = Thread.ofVirtual().start(() -> {
                while (running.get()) {
                    step.run();
                    try {
                        Thread.sleep(interval);
                    } catch (InterruptedException exception) {
                        return;
                    }
                }
            });
        }

        /// Stops writing and waits for the writer thread to end.
        void stop() throws InterruptedException {
            running.set(false);
            thread.interrupt();
            thread.join();
        }

        @Override
        public void close() {
            running.set(false);
            thread.interrupt();
        }
    }

    /// {@return a video frame of `size` bytes whose first byte marks a VP8 key frame or not}
    static EncodedFrame videoFrame(long timestamp, int size, boolean keyframe) {
        var payload = new byte[size];
        payload[0] = (byte) (keyframe ? 0x10 : 0x11);
        for (var index = 1; index < size; index++) {
            payload[index] = (byte) (index * 31 + timestamp);
        }
        return EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.wrap(payload), timestamp, keyframe);
    }

    /// {@return a writer of audio frames every 20 ms}
    static Writer audioWriter(LocalTrack track) {
        var timestamp = new long[1];
        return new Writer(() -> {
            track.write(PeerConnectionLoopbackTest.opusFrame(timestamp[0]));
            timestamp[0] += 960;
        }, Duration.ofMillis(20));
    }

    /// {@return a writer of video frames of `size` bytes at 30 fps, a key frame every second}
    static Writer videoWriter(LocalVideoTrack track, int size, List<String> rids) {
        var count = new int[1];
        return new Writer(() -> {
            var keyframe = count[0] % 30 == 0;
            var timestamp = count[0] * 3000L;
            if (rids.isEmpty()) {
                track.write(videoFrame(timestamp, size, keyframe));
            } else {
                for (var rid : rids) {
                    track.write(videoFrame(timestamp, size, keyframe), rid);
                }
            }
            count[0]++;
        }, Duration.ofMillis(33));
    }

    /// Waits until a data channel opened by `a` reaches `b` and echoes one message.
    static void assertDataFlows(Loopback.Peer a, Loopback.Peer b, DataChannel channel) throws Exception {
        var remote = b.await(PeerConnectionEvent.DataChannel.class, event -> event.channel().label()
                .equals(channel.label())).channel();
        channel.awaitOpen(Loopback.TIMEOUT);
        channel.send("ping");
        assertEquals(new DataChannelMessage.Text("ping"), remote.receive(Loopback.TIMEOUT).orElseThrow());
    }

    /// Waits until a remote track delivers `count` frames.
    static void assertFrames(com.github.auties00.parley.peer.RemoteTrack track, int count) throws Exception {
        var received = 0;
        var deadline = System.nanoTime() + Loopback.TIMEOUT.toNanos();
        while (received < count && System.nanoTime() < deadline) {
            if (track.read(Duration.ofMillis(500)).isPresent()) {
                received++;
            }
        }
        assertTrue(received >= count, "received " + received + " of " + count + " frames");
    }

    @Test
    @DisplayName("forwards three simulcast layers to a raw-packet receiver, each with its rid")
    void simulcast() throws Exception {
        try (var a = peer(); var b = peer(builder -> builder.remoteTrackMode(RemoteTrackMode.RAW_PACKETS))) {
            var track = LocalTrack.video("cam");
            a.pc.addTransceiver(track, TransceiverInit.builder()
                    .direction(TransceiverDirection.SENDONLY)
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("m").scaleDown(2),
                            Encoding.rid("l").scaleDown(4)))
                    .build());
            connect(a, b);
            var remote = b.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            var perRid = new HashMap<String, Integer>();
            try (var _ = videoWriter(track, 3000, List.of("h", "m", "l"))) {
                var deadline = System.nanoTime() + Loopback.TIMEOUT.toNanos();
                while (perRid.values().stream().filter(count -> count >= 10).count() < 3
                        && System.nanoTime() < deadline) {
                    var packet = remote.readPacket(Duration.ofMillis(500));
                    packet.ifPresent(value -> perRid.merge(value.rid().orElse("?"), 1, Integer::sum));
                }
            }
            assertEquals(Set.of("h", "m", "l"), perRid.keySet().stream().filter(rid -> perRid.get(rid) >= 10)
                    .collect(java.util.stream.Collectors.toSet()), "packets per rid: " + perRid);
        }
    }

    @Test
    @DisplayName("carries audio, three simulcast layers and a data channel on one bundled transport")
    void everything() throws Exception {
        try (var a = peer(); var b = peer(builder -> builder.remoteTrackMode(RemoteTrackMode.RAW_PACKETS))) {
            var audio = LocalTrack.audio("mic");
            var video = LocalTrack.video("cam");
            a.pc.addTrack(audio, List.of("av"));
            a.pc.addTransceiver(video, TransceiverInit.builder()
                    .direction(TransceiverDirection.SENDONLY)
                    .streams(List.of("av"))
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("m").scaleDown(2),
                            Encoding.rid("l").scaleDown(4)))
                    .build());
            var channel = a.pc.createDataChannel("control");
            connect(a, b);
            assertDataFlows(a, b, channel);
            var counts = new HashMap<String, Integer>();
            try (var _ = audioWriter(audio); var _ = videoWriter(video, 2000, List.of("h", "m", "l"))) {
                var tracks = new java.util.ArrayList<com.github.auties00.parley.peer.RemoteTrack>();
                tracks.add(b.await(PeerConnectionEvent.Track.class, event -> event.receiver().track().kind()
                        == MediaKind.AUDIO).receiver().track());
                tracks.add(b.await(PeerConnectionEvent.Track.class, event -> event.receiver().track().kind()
                        == MediaKind.VIDEO).receiver().track());
                var deadline = System.nanoTime() + Loopback.TIMEOUT.toNanos();
                while (counts.values().stream().filter(count -> count >= 10).count() < 4
                        && System.nanoTime() < deadline) {
                    for (var track : tracks) {
                        var packet = track.readPacket(Duration.ofMillis(50));
                        packet.ifPresent(value -> counts.merge(track.kind() + value.rid().map(rid -> "/" + rid)
                                .orElse(""), 1, Integer::sum));
                    }
                }
            }
            assertTrue(counts.getOrDefault("AUDIO", 0) >= 10, "packets: " + counts);
            for (var rid : List.of("h", "m", "l")) {
                assertTrue(counts.getOrDefault("VIDEO/" + rid, 0) >= 10, "packets: " + counts);
            }
            var stats = a.pc.getStats();
            assertEquals(1, stats.all(TransportStats.class).size(), "everything is bundled on one transport");
            assertEquals(4, stats.all(com.github.auties00.parley.stats.OutboundRtpStreamStats.class).size());
            assertTrue(stats.all(com.github.auties00.parley.stats.CodecStats.class).size() >= 2);
            assertTrue(stats.all(com.github.auties00.parley.stats.DataChannelStats.class).stream()
                    .anyMatch(data -> data.messagesSent() > 0));
            assertTrue(stats.all(com.github.auties00.parley.stats.CertificateStats.class).size() >= 2);
            var outbound = a.pc.getSenders().getFirst().getStats();
            assertEquals(1, outbound.all(com.github.auties00.parley.stats.OutboundRtpStreamStats.class).size());
        }
    }

    @Test
    @DisplayName("adds audio to a data-only connection by renegotiating")
    void renegotiation() throws Exception {
        try (var a = peer(); var b = peer()) {
            var channel = a.pc.createDataChannel("first");
            connect(a, b);
            assertDataFlows(a, b, channel);
            var track = LocalTrack.audio("late-mic");
            a.pc.addTrack(track, List.of());
            a.await(PeerConnectionEvent.NegotiationNeeded.class, event -> true);
            negotiate(a, b);
            var remote = b.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            try (var _ = audioWriter(track)) {
                assertFrames(remote, 10);
            }
            assertEquals(PeerConnectionState.CONNECTED, a.pc.connectionState());
        }
    }

    @Test
    @DisplayName("resolves glare with perfect negotiation and connects")
    void perfectNegotiation() throws Exception {
        try (var polite = peer(); var impolite = peer()) {
            var politeTrack = LocalTrack.audio("polite");
            var impoliteTrack = LocalTrack.audio("impolite");
            polite.pc.addTrack(politeTrack, List.of());
            impolite.pc.addTrack(impoliteTrack, List.of());
            polite.pc.setLocalDescription();
            impolite.pc.setLocalDescription();
            var impoliteOffer = impolite.gatheredDescription();
            polite.pc.setRemoteDescription(impoliteOffer);
            polite.pc.setLocalDescription();
            impolite.pc.setRemoteDescription(polite.gatheredDescription());
            polite.awaitState(PeerConnectionState.CONNECTED);
            impolite.awaitState(PeerConnectionState.CONNECTED);
            var remote = polite.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            try (var _ = audioWriter(impoliteTrack)) {
                assertFrames(remote, 10);
            }
            assertEquals(SignalingState.STABLE, polite.pc.signalingState());
        }
    }

    @Test
    @DisplayName("restarts ICE without losing the data channel")
    void iceRestart() throws Exception {
        try (var a = peer(); var b = peer()) {
            var channel = a.pc.createDataChannel("survivor");
            connect(a, b);
            assertDataFlows(a, b, channel);
            var before = a.pc.currentLocalDescription().orElseThrow().sdp();
            a.pc.restartIce();
            negotiate(a, b);
            var after = a.pc.currentLocalDescription().orElseThrow().sdp();
            assertTrue(!ufrag(before).equals(ufrag(after)), "the restart changed the credentials");
            Thread.sleep(500);
            channel.send("after restart");
            var remote = b.await(PeerConnectionEvent.DataChannel.class, event -> true).channel();
            assertEquals(new DataChannelMessage.Text("after restart"), remote.receive(Loopback.TIMEOUT)
                    .orElseThrow());
            assertEquals(PeerConnectionState.CONNECTED, a.pc.connectionState());
        }
    }

    /// {@return the first ice-ufrag of an SDP}
    static String ufrag(String sdp) {
        return sdp.lines().filter(line -> line.startsWith("a=ice-ufrag:")).findFirst().orElseThrow();
    }

    @Nested
    @DisplayName("TURN")
    class Turn {
        @ParameterizedTest
        @EnumSource(TurnTransport.class)
        @DisplayName("connects two relay-only peers through the test TURN server")
        void relay(TurnTransport transport) throws Exception {
            try (var server = TestTurnServer.start()) {
                var turn = new IceServer(List.of(server.turnUri(transport)), Optional.of(TestTurnServer.USERNAME),
                        Optional.of(TestTurnServer.PASSWORD));
                var context = TestCertificates.clientContext();
                try (var a = peer(builder -> builder.iceServers(List.of(turn))
                        .iceTransportPolicy(IceTransportPolicy.RELAY).networkStack(LoopbackOnlyStack.create(context)));
                     var b = peer(builder -> builder.iceServers(List.of(turn))
                             .iceTransportPolicy(IceTransportPolicy.RELAY)
                             .networkStack(LoopbackOnlyStack.create(context)))) {
                    var channel = a.pc.createDataChannel("relayed");
                    connect(a, b);
                    assertDataFlows(a, b, channel);
                    var stats = a.pc.getStats();
                    var transportStats = stats.all(TransportStats.class).getFirst();
                    var pair = stats.get(transportStats.selectedCandidatePairId().orElseThrow(),
                            com.github.auties00.parley.stats.IceCandidatePairStats.class).orElseThrow();
                    var local = stats.get(pair.localCandidateId(), IceCandidateStats.class).orElseThrow();
                    assertEquals(IceCandidateStats.CandidateType.RELAY, local.candidateType());
                    assertTrue(server.allocations() >= 2);
                }
            }
        }
    }

    @Test
    @DisplayName("connects a full agent to an ICE-lite peer")
    void iceLite() throws Exception {
        try (var a = peer(); var b = peer(builder -> builder.iceLite(true))) {
            var track = LocalTrack.audio("mic");
            a.pc.addTrack(track, List.of());
            var channel = a.pc.createDataChannel("lite");
            connect(a, b);
            assertDataFlows(a, b, channel);
            var remote = b.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            try (var _ = audioWriter(track)) {
                assertFrames(remote, 10);
            }
        }
    }

    @ParameterizedTest
    @EnumSource(DtlsVersion.class)
    @DisplayName("handshakes with each DTLS version")
    void dtlsVersions(DtlsVersion version) throws Exception {
        try (var a = peer(builder -> builder.dtlsVersions(Set.of(version)));
             var b = peer(builder -> builder.dtlsVersions(Set.of(version)))) {
            var channel = a.pc.createDataChannel("v");
            a.pc.addTrack(LocalTrack.audio("mic"), List.of());
            connect(a, b);
            assertDataFlows(a, b, channel);
            var transport = a.pc.getStats().all(TransportStats.class).getFirst();
            assertEquals(Optional.of(version == DtlsVersion.DTLS_1_3 ? "FEFC" : "FEFD"), transport.tlsVersion());
        }
    }

    @ParameterizedTest
    @EnumSource(SrtpProfile.class)
    @DisplayName("protects media with each SRTP profile")
    void srtpProfiles(SrtpProfile profile) throws Exception {
        try (var a = peer(builder -> builder.srtpProfiles(List.of(profile)));
             var b = peer(builder -> builder.srtpProfiles(List.of(profile)))) {
            var track = LocalTrack.audio("mic");
            a.pc.addTrack(track, List.of());
            connect(a, b);
            var remote = b.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            try (var _ = audioWriter(track)) {
                assertFrames(remote, 10);
            }
            var transport = a.pc.getStats().all(TransportStats.class).getFirst();
            assertEquals(Optional.of(profile.name()), transport.srtpCipher());
        }
    }

    @Test
    @DisplayName("sends DTMF as RFC 4733 events on the audio stream")
    void dtmf() throws Exception {
        try (var a = peer(); var b = peer(builder -> builder.remoteTrackMode(RemoteTrackMode.RAW_PACKETS))) {
            var sender = a.pc.addTrack(LocalTrack.audio("mic"), List.of());
            connect(a, b);
            var remote = b.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            var dtmf = sender.dtmf().orElseThrow();
            assertTrue(dtmf.canInsertDtmf());
            var eventPt = b.pc.getReceivers().getFirst().getParameters().codecs().stream()
                    .filter(codec -> codec.codec().mimeType().equalsIgnoreCase("audio/telephone-event"))
                    .findFirst();
            dtmf.insertDtmf("12", Duration.ofMillis(100), Duration.ofMillis(50));
            var events = 0;
            var ends = 0;
            var deadline = System.nanoTime() + Loopback.TIMEOUT.toNanos();
            while (ends < 6 && System.nanoTime() < deadline) {
                var packet = remote.readPacket(Duration.ofMillis(500));
                if (packet.isEmpty()) {
                    continue;
                }
                var payload = packet.get().packet().payload();
                if (payload.remaining() == 4 && eventPt.isEmpty() || eventPt.isPresent()
                        && packet.get().packet().payloadType() == eventPt.get().payloadType()) {
                    events++;
                    if ((payload.get(payload.position() + 1) & 0x80) != 0) {
                        ends++;
                    }
                }
            }
            assertTrue(events > 6, "events: " + events);
            assertEquals(6, ends, "two tones, each ended three times");
        }
    }

    @Test
    @DisplayName("recovers lost video packets with NACK and RTX and lowers the target bitrate under heavy loss")
    void lossyPath() throws Exception {
        var stack = LoopbackOnlyStack.create();
        try (var a = peer(builder -> builder.networkStack(stack)); var b = peer()) {
            var track = LocalTrack.video("cam");
            a.pc.addTransceiver(track, TransceiverInit.of(TransceiverDirection.SENDONLY));
            connect(a, b);
            var remote = b.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            try (var _ = videoWriter(track, 4000, List.of())) {
                assertFrames(remote, 15);
                var rampUp = waitForTarget(track, target -> target > 300_000);
                assertTrue(rampUp > 300_000, "the target rose to " + rampUp);
                stack.setLoss(0.05, 300);
                assertFrames(remote, 30);
                var inbound = b.pc.getStats().all(InboundRtpStreamStats.class).getFirst();
                assertTrue(inbound.nackCount() > 0, "NACKs sent: " + inbound.nackCount());
                assertTrue(inbound.retransmittedPacketsReceived() > 0,
                        "retransmissions: " + inbound.retransmittedPacketsReceived());
                assertTrue(inbound.fecPacketsReceived() > 0, "FEC packets: " + inbound.fecPacketsReceived());
                stack.setLoss(0.4, 300);
                var lowered = waitForTarget(track, target -> target < rampUp / 2);
                assertTrue(lowered < rampUp / 2, "the target fell to " + lowered + " from " + rampUp);
                assertTrue(stack.dropped() > 0);
            }
        }
    }

    /// Waits until the track's target bitrate satisfies `condition`, returning the last target.
    static long waitForTarget(LocalTrack track, java.util.function.LongPredicate condition) throws Exception {
        var deadline = System.nanoTime() + Loopback.TIMEOUT.toNanos();
        try (var events = track.events()) {
            var last = track.targetBitrate().orElse(0);
            while (!condition.test(last) && System.nanoTime() < deadline) {
                var event = events.next(Duration.ofMillis(500));
                if (event.isPresent() && event.get() instanceof LocalTrackEvent.TargetBitrateChanged changed) {
                    last = changed.bitsPerSecond();
                }
            }
            return last;
        }
    }
}
