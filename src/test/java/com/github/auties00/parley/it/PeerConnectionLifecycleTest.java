package com.github.auties00.parley.it;

import com.github.auties00.parley.datachannel.DataChannelMessage;
import com.github.auties00.parley.datachannel.SctpTransportState;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.peer.Encoding;
import com.github.auties00.parley.peer.JsepDescription;
import com.github.auties00.parley.peer.LocalTrack;
import com.github.auties00.parley.peer.LocalTrackEvent;
import com.github.auties00.parley.peer.PeerConnectionEvent;
import com.github.auties00.parley.peer.PeerConnectionState;
import com.github.auties00.parley.peer.RemoteTrackMode;
import com.github.auties00.parley.peer.TransceiverDirection;
import com.github.auties00.parley.peer.TransceiverInit;
import com.github.auties00.parley.stats.PeerConnectionStats;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.github.auties00.parley.it.Loopback.connect;
import static com.github.auties00.parley.it.Loopback.negotiate;
import static com.github.auties00.parley.it.Loopback.peer;
import static com.github.auties00.parley.it.PeerConnectionScenariosTest.assertFrames;
import static com.github.auties00.parley.it.PeerConnectionScenariosTest.videoFrame;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Lifecycle scenarios between peer connections in one JVM: data channels added after media in either direction,
/// closing while the handshake runs, the transport views, and an SFU forwarding a simulcast publisher to a
/// subscriber.
@DisplayName("loopback lifecycle")
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class PeerConnectionLifecycleTest {
    @Test
    @DisplayName("opens a data channel the offerer adds to an audio connection by renegotiating")
    void dataChannelAfterAudioOfferer() throws Exception {
        try (var a = peer(); var b = peer()) {
            a.pc.addTrack(LocalTrack.audio("mic"), "s");
            connect(a, b);
            assertTrue(a.pc.sctp().isEmpty(), "no SCTP transport before a data section");
            var channel = a.pc.createDataChannel("late");
            negotiate(a, b);
            assertTrue(channel.awaitOpen(Loopback.TIMEOUT), "the late channel opens");
            var remote = b.await(PeerConnectionEvent.DataChannel.class, event -> true).channel();
            channel.send("ping");
            assertEquals(new DataChannelMessage.Text("ping"), remote.receive(Loopback.TIMEOUT).orElseThrow());
            var sctp = a.pc.sctp().orElseThrow();
            assertEquals(SctpTransportState.CONNECTED, sctp.state());
            assertTrue(sctp.maxMessageSize() > 0);
            assertEquals(com.github.auties00.parley.dtls.DtlsState.CONNECTED, sctp.transport().state());
            assertEquals(1, a.pc.getStats().all(PeerConnectionStats.class).getFirst().dataChannelsOpened());
        }
    }

    @Test
    @DisplayName("opens a data channel the answerer adds to an audio connection by renegotiating")
    void dataChannelAfterAudioAnswerer() throws Exception {
        try (var a = peer(); var b = peer()) {
            a.pc.addTrack(LocalTrack.audio("mic"), "s");
            connect(a, b);
            var channel = b.pc.createDataChannel("late");
            negotiate(b, a);
            assertTrue(channel.awaitOpen(Loopback.TIMEOUT), "the late channel opens");
            var remote = a.await(PeerConnectionEvent.DataChannel.class, event -> true).channel();
            remote.send("pong");
            assertEquals(new DataChannelMessage.Text("pong"), channel.receive(Loopback.TIMEOUT).orElseThrow());
        }
    }

    @Test
    @DisplayName("follows a peer that restarts DTLS: new association, media and data channels flow again")
    void dtlsRestart() throws Exception {
        try (var a = peer(); var b = peer()) {
            var track = LocalTrack.audio("mic");
            a.pc.addTrack(track, "s");
            var before = a.pc.createDataChannel("before");
            connect(a, b);
            assertTrue(before.awaitOpen(Loopback.TIMEOUT));
            var remote = b.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            var oldCertificate = a.pc.getSenders().getFirst().transport().orElseThrow().remoteCertificates();
            a.pc.setLocalDescription(a.pc.createOffer());
            var offer = a.gatheredDescription();
            var restarted = new JsepDescription(offer.type(), offer.sdp().replaceAll("a=tls-id:\\S+",
                    "a=tls-id:restarted0123456789abcdef"));
            assertFalse(restarted.sdp().equals(offer.sdp()), "the offer carries a tls-id");
            b.pc.setRemoteDescription(restarted);
            b.pc.setLocalDescription(b.pc.createAnswer());
            a.pc.setRemoteDescription(b.gatheredDescription());
            assertTrue(before.awaitClosed(Loopback.TIMEOUT), "the old association's channels close");
            var after = a.pc.createDataChannel("after");
            assertTrue(after.awaitOpen(Loopback.TIMEOUT), "a channel opens over the new association");
            var echo = b.await(PeerConnectionEvent.DataChannel.class, event -> event.channel().label().equals("after"))
                    .channel();
            after.send("again");
            assertEquals(new DataChannelMessage.Text("again"), echo.receive(Loopback.TIMEOUT).orElseThrow());
            try (var _ = PeerConnectionScenariosTest.audioWriter(track)) {
                assertFrames(remote, 10);
            }
            assertTrue(a.pc.awaitConnectionState(PeerConnectionState.CONNECTED, Loopback.TIMEOUT));
            assertEquals(oldCertificate.size(),
                    a.pc.getSenders().getFirst().transport().orElseThrow().remoteCertificates().size());
        }
    }

    @Test
    @DisplayName("exposes the DTLS and ICE transports of senders and receivers")
    void transportViews() throws Exception {
        try (var a = peer(); var b = peer()) {
            var sender = a.pc.addTrack(LocalTrack.audio("mic"), "s");
            assertTrue(sender.transport().isEmpty());
            connect(a, b);
            var dtls = sender.transport().orElseThrow();
            assertEquals(com.github.auties00.parley.dtls.DtlsState.CONNECTED, dtls.state());
            assertEquals(1, dtls.remoteCertificates().size());
            var ice = dtls.iceTransport();
            assertTrue(ice.selectedCandidatePair().isPresent());
            assertFalse(ice.localCandidates().isEmpty());
            assertTrue(ice.remoteParameters().isPresent());
            try (var events = dtls.events()) {
                var seen = new ArrayList<com.github.auties00.parley.dtls.DtlsState>();
                for (var event = events.next(Duration.ZERO); event.isPresent(); event = events.next(Duration.ZERO)) {
                    seen.add(event.get());
                }
                assertTrue(seen.contains(com.github.auties00.parley.dtls.DtlsState.CONNECTED),
                        "the first stream holds the state changes since the transport started: " + seen);
            }
            var receiver = b.pc.getReceivers().getFirst();
            assertTrue(receiver.transport().isPresent());
            assertTrue(a.pc.awaitConnectionState(PeerConnectionState.CONNECTED, Duration.ZERO));
        }
    }

    @Test
    @DisplayName("leaves no thread of the configured factory running after a close during the handshake")
    void closeDuringHandshake() throws Exception {
        var random = new Random(7);
        var threads = ConcurrentHashMap.<Thread>newKeySet();
        var base = Thread.ofVirtual().name("tracked-", 0).factory();
        ThreadFactory tracking = runnable -> {
            var thread = base.newThread(runnable);
            threads.add(thread);
            return thread;
        };
        for (var round = 0; round < 12; round++) {
            var a = peer(builder -> builder.threadFactory(tracking).networkStack(LoopbackOnlyStack.create(tracking)));
            var b = peer(builder -> builder.threadFactory(tracking).networkStack(LoopbackOnlyStack.create(tracking)));
            a.pc.addTrack(LocalTrack.audio("mic"), "s");
            a.pc.createDataChannel("chat");
            negotiate(a, b);
            Thread.sleep(random.nextInt(200));
            a.pc.close();
            b.pc.close();
            a.pc.close();
        }
        var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        List<Thread> alive = List.of();
        while (System.nanoTime() < deadline) {
            alive = threads.stream().filter(Thread::isAlive).toList();
            if (alive.isEmpty()) {
                break;
            }
            Thread.sleep(50);
        }
        var stacks = new ArrayList<String>();
        for (var thread : alive) {
            stacks.add(thread.getName() + " " + List.of(thread.getStackTrace()).stream().limit(4).toList());
        }
        assertTrue(alive.isEmpty(), "threads alive 3 s after close: " + stacks);
    }

    @Test
    @DisplayName("forwards a simulcast publisher through an SFU and switches layers on a key frame")
    void sfu() throws Exception {
        try (var publisher = peer();
             var sfuIn = peer(builder -> builder.remoteTrackMode(RemoteTrackMode.RAW_PACKETS));
             var sfuOut = peer();
             var subscriber = peer()) {
            var camera = LocalTrack.video("camera");
            publisher.pc.addTransceiver(camera, TransceiverInit.builder()
                    .direction(TransceiverDirection.SENDONLY)
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("l")))
                    .build());
            connect(publisher, sfuIn);
            var forwarded = LocalTrack.forwarded("relay", MediaKind.VIDEO);
            var forwardedEvents = forwarded.events();
            sfuOut.pc.addTrack(forwarded, "relay");
            connect(sfuOut, subscriber);
            assertTrue(sfuOut.pc.awaitConnectionState(PeerConnectionState.CONNECTED, Loopback.TIMEOUT));
            var incoming = sfuIn.await(PeerConnectionEvent.Track.class, event -> true).receiver();
            var outgoing = subscriber.await(PeerConnectionEvent.Track.class, event -> true).receiver().track();
            var cameraEvents = camera.events();
            var layer = new java.util.concurrent.atomic.AtomicReference<>("l");
            var running = new AtomicBoolean(true);
            var forwarder = Thread.ofVirtual().start(() -> {
                try (var packets = incoming.track().packets()) {
                    while (running.get()) {
                        var packet = packets.next(Duration.ofMillis(100));
                        if (packet.isPresent() && packet.get().rid().equals(Optional.of(layer.get()))) {
                            forwarded.write(packet.get());
                        }
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
            });
            var relay = Thread.ofVirtual().start(() -> {
                for (var event : forwardedEvents) {
                    if (event instanceof LocalTrackEvent.KeyframeRequested) {
                        incoming.requestKeyFrame(layer.get());
                    }
                }
            });
            var count = new int[1];
            try (var _ = new PeerConnectionScenariosTest.Writer(() -> {
                var keyframe = count[0] % 60 == 0;
                for (var rid : List.of("h", "l")) {
                    camera.write(videoFrame(count[0] * 3000L, 1500, keyframe), rid);
                }
                count[0]++;
            }, Duration.ofMillis(33))) {
                assertFrames(outgoing, 10);
                layer.set("h");
                var requested = false;
                var deadline = System.nanoTime() + Loopback.TIMEOUT.toNanos();
                while (!requested && System.nanoTime() < deadline) {
                    var event = cameraEvents.next(Duration.ofMillis(500));
                    requested = event.isPresent() && event.get()
                            .equals(new LocalTrackEvent.KeyframeRequested(Optional.of("h")));
                }
                assertTrue(requested, "the switch asks the publisher for a key frame on the new layer");
                assertFrames(outgoing, 10);
            } finally {
                running.set(false);
                forwarder.join(5000);
                forwardedEvents.close();
                relay.join(5000);
                cameraEvents.close();
            }
            assertEquals(1, subscriber.pc.getReceivers().getFirst().getSynchronizationSources().size(),
                    "the subscriber sees one stream across the layer switch");
        }
    }
}
