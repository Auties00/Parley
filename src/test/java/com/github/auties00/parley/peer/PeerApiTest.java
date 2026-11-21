package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceTransportPolicy;
import com.github.auties00.parley.ice.IceTransportState;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.stats.InboundRtpStreamStats;
import com.github.auties00.parley.stats.OutboundRtpStreamStats;
import com.github.auties00.parley.stats.PeerConnectionStats;
import com.github.auties00.parley.stats.RtcStats;
import com.github.auties00.parley.stats.TransportStats;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.github.auties00.parley.peer.Peers.negotiate;
import static com.github.auties00.parley.peer.Peers.peer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the object model around the JSEP engine: senders and their parameters, tracks, DTMF, events, the
/// aggregate states, the configuration and the statistics selection, over a fake backend.
@DisplayName("peer API")
class PeerApiTest {
    static EncodedFrame frame(MediaKind kind) {
        return EncodedFrame.of(kind, ByteBuffer.wrap(new byte[]{1, 2, 3}), 1000, true);
    }

    @Nested
    @DisplayName("senders")
    class Senders {
        @Test
        @DisplayName("allow changing caps and activity through getParameters and setParameters")
        void setParameters() {
            var a = peer();
            var sender = a.pc().addTransceiver(MediaKind.VIDEO, TransceiverInit.builder()
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("l").withScaleResolutionDownBy(4))).build()).sender();
            assertThrows(InvalidStateException.class, () -> sender.setParameters(new RtpSendParameters("x",
                    List.of(), List.of(), new RtcpParameters("c", false), List.of())));
            var parameters = sender.getParameters();
            assertEquals(2, parameters.encodings().size());
            var edited = parameters.withEncodings(List.of(parameters.encodings().get(0).withMaxBitrate(1_000_000),
                    parameters.encodings().get(1).withActive(false)));
            sender.setParameters(edited);
            var again = sender.getParameters();
            assertEquals(OptionalLong.of(1_000_000), again.encodings().get(0).maxBitrate());
            assertFalse(again.encodings().get(1).active());
            assertThrows(InvalidModificationException.class, () -> sender.setParameters(edited));
            var fresh = sender.getParameters();
            assertThrows(InvalidModificationException.class, () -> sender.setParameters(
                    fresh.withEncodings(List.of(fresh.encodings().getFirst()))));
            var renamed = sender.getParameters();
            assertThrows(InvalidModificationException.class, () -> sender.setParameters(renamed.withEncodings(
                    List.of(renamed.encodings().get(0).withRid("x"), renamed.encodings().get(1)))));
        }

        @Test
        @DisplayName("reject invalid encodings and simulcast layers without rids")
        void encodings() {
            assertThrows(IllegalArgumentException.class, () -> Encoding.rid("a.b"));
            assertThrows(IllegalArgumentException.class, () -> Encoding.defaults().withScaleResolutionDownBy(0.5));
            assertThrows(IllegalArgumentException.class, () -> Encoding.defaults().withMaxBitrate(0));
            assertThrows(IllegalArgumentException.class, () -> TransceiverInit.builder()
                    .sendEncodings(List.of(Encoding.defaults(), Encoding.rid("x"))).build());
            assertThrows(IllegalArgumentException.class, () -> TransceiverInit.builder()
                    .sendEncodings(List.of(Encoding.rid("x"), Encoding.rid("x"))).build());
            assertThrows(IllegalArgumentException.class, () -> TransceiverInit.of(TransceiverDirection.STOPPED));
        }

        @Test
        @DisplayName("replace the track without renegotiation and refuse another kind")
        void replaceTrack() {
            var a = peer();
            var first = LocalTrack.audio("first");
            var sender = a.pc().addTrack(first, List.of());
            a.drain();
            var second = LocalTrack.audio("second");
            sender.replaceTrack(second);
            assertSame(second, sender.track().orElseThrow());
            assertEquals(0, a.count(PeerConnectionEvent.NegotiationNeeded.class));
            assertThrows(IllegalArgumentException.class, () -> sender.replaceTrack(LocalTrack.video("v")));
            sender.clearTrack();
            assertTrue(sender.track().isEmpty());
            assertThrows(InvalidAccessException.class, () -> a.pc().addTrack(LocalTrack.audio("x"), List.of())
                    .connection().addTrack(a.pc().getSenders().get(1).track().orElseThrow(), List.of()));
        }

        @Test
        @DisplayName("stop sending on removeTrack and keep receiving")
        void removeTrack() {
            var a = peer();
            var sender = a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().removeTrack(sender);
            assertTrue(sender.track().isEmpty());
            assertEquals(TransceiverDirection.RECVONLY, a.pc().getTransceivers().getFirst().direction());
            assertThrows(InvalidAccessException.class, () -> a.pc().removeTrack(peer().pc()
                    .addTrack(LocalTrack.audio("other"), List.of())));
        }

        @Test
        @DisplayName("report the default capabilities by kind")
        void capabilities() {
            var audio = RtpSender.getCapabilities(MediaKind.AUDIO);
            assertTrue(audio.codecs().stream().allMatch(codec -> codec.mimeType().startsWith("audio/")));
            assertTrue(audio.codecs().stream().anyMatch(codec -> codec.mimeType().equals("audio/opus")));
            var video = RtpReceiver.getCapabilities(MediaKind.VIDEO);
            assertTrue(video.codecs().stream().anyMatch(codec -> codec.mimeType().equals("video/AV1")));
            assertTrue(video.headerExtensions().stream().anyMatch(extension -> extension.uri().toString()
                    .endsWith("rtp-stream-id")));
            assertFalse(audio.headerExtensions().stream().anyMatch(extension -> extension.uri().toString()
                    .endsWith("rtp-stream-id")));
        }

        @Test
        @DisplayName("expose the negotiated codecs and extensions in their parameters")
        void negotiatedParameters() {
            var a = peer();
            var b = peer();
            var sender = a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var parameters = sender.getParameters();
            assertEquals("audio/opus", parameters.codecs().getFirst().codec().mimeType());
            assertFalse(parameters.headerExtensions().isEmpty());
            assertTrue(parameters.rtcp().reducedSize());
            var receive = b.pc().getReceivers().getFirst().getParameters();
            assertEquals("audio/opus", receive.codecs().getFirst().codec().mimeType());
        }
    }

    @Nested
    @DisplayName("tracks")
    class Tracks {
        @Test
        @DisplayName("hand written frames to the attached senders through the transform")
        void localWrite() {
            var a = peer();
            var track = LocalTrack.video("cam");
            var sender = a.pc().addTrack(track, List.of());
            var seen = new ArrayList<EncodedFrame>();
            sender.setPipeline((frame, rid) -> seen.add(frame));
            track.write(frame(MediaKind.VIDEO));
            assertEquals(1, seen.size());
            sender.setTransform(frame -> frame.withData(ByteBuffer.wrap(new byte[]{9})));
            track.write(frame(MediaKind.VIDEO));
            assertEquals(1, seen.get(1).data().remaining());
            sender.setTransform(frame -> {
                throw new IllegalStateException("boom");
            });
            track.write(frame(MediaKind.VIDEO));
            assertEquals(2, seen.size(), "a throwing transform drops the frame");
            track.setEnabled(false);
            track.write(frame(MediaKind.VIDEO));
            assertEquals(1, track.framesDropped());
            assertThrows(IllegalArgumentException.class, () -> track.write(frame(MediaKind.AUDIO)));
            track.stop();
            assertThrows(IllegalStateException.class, () -> track.write(frame(MediaKind.VIDEO)));
        }

        @Test
        @DisplayName("raise keyframe requests and target bitrates as events")
        void localEvents() throws InterruptedException {
            var track = LocalTrack.video("cam");
            try (var events = track.events()) {
                track.requestKeyframe(Optional.of("h"));
                track.updateTargetBitrate(Optional.empty(), 500_000);
                track.updateTargetBitrate(Optional.empty(), 500_000);
                assertEquals(new LocalTrackEvent.KeyframeRequested(Optional.of("h")), events.next());
                assertEquals(new LocalTrackEvent.TargetBitrateChanged(Optional.empty(), 500_000), events.next());
                assertTrue(events.poll().isEmpty(), "an unchanged bitrate raises nothing");
                assertEquals(OptionalLong.of(500_000), track.targetBitrate());
                track.stop();
                assertEquals(new LocalTrackEvent.Ended(), events.next());
                assertTrue(events.next(Duration.ofMillis(10)).isEmpty());
            }
            assertThrows(IllegalArgumentException.class, () -> LocalTrack.audio("has space"));
        }

        @Test
        @DisplayName("deliver frames, playout outcomes or packets by mode and end cleanly")
        void remoteRead() throws InterruptedException {
            var track = new RemoteTrack("t", MediaKind.AUDIO, RemoteTrackMode.JITTER_BUFFERED);
            assertTrue(track.isMuted());
            track.deliver(new com.github.auties00.parley.jitter.AudioPlayout.Silence(Duration.ofMillis(20)));
            track.deliver(frame(MediaKind.AUDIO));
            assertFalse(track.isMuted());
            assertEquals(1000, track.read().rtpTimestamp(), "read skips the silence");
            assertTrue(track.read(Duration.ofMillis(5)).isEmpty());
            assertThrows(IllegalStateException.class, track::readPacket);
            track.end();
            assertThrows(IllegalStateException.class, track::read);
            var raw = new RemoteTrack("r", MediaKind.VIDEO, RemoteTrackMode.RAW_PACKETS);
            assertThrows(IllegalStateException.class, raw::read);
            assertTrue(raw.readPacket(Duration.ofMillis(5)).isEmpty());
        }

        @Test
        @DisplayName("drop the oldest item when the reader falls behind")
        void overflow() throws InterruptedException {
            var track = new RemoteTrack("t", MediaKind.VIDEO, RemoteTrackMode.JITTER_BUFFERED);
            for (var index = 0; index < 1030; index++) {
                track.deliver(EncodedFrame.of(MediaKind.VIDEO, ByteBuffer.allocate(1), index, false));
            }
            assertEquals(6, track.dropped());
            assertEquals(6, track.read().rtpTimestamp());
        }
    }

    @Nested
    @DisplayName("DTMF")
    class Dtmf {
        @Test
        @DisplayName("refuses tones until telephone-event is negotiated and invalid tones always")
        void validation() {
            var a = peer();
            var dtmf = a.pc().addTrack(LocalTrack.audio("mic"), List.of()).dtmf().orElseThrow();
            assertFalse(dtmf.canInsertDtmf());
            assertThrows(InvalidStateException.class, () -> dtmf.insertDtmf("1"));
            assertThrows(IllegalArgumentException.class, () -> dtmf.insertDtmf("1x"));
            assertTrue(a.pc().addTrack(LocalTrack.video("cam"), List.of()).dtmf().isEmpty());
        }

        @Test
        @DisplayName("plays queued tones with clamped durations and raises tone changes")
        void playout() throws InterruptedException {
            var a = peer();
            var b = peer();
            var sender = a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var dtmf = sender.dtmf().orElseThrow();
            var played = new CopyOnWriteArrayList<String>();
            var done = new CountDownLatch(1);
            dtmf.setSink((tone, duration) -> played.add(tone + ":" + duration.toMillis()));
            try (var events = dtmf.events()) {
                dtmf.insertDtmf("1a", Duration.ofMillis(10), Duration.ofMillis(1));
                var changes = new ArrayList<Optional<Character>>();
                while (true) {
                    var change = events.next(Duration.ofSeconds(5)).orElseThrow();
                    changes.add(change.tone());
                    if (change.tone().isEmpty()) {
                        done.countDown();
                        break;
                    }
                }
                assertTrue(done.await(1, TimeUnit.SECONDS));
                assertEquals(List.of(Optional.of('1'), Optional.of('A'), Optional.empty()), changes);
            }
            assertEquals(List.of("1:40", "A:40"), played, "durations are raised to 40 ms");
            assertEquals("", dtmf.toneBuffer());
        }
    }

    @Nested
    @DisplayName("events and states")
    class States {
        @Test
        @DisplayName("aggregate ICE and DTLS states into the connection state")
        void aggregate() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var transport = a.backend().last().transports().getFirst().id();
            var listener = a.backend().listener;
            assertEquals(PeerConnectionState.NEW, a.pc().connectionState());
            listener.onIceState(transport, IceTransportState.CHECKING);
            assertEquals(PeerConnectionState.CONNECTING, a.pc().connectionState());
            assertEquals(IceTransportState.CHECKING, a.pc().iceConnectionState());
            listener.onIceState(transport, IceTransportState.CONNECTED);
            listener.onDtlsState(transport, DtlsState.CONNECTING);
            assertEquals(PeerConnectionState.CONNECTING, a.pc().connectionState());
            listener.onDtlsState(transport, DtlsState.CONNECTED);
            assertEquals(PeerConnectionState.CONNECTED, a.pc().connectionState());
            listener.onIceState(transport, IceTransportState.DISCONNECTED);
            assertEquals(PeerConnectionState.DISCONNECTED, a.pc().connectionState());
            listener.onDtlsState(transport, DtlsState.FAILED);
            assertEquals(PeerConnectionState.FAILED, a.pc().connectionState());
            var changes = a.drain().stream().filter(PeerConnectionEvent.ConnectionStateChanged.class::isInstance)
                    .map(event -> ((PeerConnectionEvent.ConnectionStateChanged) event).state()).toList();
            assertEquals(List.of(PeerConnectionState.CONNECTING, PeerConnectionState.CONNECTED,
                    PeerConnectionState.DISCONNECTED, PeerConnectionState.FAILED), changes);
            listener.onIceState("unknown", IceTransportState.FAILED);
            listener.onGatheringState(transport, IceGatheringState.GATHERING);
            assertEquals(IceGatheringState.GATHERING, a.pc().iceGatheringState());
        }

        @Test
        @DisplayName("deliver events to listeners in order until they are closed")
        void listeners() throws Exception {
            var a = peer();
            var received = new CopyOnWriteArrayList<PeerConnectionEvent>();
            var latch = new CountDownLatch(2);
            var subscription = a.pc().addListener(event -> {
                received.add(event);
                latch.countDown();
            });
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().setLocalDescription(a.pc().createOffer());
            assertTrue(latch.await(5, TimeUnit.SECONDS));
            assertTrue(received.getFirst() instanceof PeerConnectionEvent.NegotiationNeeded);
            assertEquals(new PeerConnectionEvent.SignalingStateChanged(SignalingState.HAVE_LOCAL_OFFER),
                    received.get(1));
            subscription.close();
            subscription.close();
        }

        @Test
        @DisplayName("end an event stream's iteration when the connection closes")
        void iteration() throws InterruptedException {
            var a = peer();
            var collected = new CopyOnWriteArrayList<PeerConnectionEvent>();
            var thread = Thread.ofVirtual().start(() -> {
                try (var events = a.pc().events()) {
                    for (var event : events) {
                        collected.add(event);
                    }
                }
            });
            Thread.sleep(50);
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().close();
            thread.join(5000);
            assertFalse(thread.isAlive());
            assertEquals(new PeerConnectionEvent.SignalingStateChanged(SignalingState.CLOSED), collected.getLast());
        }
    }

    @Nested
    @DisplayName("configuration")
    class ConfigurationTests {
        @Test
        @DisplayName("lets the ICE servers and policy change and nothing fixed")
        void setConfiguration() {
            var a = peer();
            var configuration = a.pc().getConfiguration();
            a.pc().setConfiguration(configuration.toBuilder().iceTransportPolicy(IceTransportPolicy.RELAY)
                    .threadFactory(configuration.threadFactory()).clock(configuration.clock()).build());
            assertEquals(IceTransportPolicy.RELAY, a.pc().getConfiguration().iceTransportPolicy());
            assertThrows(InvalidModificationException.class, () -> a.pc().setConfiguration(a.pc()
                    .getConfiguration().toBuilder().bundlePolicy(BundlePolicy.MAX_BUNDLE).build()));
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().setLocalDescription(a.pc().createOffer());
            assertThrows(InvalidModificationException.class, () -> a.pc().setConfiguration(a.pc()
                    .getConfiguration().toBuilder().iceCandidatePoolSize(4).build()));
        }

        @Test
        @DisplayName("validates its ranges")
        void validation() {
            assertThrows(IllegalArgumentException.class, () -> Configuration.builder().iceCandidatePoolSize(256)
                    .build());
            assertThrows(IllegalArgumentException.class, () -> Configuration.builder().bitrates(10, 5, 20).build());
            assertThrows(IllegalArgumentException.class, () -> Configuration.builder().codecs(List.of()).build());
        }

        @Test
        @DisplayName("validates data channel options")
        void dataChannelOptions() {
            var a = peer();
            assertThrows(IllegalArgumentException.class, () -> a.pc().createDataChannel("x",
                    new com.github.auties00.parley.datachannel.DataChannelInit(true, OptionalInt.of(1),
                            Optional.of(Duration.ofSeconds(1)), "", false, OptionalInt.empty(),
                            com.github.auties00.parley.datachannel.DataChannelPriority.LOW)));
            assertThrows(IllegalArgumentException.class, () -> a.pc().createDataChannel("x",
                    new com.github.auties00.parley.datachannel.DataChannelInit(true, OptionalInt.empty(),
                            Optional.empty(), "", true, OptionalInt.empty(),
                            com.github.auties00.parley.datachannel.DataChannelPriority.LOW)));
        }
    }

    @Nested
    @DisplayName("statistics")
    class Statistics {
        static TransportStats transport(String id) {
            return new TransportStats(id, Instant.EPOCH, 0, 0, 0, 0, TransportStats.IceRole.CONTROLLING,
                    Optional.empty(), TransportStats.IceState.CONNECTED, TransportStats.DtlsState.CONNECTED,
                    Optional.empty(), 0, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty());
        }

        static OutboundRtpStreamStats outbound(String id, long ssrc, String transportId) {
            return new OutboundRtpStreamStats(id, Instant.EPOCH, ssrc, MediaKind.AUDIO, transportId, Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 1, 2, 3, 0, 0,
                    OptionalLong.empty(), OptionalLong.empty(), 0, OptionalLong.empty(), OptionalLong.empty(),
                    OptionalLong.empty(), OptionalInt.empty(), OptionalInt.empty(), OptionalDouble.empty(), 0, 0, 0,
                    true, Optional.empty(), Optional.empty(), java.util.Map.of());
        }

        @Test
        @DisplayName("report the peer-connection object and select one sender's objects")
        void selection() {
            var a = peer();
            var sender = a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var ssrc = sender.layers().getFirst().ssrc();
            a.backend().statistics.addAll(List.<RtcStats>of(transport("T0"), transport("T1"),
                    outbound("OT1", ssrc, "T0"), outbound("OT2", ssrc + 1, "T1")));
            var all = a.pc().getStats();
            assertEquals(5, all.size());
            assertEquals(1, all.all(PeerConnectionStats.class).size());
            var selected = sender.getStats();
            assertEquals(List.of("OT1", "T0"), selected.stream(RtcStats.class).map(RtcStats::id).toList());
            assertTrue(a.pc().getReceivers().getFirst().getStats().stream(InboundRtpStreamStats.class).findAny()
                    .isEmpty());
        }
    }
}
