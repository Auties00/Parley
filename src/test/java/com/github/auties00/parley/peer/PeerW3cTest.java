package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceProtocol;
import com.github.auties00.parley.ice.IceTransportState;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.github.auties00.parley.peer.Peers.negotiate;
import static com.github.auties00.parley.peer.Peers.peer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the W3C members the peer object model gained over the fake backend: waits, transport views, key frame
/// requests, encoding parameters, the exception hierarchy, candidates, DTMF lifecycle and close.
@DisplayName("peer W3C surface")
class PeerW3cTest {
    @Nested
    @DisplayName("waits")
    class Waits {
        @Test
        @DisplayName("awaitConnectionState returns true on the state, false on timeout and on failure")
        void connectionState() throws Exception {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"));
            negotiate(a, b);
            var transport = a.backend().last().transports().getFirst().id();
            assertFalse(a.pc().awaitConnectionState(PeerConnectionState.CONNECTED, Duration.ofMillis(20)));
            var listener = a.backend().listener;
            Thread.ofVirtual().start(() -> {
                sleep(50);
                listener.onIceState(transport, IceTransportState.CONNECTED);
                listener.onDtlsState(transport, DtlsState.CONNECTED);
            });
            assertTrue(a.pc().awaitConnectionState(PeerConnectionState.CONNECTED, Duration.ofSeconds(5)));
            listener.onDtlsState(transport, DtlsState.FAILED);
            assertFalse(a.pc().awaitConnectionState(PeerConnectionState.CONNECTED, Duration.ofSeconds(5)),
                    "a failed connection ends the wait at once");
            assertTrue(a.pc().awaitConnectionState(PeerConnectionState.FAILED, Duration.ZERO));
        }

        @Test
        @DisplayName("awaitIceGatheringComplete returns once every transport completed, false once closed")
        void gathering() throws Exception {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"));
            a.pc().setLocalDescription();
            var transport = a.backend().gathering.getFirst().getKey();
            Thread.ofVirtual().start(() -> {
                sleep(50);
                a.backend().listener.onGatheringState(transport, IceGatheringState.COMPLETE);
            });
            assertTrue(a.pc().awaitIceGatheringComplete(Duration.ofSeconds(5)));
            var b = peer();
            Thread.ofVirtual().start(() -> {
                sleep(50);
                b.pc().close();
            });
            assertFalse(b.pc().awaitIceGatheringComplete(Duration.ofSeconds(5)));
        }

        @Test
        @DisplayName("an interrupted wait throws")
        void interrupted() {
            var a = peer();
            Thread.currentThread().interrupt();
            assertThrows(InterruptedException.class,
                    () -> a.pc().awaitConnectionState(PeerConnectionState.CONNECTED, Duration.ofSeconds(1)));
        }
    }

    @Nested
    @DisplayName("events")
    class Events {
        @Test
        @DisplayName("the first stream gets the events raised before it, in order")
        void backlog() throws InterruptedException {
            var c = PeerConnection.create(Configuration.builder().build(), FakeBackend::new);
            c.addTrack(LocalTrack.audio("mic"), "s");
            c.setLocalDescription();
            try (var events = c.events()) {
                assertInstanceOf(PeerConnectionEvent.NegotiationNeeded.class, events.next());
                assertEquals(new PeerConnectionEvent.SignalingStateChanged(SignalingState.HAVE_LOCAL_OFFER),
                        events.next());
            }
            try (var late = c.events()) {
                assertTrue(late.next(Duration.ZERO).isEmpty(), "a later stream starts empty");
            }
            c.close();
        }

        @Test
        @DisplayName("candidate events carry the server URL and relay protocol, errors the local address")
        void candidateMembers() throws InterruptedException {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"));
            a.pc().setLocalDescription();
            var transport = a.backend().gathering.getFirst().getKey();
            a.drain();
            var url = URI.create("turn:turn.example.org");
            a.backend().listener.onLocalCandidate(transport, "1 1 udp 1 192.0.2.1 5000 typ relay raddr 0.0.0.0 rport 0",
                    Optional.of(url), Optional.of(IceProtocol.TCP));
            a.backend().listener.onCandidateError(transport, Optional.of("192.0.2.9"), OptionalInt.of(4000), url, 701,
                    "unreachable");
            var events = a.drain();
            var candidate = events.stream().filter(PeerConnectionEvent.IceCandidate.class::isInstance)
                    .map(PeerConnectionEvent.IceCandidate.class::cast).findFirst().orElseThrow();
            assertEquals(Optional.of(url), candidate.url());
            assertEquals(Optional.of(IceProtocol.TCP), candidate.relayProtocol());
            assertTrue(events.contains(new PeerConnectionEvent.IceCandidateError(Optional.of("192.0.2.9"),
                    OptionalInt.of(4000), url, 701, "unreachable")));
        }

        @Test
        @DisplayName("close publishes the closed state and ends the streams even when a transport throws")
        void closeAlwaysEnds() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"));
            a.drain();
            a.backend().failOnClose = true;
            a.pc().close();
            assertTrue(a.backend().closed);
            assertEquals(List.of(new PeerConnectionEvent.SignalingStateChanged(SignalingState.CLOSED)), a.drain());
            assertTrue(a.events().isEnded());
            assertEquals(PeerConnectionState.CLOSED, a.pc().connectionState());
            a.pc().close();
        }

        @Test
        @DisplayName("counts the data channels the backend reports opened and closed")
        void dataChannelCounters() {
            var a = peer();
            a.backend().listener.onDataChannelOpened();
            a.backend().listener.onDataChannelOpened();
            a.backend().listener.onDataChannelClosed();
            var stats = a.pc().getStats().all(com.github.auties00.parley.stats.PeerConnectionStats.class)
                    .getFirst();
            assertEquals(2, stats.dataChannelsOpened());
            assertEquals(1, stats.dataChannelsClosed());
        }
    }

    @Nested
    @DisplayName("senders and receivers")
    class SendersAndReceivers {
        @Test
        @DisplayName("setParameters validates scalability modes against the webrtc-svc table")
        void scalabilityModes() {
            var a = peer();
            var video = a.pc().addTransceiver(MediaKind.VIDEO).sender();
            var parameters = video.getParameters();
            video.setParameters(parameters.withEncodings(List.of(withMode(parameters.encodings().getFirst(),
                    "L3T3_KEY"))));
            var again = video.getParameters();
            assertThrows(OperationErrorException.class, () -> video.setParameters(again.withEncodings(List.of(
                    withMode(again.encodings().getFirst(), "L4T1")))));
            var audio = a.pc().addTransceiver(MediaKind.AUDIO).sender();
            var audioParameters = audio.getParameters();
            assertThrows(OperationErrorException.class, () -> audio.setParameters(audioParameters.withEncodings(
                    List.of(withMode(audioParameters.encodings().getFirst(), "L1T1")))));
            var vp8 = peer(builder -> builder.codecs(List.of(Codec.opus(), Codec.vp8())));
            var sender = vp8.pc().addTransceiver(MediaKind.VIDEO).sender();
            var vp8Parameters = sender.getParameters();
            assertThrows(OperationErrorException.class, () -> sender.setParameters(vp8Parameters.withEncodings(
                    List.of(withMode(vp8Parameters.encodings().getFirst(), "L2T2")))),
                    "VP8 carries temporal layers only");
            var temporal = sender.getParameters();
            sender.setParameters(temporal.withEncodings(List.of(withMode(temporal.encodings().getFirst(), "L1T3"))));
        }

        @Test
        @DisplayName("setParameters raises EncodingChanged for the encodings that changed")
        void encodingChanged() throws InterruptedException {
            var a = peer();
            var track = LocalTrack.video("cam");
            var sender = a.pc().addTransceiver(track, TransceiverInit.builder()
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("l"))).build()).sender();
            try (var events = track.events()) {
                assertEquals(new LocalTrackEvent.EncodingChanged(Optional.of("h"), Encoding.rid("h")),
                        events.next(), "attaching the track tells it the encodings");
                assertEquals(new LocalTrackEvent.EncodingChanged(Optional.of("l"), Encoding.rid("l")),
                        events.next());
                var parameters = sender.getParameters();
                var inactive = parameters.encodings().get(1).active(false);
                sender.setParameters(parameters.withEncodings(List.of(parameters.encodings().get(0), inactive)));
                assertEquals(new LocalTrackEvent.EncodingChanged(Optional.of("l"), inactive), events.next());
                assertTrue(events.next(Duration.ZERO).isEmpty(), "an unchanged encoding raises nothing");
            }
        }

        @Test
        @DisplayName("generateKeyFrame raises a request per layer, or for one layer")
        void generateKeyFrame() throws InterruptedException {
            var a = peer();
            var track = LocalTrack.video("cam");
            var sender = a.pc().addTransceiver(MediaKind.VIDEO, TransceiverInit.builder()
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("l"))).build()).sender();
            assertThrows(InvalidStateException.class, sender::generateKeyFrame);
            sender.replaceTrack(track);
            try (var events = track.events()) {
                sender.generateKeyFrame();
                sender.generateKeyFrame("l");
                assertThrows(IllegalArgumentException.class, () -> sender.generateKeyFrame("x"));
                var requests = events.stream().filter(LocalTrackEvent.KeyframeRequested.class::isInstance)
                        .limit(3).toList();
                assertEquals(List.of(new LocalTrackEvent.KeyframeRequested(Optional.of("h")),
                        new LocalTrackEvent.KeyframeRequested(Optional.of("l")),
                        new LocalTrackEvent.KeyframeRequested(Optional.of("l"))), requests);
            }
        }

        @Test
        @DisplayName("requestKeyFrame asks the backend, for every layer or one")
        void requestKeyFrame() {
            var a = peer();
            var receiver = a.pc().addTransceiver(MediaKind.VIDEO).receiver();
            receiver.requestKeyFrame();
            receiver.requestKeyFrame("h");
            assertEquals(List.of("", "h"), a.backend().keyFrameRequests);
        }

        @Test
        @DisplayName("transports are empty before negotiation and after close")
        void transports() {
            var a = peer();
            var transceiver = a.pc().addTransceiver(MediaKind.AUDIO);
            assertTrue(transceiver.sender().transport().isEmpty());
            assertTrue(transceiver.receiver().transport().isEmpty());
            assertTrue(a.pc().sctp().isEmpty());
            a.pc().close();
            assertTrue(a.pc().sctp().isEmpty());
        }

        @Test
        @DisplayName("addTrack takes stream ids as varargs and names a null one")
        void addTrackVarargs() {
            var a = peer();
            var sender = a.pc().addTrack(LocalTrack.audio("mic"), "s1", "s2");
            assertEquals(List.of("s1", "s2"), sender.streams());
            var npe = assertThrows(NullPointerException.class,
                    () -> a.pc().addTrack(LocalTrack.audio("x"), "s", null));
            assertEquals("streams cannot contain null", npe.getMessage());
            assertEquals(TransceiverDirection.SENDRECV, a.pc().addTransceiver(MediaKind.VIDEO).direction());
        }
    }

    @Nested
    @DisplayName("errors")
    class Errors {
        @Test
        @DisplayName("the W3C exceptions extend the JDK types callers catch")
        void hierarchy() {
            assertInstanceOf(IllegalStateException.class, new InvalidStateException("x"));
            assertInstanceOf(IllegalStateException.class, new OperationErrorException("x"));
            assertInstanceOf(IllegalArgumentException.class, new InvalidAccessException("x"));
            assertInstanceOf(IllegalArgumentException.class, new InvalidModificationException("x"));
            var a = peer();
            a.pc().close();
            assertThrows(IllegalStateException.class, () -> a.pc().createOffer());
        }

        @Test
        @DisplayName("an expired certificate is refused with InvalidAccessException")
        void expiredCertificate() throws InterruptedException {
            var certificate = DtlsCertificate.generateEcdsa(Duration.ofMillis(1));
            var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (!certificate.isExpired(Instant.now()) && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            var builder = Configuration.builder().certificates(List.of(certificate));
            assertThrows(InvalidAccessException.class, builder::build);
            Configuration.builder().certificates(List.of(DtlsCertificate.generateEcdsa())).build();
        }

        @Test
        @DisplayName("an end of candidates may name no section, a candidate may not")
        void endOfCandidates() {
            var end = IceCandidateInit.endOfCandidates();
            assertTrue(end.isEndOfCandidates());
            assertTrue(end.sdpMid().isEmpty() && end.sdpMLineIndex().isEmpty());
            assertThrows(IllegalArgumentException.class, () -> new IceCandidateInit("candidate:1 1 udp 1 1.2.3.4 5 "
                    + "typ host", Optional.empty(), OptionalInt.empty(), Optional.empty()));
        }
    }

    @Nested
    @DisplayName("DTMF")
    class Dtmf {
        @Test
        @DisplayName("plays on a thread of the configured factory and stops when the sender stops sending")
        void lifecycle() throws InterruptedException {
            var threads = ConcurrentHashMap.<Thread>newKeySet();
            var factory = Thread.ofVirtual().name("test-", 0).factory();
            var a = peer(builder -> builder.threadFactory(runnable -> {
                var thread = factory.newThread(runnable);
                threads.add(thread);
                return thread;
            }));
            var b = peer();
            var sender = a.pc().addTrack(LocalTrack.audio("mic"));
            negotiate(a, b);
            var dtmf = sender.dtmf().orElseThrow();
            var started = new CountDownLatch(1);
            var played = new CopyOnWriteArrayList<Character>();
            dtmf.setSink((tone, duration) -> {
                played.add(tone);
                started.countDown();
                Thread.sleep(duration);
            });
            var events = dtmf.events();
            dtmf.insertDtmf("123456789", Duration.ofMillis(200), Duration.ofMillis(50));
            assertTrue(started.await(5, TimeUnit.SECONDS));
            var player = threads.stream().filter(Thread::isAlive).findFirst();
            assertTrue(player.isPresent(), "the player comes from the configured factory");
            sender.stopSending();
            assertEquals("", dtmf.toneBuffer());
            player.get().join(2000);
            assertFalse(player.get().isAlive(), "the player stops with the sender");
            assertTrue(played.size() < 9);
            a.pc().close();
            assertFalse(events.stream().toList().isEmpty(), "the tone changes end when the connection closes");
            assertTrue(events.isEnded());
        }
    }

    /// {@return `encoding` with a scalability mode}
    private static Encoding withMode(Encoding encoding, String mode) {
        return encoding.scalabilityMode(mode);
    }

    /// Sleeps without a checked exception.
    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }
}
