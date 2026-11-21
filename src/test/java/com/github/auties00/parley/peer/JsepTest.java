package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.sdp.BrowserFixtures;
import com.github.auties00.parley.sdp.MediaDirection;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.sdp.SessionDescription;
import com.github.auties00.parley.sdp.SetupRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static com.github.auties00.parley.peer.Peers.negotiate;
import static com.github.auties00.parley.peer.Peers.parse;
import static com.github.auties00.parley.peer.Peers.peer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Exercises the JSEP engine through the public peer connection API over a fake backend: offers and answers, the
/// signaling state machine, BUNDLE policies, codec and direction negotiation, simulcast, ICE restarts, rollback and
/// the remote description checks.
@DisplayName("JSEP")
class JsepTest {
    static Codec codec(String mime, int clock, int channels, Map<String, String> fmtp) {
        return new Codec(mime, clock, channels > 0 ? OptionalInt.of(channels) : OptionalInt.empty(), fmtp);
    }

    @Nested
    @DisplayName("offers")
    class Offers {
        @Test
        @DisplayName("lays out audio, video and data with mids, BUNDLE, actpass and rtcp-mux")
        void layout() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of("s"));
            a.pc().addTrack(LocalTrack.video("cam"), List.of("s"));
            a.pc().createDataChannel("chat");
            var offer = parse(a.pc().createOffer());
            assertEquals(List.of("audio", "video", "application"),
                    offer.media().stream().map(section -> section.media()).toList());
            assertEquals(List.of("0", "1", "2"), offer.bundleGroups().getFirst().mids());
            for (var section : offer.media()) {
                assertEquals(SetupRole.ACTPASS, offer.attribute(section, SdpAttribute.Setup.class).orElseThrow().role());
                assertTrue(section.attribute(SdpAttribute.IceUfrag.class).isPresent());
                assertTrue(section.attribute(SdpAttribute.Fingerprint.class).isPresent());
            }
            var audio = offer.media().getFirst();
            assertTrue(audio.hasAttribute("rtcp-mux"));
            assertEquals("111", audio.formats().getFirst(), "opus gets the payload type browsers give it");
            assertEquals("s", audio.attribute(SdpAttribute.Msid.class).orElseThrow().streamId());
            assertEquals(2, audio.attributes(SdpAttribute.Ssrc.class).size());
            var video = offer.media().get(1);
            assertTrue(video.attributes(SdpAttribute.Fmtp.class).stream()
                    .anyMatch(fmtp -> fmtp.parameters().startsWith("apt=")), "RTX is offered");
            assertEquals(1, video.attributes(SdpAttribute.SsrcGroup.class).size());
            var data = offer.media().get(2);
            assertEquals("UDP/DTLS/SCTP", data.protocol());
            assertEquals(5000, data.attribute(SdpAttribute.SctpPort.class).orElseThrow().port());
        }

        @Test
        @DisplayName("keeps the session id and bumps the version only when the offer changes")
        void versions() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var first = parse(a.pc().createOffer()).origin().orElseThrow();
            var same = parse(a.pc().createOffer()).origin().orElseThrow();
            assertEquals(first, same);
            a.pc().addTrack(LocalTrack.video("cam"), List.of());
            var changed = parse(a.pc().createOffer()).origin().orElseThrow();
            assertEquals(first.sessionId(), changed.sessionId());
            assertEquals(first.sessionVersion() + 1, changed.sessionVersion());
        }

        @Test
        @DisplayName("offers bundle-only sections under max-bundle and balanced, none under max-compat")
        void bundlePolicies() {
            for (var policy : BundlePolicy.values()) {
                var a = peer(builder -> builder.bundlePolicy(policy));
                a.pc().addTransceiver(MediaKind.AUDIO, TransceiverInit.of(TransceiverDirection.SENDRECV));
                a.pc().addTransceiver(MediaKind.AUDIO, TransceiverInit.of(TransceiverDirection.SENDRECV));
                a.pc().addTransceiver(MediaKind.VIDEO, TransceiverInit.of(TransceiverDirection.SENDRECV));
                var sections = parse(a.pc().createOffer()).media();
                var bundleOnly = sections.stream().map(section -> section.hasAttribute("bundle-only")).toList();
                var expected = switch (policy) {
                    case MAX_BUNDLE -> List.of(false, true, true);
                    case BALANCED -> List.of(false, true, false);
                    case MAX_COMPAT -> List.of(false, false, false);
                };
                assertEquals(expected, bundleOnly, policy.name());
                sections.stream().filter(section -> section.hasAttribute("bundle-only"))
                        .forEach(section -> assertEquals(0, section.port()));
            }
        }

        @Test
        @DisplayName("offers three simulcast layers with rid lines and no ssrc lines")
        void simulcast() {
            var a = peer();
            a.pc().addTransceiver(LocalTrack.video("cam"), TransceiverInit.builder()
                    .direction(TransceiverDirection.SENDONLY)
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("m").withScaleResolutionDownBy(2),
                            Encoding.rid("l").withScaleResolutionDownBy(4)))
                    .build());
            var video = parse(a.pc().createOffer()).media().getFirst();
            assertEquals(List.of("h", "m", "l"), video.attributes(SdpAttribute.Rid.class).stream()
                    .map(SdpAttribute.Rid::id).toList());
            var simulcast = video.attribute(SdpAttribute.Simulcast.class).orElseThrow();
            assertEquals(3, simulcast.send().size());
            assertTrue(video.attributes(SdpAttribute.Ssrc.class).isEmpty());
            assertTrue(video.attributes(SdpAttribute.Extmap.class).stream()
                    .anyMatch(extmap -> extmap.uri().toString().endsWith("rtp-stream-id")));
        }

        @Test
        @DisplayName("follows the transceiver's codec preferences")
        void codecPreferences() {
            var a = peer();
            var transceiver = a.pc().addTransceiver(MediaKind.VIDEO, TransceiverInit.of(TransceiverDirection.SENDRECV));
            transceiver.setCodecPreferences(List.of(
                    codec("video/H264", 90000, 0, Map.of("level-asymmetry-allowed", "1", "packetization-mode", "1",
                            "profile-level-id", "42e01f")),
                    codec("video/VP8", 90000, 0, Map.of())));
            var video = parse(a.pc().createOffer()).media().getFirst();
            var names = video.attributes(SdpAttribute.Rtpmap.class).stream().map(SdpAttribute.Rtpmap::encodingName)
                    .toList();
            assertEquals(List.of("H264", "VP8"), names, "no RTX without it in the preferences");
            assertThrows(InvalidModificationException.class, () -> transceiver.setCodecPreferences(
                    List.of(codec("video/Theora", 90000, 0, Map.of()))));
        }

        @Test
        @DisplayName("is refused while a remote offer is pending")
        void wrongState() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            b.pc().setRemoteDescription(a.pc().createOffer());
            assertThrows(InvalidStateException.class, () -> b.pc().createOffer());
        }
    }

    @Nested
    @DisplayName("offer/answer")
    class Exchange {
        @Test
        @DisplayName("reaches stable on both sides with complementary roles on one bundled transport")
        void basic() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of("s"));
            a.pc().addTrack(LocalTrack.video("cam"), List.of("s"));
            negotiate(a, b);
            assertEquals(SignalingState.STABLE, a.pc().signalingState());
            assertEquals(SignalingState.STABLE, b.pc().signalingState());
            var offerer = a.backend().last();
            var answerer = b.backend().last();
            assertEquals(1, offerer.transports().size());
            assertEquals(1, answerer.transports().size());
            assertEquals(IceRole.CONTROLLING, offerer.transports().getFirst().iceRole());
            assertEquals(IceRole.CONTROLLED, answerer.transports().getFirst().iceRole());
            assertEquals(DtlsRole.SERVER, offerer.transports().getFirst().dtlsRole());
            assertEquals(DtlsRole.CLIENT, answerer.transports().getFirst().dtlsRole());
            assertEquals(offerer.transports().getFirst().local(), answerer.transports().getFirst().remote());
            assertEquals(List.of(FakeBackend.FINGERPRINT), offerer.transports().getFirst().remoteFingerprints());
            assertEquals(2, offerer.media().size());
            for (var transceiver : a.pc().getTransceivers()) {
                assertEquals(Optional.of(TransceiverDirection.SENDONLY), transceiver.currentDirection());
            }
            for (var transceiver : b.pc().getTransceivers()) {
                assertEquals(Optional.of(TransceiverDirection.RECVONLY), transceiver.currentDirection());
            }
        }

        @Test
        @DisplayName("raises a track event on the side that starts receiving, with the stream ids")
        void trackEvents() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of("stream-1"));
            b.drain();
            negotiate(a, b);
            var tracks = b.drain().stream().filter(PeerConnectionEvent.Track.class::isInstance)
                    .map(PeerConnectionEvent.Track.class::cast).toList();
            assertEquals(1, tracks.size());
            assertEquals(List.of("stream-1"), tracks.getFirst().streams());
            assertEquals(MediaKind.AUDIO, tracks.getFirst().receiver().track().kind());
            assertEquals(0, a.count(PeerConnectionEvent.Track.class));
        }

        @Test
        @DisplayName("negotiates the codecs both sides support with the offerer's payload types")
        void codecs() {
            var a = peer();
            var b = peer(builder -> builder.codecs(List.of(codec("audio/opus", 48000, 2, Map.of()),
                    codec("video/VP9", 90000, 0, Map.of("profile-id", "0")), codec("video/rtx", 90000, 0, Map.of()))));
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().addTrack(LocalTrack.video("cam"), List.of());
            negotiate(a, b);
            var video = a.backend().last().media().get(1);
            assertEquals(List.of("video/VP9"), video.codecs().stream().map(entry -> entry.codec().mimeType()).toList());
            assertTrue(video.codecs().getFirst().rtxPayloadType().isPresent());
            var offeredVp9 = parse(a.pc().currentLocalDescription().orElseThrow()).media().get(1)
                    .attributes(SdpAttribute.Rtpmap.class).stream()
                    .filter(rtpmap -> rtpmap.encodingName().equals("VP9")).findFirst().orElseThrow();
            assertEquals(offeredVp9.payloadType(), video.codecs().getFirst().payloadType());
            assertTrue(video.extensions().containsValue(java.net.URI.create("urn:ietf:params:rtp-hdrext:sdes:mid")));
        }

        @Test
        @DisplayName("rejects a section without a common codec")
        void noCommonCodec() {
            var a = peer();
            var b = peer(builder -> builder.codecs(List.of(codec("audio/opus", 48000, 2, Map.of()))));
            a.pc().addTrack(LocalTrack.video("cam"), List.of());
            b.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var answer = parse(b.pc().currentLocalDescription().orElseThrow());
            assertEquals(0, answer.media().getFirst().port());
            assertTrue(a.pc().getTransceivers().isEmpty(), "the rejected transceiver is gone");
        }

        @ParameterizedTest
        @EnumSource(value = TransceiverDirection.class, names = {"SENDRECV", "SENDONLY", "RECVONLY", "INACTIVE"})
        @DisplayName("answers each offered direction with its intersection")
        void directions(TransceiverDirection offered) {
            var a = peer();
            var b = peer();
            a.pc().addTransceiver(MediaKind.AUDIO, TransceiverInit.of(offered));
            var offer = a.pc().createOffer();
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            b.pc().getTransceivers().getFirst().setDirection(TransceiverDirection.SENDRECV);
            var answer = b.pc().createAnswer();
            b.pc().setLocalDescription(answer);
            a.pc().setRemoteDescription(answer);
            var answered = parse(answer).media().getFirst().direction().orElseThrow();
            assertEquals(MediaDirection.of(offered.receives(), offered.sends()), answered);
            assertEquals(Optional.of(offered), a.pc().getTransceivers().getFirst().currentDirection());
        }

        @Test
        @DisplayName("negotiates simulcast: three receive layers by rid on the answerer")
        void simulcast() {
            var a = peer();
            var b = peer();
            a.pc().addTransceiver(LocalTrack.video("cam"), TransceiverInit.builder()
                    .direction(TransceiverDirection.SENDONLY)
                    .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("m"), Encoding.rid("l")))
                    .build());
            negotiate(a, b);
            var answer = parse(b.pc().currentLocalDescription().orElseThrow()).media().getFirst();
            assertEquals(3, answer.attribute(SdpAttribute.Simulcast.class).orElseThrow().receive().size());
            var received = b.backend().last().media().getFirst().receiveLayers();
            assertEquals(List.of("h", "m", "l"), received.stream().map(layer -> layer.rid().orElseThrow()).toList());
            var sent = a.backend().last().media().getFirst().sendLayers();
            assertEquals(3, sent.size());
        }

        @Test
        @DisplayName("answers a Chrome simulcast offer with recv rids")
        void chromeSimulcast() {
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(BrowserFixtures.CHROME_SIMULCAST_OFFER));
            var answer = parse(b.pc().createAnswer()).media().getFirst();
            assertEquals(List.of(SdpAttribute.Rid.Direction.RECV, SdpAttribute.Rid.Direction.RECV,
                    SdpAttribute.Rid.Direction.RECV), answer.attributes(SdpAttribute.Rid.class).stream()
                    .map(SdpAttribute.Rid::direction).toList());
            assertEquals(MediaDirection.RECVONLY, answer.direction().orElseThrow());
        }

        @Test
        @DisplayName("negotiates a data section with the peer's SCTP port and message size")
        void data() {
            var a = peer();
            var b = peer();
            a.pc().createDataChannel("chat");
            assertEquals(List.of("chat"), a.backend().channels);
            negotiate(a, b);
            var data = a.backend().last().data().orElseThrow();
            assertEquals(5000, data.remotePort());
            assertEquals(262144, data.remoteMaxMessageSize());
        }

        @Test
        @DisplayName("treats the peer's ICE-lite flag as a reason to control")
        void liteOfferer() {
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(BrowserFixtures.LITE_SFU_OFFER));
            b.pc().setLocalDescription(b.pc().createAnswer());
            var transport = b.backend().last().transports().getFirst();
            assertTrue(transport.remoteLite());
            assertEquals(IceRole.CONTROLLING, transport.iceRole());
            assertEquals(List.of("1775469887 1 udp 2122260223 203.0.113.35 3480 typ host generation 0"),
                    transport.remoteCandidates());
            assertTrue(transport.remoteComplete());
        }

        @Test
        @DisplayName("writes a=ice-lite and controls nothing as an ICE-lite answerer")
        void liteAnswerer() {
            var a = peer();
            var b = peer(builder -> builder.iceLite(true));
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            assertTrue(parse(b.pc().currentLocalDescription().orElseThrow())
                    .attribute(SdpAttribute.IceLite.class).isPresent());
            assertEquals(IceRole.CONTROLLED, b.backend().last().transports().getFirst().iceRole());
            assertTrue(a.backend().last().transports().getFirst().remoteLite());
            assertEquals(IceRole.CONTROLLING, a.backend().last().transports().getFirst().iceRole());
        }
    }

    @Nested
    @DisplayName("browser offers")
    class Browsers {
        @Test
        @DisplayName("answers a Chrome offer section by section, keeping its payload types and BUNDLE group")
        void chrome() {
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(BrowserFixtures.CHROME_OFFER));
            assertEquals(2, b.pc().getTransceivers().size());
            var answer = parse(b.pc().createAnswer());
            b.pc().setLocalDescription(JsepDescription.answer(answer.encode()));
            assertEquals(List.of("0", "1", "2"), answer.bundleGroups().getFirst().mids());
            var audio = answer.media().getFirst();
            assertEquals("111", audio.formats().getFirst());
            assertEquals(MediaDirection.RECVONLY, audio.direction().orElseThrow());
            assertEquals(SetupRole.ACTIVE, answer.attribute(audio, SdpAttribute.Setup.class).orElseThrow().role());
            var video = b.backend().last().media().get(1);
            assertEquals("video/VP8", video.codecs().getFirst().codec().mimeType());
            assertEquals(OptionalInt.of(97), video.codecs().getFirst().rtxPayloadType());
            var layer = video.receiveLayers().getFirst();
            assertEquals(2231627014L, layer.ssrc().orElseThrow());
            assertEquals(632943048L, layer.rtxSsrc().orElseThrow());
            assertTrue(b.backend().last().data().isPresent());
        }

        @Test
        @DisplayName("answers a Firefox offer whose fingerprint is at the session level")
        void firefox() {
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(BrowserFixtures.FIREFOX_OFFER));
            b.pc().setLocalDescription(b.pc().createAnswer());
            var transport = b.backend().last().transports().getFirst();
            assertEquals(BrowserFixtures.FINGERPRINT, transport.remoteFingerprints().getFirst().fingerprint());
            var audio = b.backend().last().media().getFirst();
            assertEquals(109, audio.codecs().getFirst().payloadType());
            assertTrue(audio.telephoneEvent().isPresent());
        }

        @Test
        @DisplayName("answers a Safari offer with H.264 first and keeps the constrained-high profile apart")
        void safari() {
            var b = peer();
            b.pc().addTrack(LocalTrack.video("cam"), List.of());
            b.pc().setRemoteDescription(JsepDescription.offer(BrowserFixtures.SAFARI_OFFER));
            var answer = parse(b.pc().createAnswer());
            var video = answer.media().get(1);
            assertFalse(video.formats().contains("96"), "640c1f is constrained high, which Parley does not offer");
            assertTrue(video.formats().contains("98"));
            assertTrue(video.formats().contains("127"), "RED is accepted");
            assertEquals(MediaDirection.SENDONLY, video.direction().orElseThrow());
        }
    }

    @Nested
    @DisplayName("state machine")
    class StateMachine {
        @Test
        @DisplayName("rolls a local offer back to stable and unbinds the transceivers")
        void rollbackLocal() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().setLocalDescription(a.pc().createOffer());
            assertEquals(SignalingState.HAVE_LOCAL_OFFER, a.pc().signalingState());
            assertEquals(Optional.of("0"), a.pc().getTransceivers().getFirst().mid());
            a.pc().setLocalDescription(JsepDescription.rollback());
            assertEquals(SignalingState.STABLE, a.pc().signalingState());
            assertEquals(Optional.empty(), a.pc().getTransceivers().getFirst().mid());
            assertTrue(a.pc().localDescription().isEmpty());
        }

        @Test
        @DisplayName("rolls a remote offer back and drops the transceivers it created")
        void rollbackRemote() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            b.pc().setRemoteDescription(a.pc().createOffer());
            assertEquals(1, b.pc().getTransceivers().size());
            b.pc().setRemoteDescription(JsepDescription.rollback());
            assertEquals(SignalingState.STABLE, b.pc().signalingState());
            assertTrue(b.pc().getTransceivers().isEmpty());
        }

        @Test
        @DisplayName("resolves glare: a remote offer applied over a local offer rolls the local one back")
        void perfectNegotiation() {
            var polite = peer();
            var impolite = peer();
            polite.pc().addTrack(LocalTrack.audio("polite-mic"), List.of());
            impolite.pc().addTrack(LocalTrack.audio("impolite-mic"), List.of());
            polite.pc().setLocalDescription();
            var impoliteOffer = impolite.pc().setLocalDescription();
            polite.pc().setRemoteDescription(impoliteOffer);
            assertEquals(SignalingState.HAVE_REMOTE_OFFER, polite.pc().signalingState());
            var answer = polite.pc().setLocalDescription();
            assertEquals(JsepType.ANSWER, answer.type());
            impolite.pc().setRemoteDescription(answer);
            assertEquals(SignalingState.STABLE, impolite.pc().signalingState());
            assertEquals(1, polite.pc().getTransceivers().size(), "addTrack's transceiver took the offered section");
            assertEquals(Optional.of(TransceiverDirection.SENDRECV),
                    polite.pc().getTransceivers().getFirst().currentDirection());
        }

        @Test
        @DisplayName("passes through provisional answers on both sides")
        void pranswer() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer();
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            var provisional = JsepDescription.pranswer(b.pc().createAnswer().sdp());
            b.pc().setLocalDescription(provisional);
            assertEquals(SignalingState.HAVE_LOCAL_PRANSWER, b.pc().signalingState());
            a.pc().setRemoteDescription(provisional);
            assertEquals(SignalingState.HAVE_REMOTE_PRANSWER, a.pc().signalingState());
            var answer = b.pc().createAnswer();
            b.pc().setLocalDescription(answer);
            a.pc().setRemoteDescription(answer);
            assertEquals(SignalingState.STABLE, a.pc().signalingState());
            assertEquals(SignalingState.STABLE, b.pc().signalingState());
        }

        @Test
        @DisplayName("refuses descriptions that do not fit the state")
        void invalidTransitions() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer();
            assertThrows(InvalidStateException.class, () -> a.pc().setRemoteDescription(JsepDescription.answer(
                    offer.sdp())));
            assertThrows(InvalidStateException.class, () -> a.pc().createAnswer());
            assertThrows(InvalidStateException.class, () -> a.pc().setLocalDescription(JsepDescription.rollback()));
            assertThrows(InvalidStateException.class,
                    () -> a.pc().setLocalDescription(JsepDescription.answer(offer.sdp())));
        }

        @Test
        @DisplayName("rejects the offer section of a stopped transceiver and recycles it for a new one")
        void stopAndRecycle() {
            var a = peer();
            var b = peer();
            var audio = a.pc().addTransceiver(MediaKind.AUDIO, TransceiverInit.of(TransceiverDirection.SENDRECV));
            negotiate(a, b);
            audio.stop();
            assertEquals(TransceiverDirection.STOPPED, audio.direction());
            negotiate(a, b);
            assertTrue(a.pc().getTransceivers().isEmpty());
            assertEquals(List.of("0"), a.backend().last().closedMids());
            a.pc().addTransceiver(MediaKind.VIDEO, TransceiverInit.of(TransceiverDirection.SENDRECV));
            var offer = parse(a.pc().createOffer());
            assertEquals(1, offer.media().size(), "the rejected section is recycled");
            assertEquals("video", offer.media().getFirst().media());
            assertNotEquals("0", offer.media().getFirst().mid().orElseThrow(), "a recycled section gets a new mid");
        }

        @Test
        @DisplayName("closes for good: states, events and further calls")
        void close() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.drain();
            a.pc().close();
            assertEquals(SignalingState.CLOSED, a.pc().signalingState());
            assertEquals(PeerConnectionState.CLOSED, a.pc().connectionState());
            assertTrue(a.backend().closed);
            assertTrue(a.drain().getLast() instanceof PeerConnectionEvent.SignalingStateChanged(var state)
                    && state == SignalingState.CLOSED);
            assertTrue(a.events().isEnded());
            assertThrows(InvalidStateException.class, () -> a.pc().createOffer());
            a.pc().close();
        }
    }

    @Nested
    @DisplayName("negotiationneeded")
    class NegotiationNeeded {
        @Test
        @DisplayName("fires once for a burst of changes and not after the exchange")
        void once() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().addTrack(LocalTrack.video("cam"), List.of());
            assertEquals(1, a.count(PeerConnectionEvent.NegotiationNeeded.class));
            negotiate(a, b);
            assertEquals(0, a.count(PeerConnectionEvent.NegotiationNeeded.class));
        }

        @Test
        @DisplayName("fires for a direction change, a stream change, a stop, a data channel and an ICE restart")
        void triggers() {
            var a = peer();
            var b = peer();
            var transceiver = a.pc().addTransceiver(LocalTrack.audio("mic"), TransceiverInit.of(TransceiverDirection.SENDRECV));
            negotiate(a, b);
            a.drain();
            transceiver.setDirection(TransceiverDirection.RECVONLY);
            assertEquals(1, a.count(PeerConnectionEvent.NegotiationNeeded.class));
            negotiate(a, b);
            transceiver.setDirection(TransceiverDirection.SENDRECV);
            negotiate(a, b);
            a.drain();
            transceiver.sender().setStreams(List.of("other"));
            assertEquals(1, a.count(PeerConnectionEvent.NegotiationNeeded.class));
            negotiate(a, b);
            a.pc().createDataChannel("x");
            assertEquals(1, a.count(PeerConnectionEvent.NegotiationNeeded.class));
            negotiate(a, b);
            a.pc().restartIce();
            assertEquals(1, a.count(PeerConnectionEvent.NegotiationNeeded.class));
        }

        @Test
        @DisplayName("waits for stable before firing")
        void notWhileNegotiating() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().setLocalDescription(a.pc().createOffer());
            a.drain();
            a.pc().addTrack(LocalTrack.video("cam"), List.of());
            assertEquals(0, a.count(PeerConnectionEvent.NegotiationNeeded.class));
        }
    }

    @Nested
    @DisplayName("ICE")
    class Ice {
        @Test
        @DisplayName("restarts with fresh credentials on both sides and flags the transport")
        void restart() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var before = a.backend().last().transports().getFirst();
            a.pc().restartIce();
            negotiate(a, b);
            var after = a.backend().last().transports().getFirst();
            assertNotEquals(before.local(), after.local());
            assertNotEquals(before.remote(), after.remote());
            assertFalse(after.dtlsRestart(), "an ICE restart keeps the DTLS association");
            assertEquals(before.localTlsId(), after.localTlsId());
            assertEquals(2, a.backend().gathering.size(), "gathering restarts with the new credentials");
        }

        @Test
        @DisplayName("restarts on an offer option too")
        void restartOption() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var old = parse(a.pc().currentLocalDescription().orElseThrow()).media().getFirst()
                    .attribute(SdpAttribute.IceUfrag.class).orElseThrow();
            var offer = parse(a.pc().createOffer(new OfferOptions(true))).media().getFirst()
                    .attribute(SdpAttribute.IceUfrag.class).orElseThrow();
            assertNotEquals(old, offer);
        }

        @Test
        @DisplayName("surfaces gathered candidates as events and in the local description")
        void localCandidates() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().setLocalDescription(a.pc().createOffer());
            var transport = a.backend().gathering.getFirst().getKey();
            a.drain();
            a.backend().listener.onLocalCandidate(transport, "1 1 udp 2122260223 192.0.2.1 5000 typ host",
                    Optional.empty(), Optional.empty());
            a.backend().listener.onGatheringState(transport, com.github.auties00.parley.ice.IceGatheringState.COMPLETE);
            var events = a.drain();
            var candidate = events.stream().filter(PeerConnectionEvent.IceCandidate.class::isInstance)
                    .map(PeerConnectionEvent.IceCandidate.class::cast).findFirst().orElseThrow().candidate();
            assertEquals(Optional.of("0"), candidate.sdpMid());
            assertEquals(OptionalInt.of(0), candidate.sdpMLineIndex());
            assertTrue(candidate.candidate().startsWith("candidate:"));
            assertTrue(events.stream().anyMatch(PeerConnectionEvent.EndOfCandidates.class::isInstance));
            var local = a.pc().localDescription().orElseThrow().sdp();
            assertTrue(local.contains("a=candidate:1 1 udp 2122260223 192.0.2.1 5000 typ host"));
            assertTrue(local.contains("a=end-of-candidates"));
        }

        @Test
        @DisplayName("routes trickled remote candidates to the transport once it runs")
        void remoteCandidates() {
            var a = peer();
            var b = peer();
            assertThrows(InvalidStateException.class, () -> b.pc().addIceCandidate(IceCandidateInit.of("", "0")));
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer();
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            b.pc().addIceCandidate(IceCandidateInit.of("candidate:1 1 udp 1 192.0.2.7 4000 typ host", "0"));
            assertTrue(b.backend().remoteCandidates.isEmpty(), "no transport before the answer");
            assertTrue(b.pc().remoteDescription().orElseThrow().sdp().contains("a=candidate:1 1 udp 1 192.0.2.7"));
            b.pc().setLocalDescription(b.pc().createAnswer());
            assertTrue(b.backend().last().transports().getFirst().remoteCandidates()
                    .contains("1 1 udp 1 192.0.2.7 4000 typ host"));
            b.pc().addIceCandidate(IceCandidateInit.of("candidate:2 1 udp 1 192.0.2.8 4000 typ host", "0"));
            assertEquals(1, b.backend().remoteCandidates.size());
            b.pc().addIceCandidate(IceCandidateInit.of("", "0"));
            assertEquals(1, b.backend().endedCandidates.size());
            b.pc().addIceCandidate(IceCandidateInit.endOfCandidates());
            assertEquals(2, b.backend().endedCandidates.size(), "the end of candidates for every section");
            assertThrows(OperationErrorException.class,
                    () -> b.pc().addIceCandidate(IceCandidateInit.of("candidate:3 1 udp 1 192.0.2.9 1 typ host", "9")));
            assertThrows(OperationErrorException.class, () -> b.pc().addIceCandidate(new IceCandidateInit(
                    "candidate:3 1 udp 1 192.0.2.9 1 typ host", Optional.of("0"), OptionalInt.empty(),
                    Optional.of("zzzz"))));
        }
    }

    @Nested
    @DisplayName("SDP munging")
    class Munging {
        @Test
        @DisplayName("allows removing and reordering codecs, editing fmtp and adding bandwidth")
        void allowed() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = parse(a.pc().createOffer());
            var audio = offer.media().getFirst();
            var lines = new java.util.ArrayList<com.github.auties00.parley.sdp.SdpLine>();
            lines.add(new com.github.auties00.parley.sdp.SdpLine('b', "AS:64"));
            for (var line : audio.lines()) {
                if (line.isAttribute("fmtp") && line.attributeValue().orElse("").startsWith("111 ")) {
                    lines.add(com.github.auties00.parley.sdp.SdpLine.attribute("fmtp", "111 minptime=10;stereo=1"));
                } else if (!(line.type() == 'a' && line.attributeValue().orElse("").startsWith("0 "))) {
                    lines.add(line);
                }
            }
            var munged = offer.withMedia(List.of(audio.withFormats(audio.formats().stream()
                    .filter(format -> !format.equals("0")).toList()).withLines(lines)));
            a.pc().setLocalDescription(JsepDescription.offer(munged.encode()));
            b.pc().setRemoteDescription(a.pc().localDescription().orElseThrow());
            var answer = b.pc().createAnswer();
            b.pc().setLocalDescription(answer);
            a.pc().setRemoteDescription(answer);
            assertFalse(parse(answer).media().getFirst().formats().contains("0"));
            assertEquals(64_000 - JsepEngine.AUDIO_PACKETS_PER_SECOND * JsepEngine.PACKET_OVERHEAD_BYTES * 8,
                    b.backend().last().media().getFirst().maxBitrate().orElseThrow(),
                    "b=AS includes the packet overhead, which the payload cap excludes");
        }

        @Test
        @DisplayName("refuses a changed ICE credential, a remapped payload type or an added attribute")
        void forbidden() throws Exception {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer().sdp();
            var ufrag = SessionDescription.parse(offer).media().getFirst().attribute(SdpAttribute.IceUfrag.class)
                    .orElseThrow().ufrag();
            assertThrows(InvalidModificationException.class, () -> a.pc().setLocalDescription(
                    JsepDescription.offer(offer.replace("a=ice-ufrag:" + ufrag, "a=ice-ufrag:abcd"))));
            assertThrows(InvalidModificationException.class, () -> a.pc().setLocalDescription(
                    JsepDescription.offer(offer.replace("a=rtpmap:111 opus/48000/2", "a=rtpmap:111 G722/8000"))));
            assertThrows(InvalidModificationException.class, () -> a.pc().setLocalDescription(
                    JsepDescription.offer(offer.replace("a=rtcp-mux\r\n", "a=rtcp-mux\r\na=x-custom:1\r\n"))));
            assertThrows(OperationErrorException.class, () -> a.pc().setLocalDescription(
                    JsepDescription.offer("garbage")));
        }

        @Test
        @DisplayName("applies the last created description when the SDP is empty")
        void emptySdp() {
            var a = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer();
            a.pc().setLocalDescription(JsepDescription.offer(""));
            assertEquals(offer.sdp(), a.pc().localDescription().orElseThrow().sdp());
        }
    }

    @Nested
    @DisplayName("remote description checks")
    class Validation {
        static String remove(String sdp, String prefix) {
            return String.join("\r\n", sdp.lines().filter(line -> !line.startsWith(prefix)).toList()) + "\r\n";
        }

        @Test
        @DisplayName("refuses an offer without a fingerprint, ICE credentials, rtcp-mux or mids")
        void missingAttributes() {
            for (var prefix : List.of("a=fingerprint", "a=ice-ufrag", "a=ice-pwd", "a=rtcp-mux", "a=mid")) {
                var b = peer();
                var sdp = remove(BrowserFixtures.CHROME_OFFER, prefix);
                assertThrows(OperationErrorException.class,
                        () -> b.pc().setRemoteDescription(JsepDescription.offer(sdp)), prefix);
                assertEquals(SignalingState.STABLE, b.pc().signalingState());
            }
        }

        @Test
        @DisplayName("refuses a BUNDLE group naming an unknown section and a malformed fingerprint")
        void malformed() {
            var b = peer();
            assertThrows(OperationErrorException.class, () -> b.pc().setRemoteDescription(JsepDescription.offer(
                    BrowserFixtures.CHROME_OFFER.replace("a=group:BUNDLE 0 1 2", "a=group:BUNDLE 0 1 2 9"))));
            assertThrows(OperationErrorException.class, () -> b.pc().setRemoteDescription(JsepDescription.offer(
                    BrowserFixtures.CHROME_OFFER.replace(BrowserFixtures.FINGERPRINT, "XYZ"))));
            assertThrows(OperationErrorException.class, () -> b.pc().setRemoteDescription(JsepDescription.offer(
                    BrowserFixtures.CHROME_OFFER.replace("a=ice-pwd:x9cml/YzichV2+XlhiMu8g8P", "a=ice-pwd:short"))));
        }

        @Test
        @DisplayName("refuses an answer that does not match the offer")
        void mismatchedAnswer() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer();
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            var answer = b.pc().createAnswer().sdp();
            assertThrows(InvalidAccessException.class, () -> a.pc().setRemoteDescription(JsepDescription.answer(
                    answer.replace("a=mid:0", "a=mid:9").replace("a=group:BUNDLE 0", "a=group:BUNDLE 9"))));
            assertThrows(OperationErrorException.class, () -> a.pc().setRemoteDescription(JsepDescription.answer(
                    answer.replace("a=setup:active", "a=setup:actpass"))));
            a.pc().setRemoteDescription(JsepDescription.answer(answer));
            assertEquals(SignalingState.STABLE, a.pc().signalingState());
        }
    }
}
