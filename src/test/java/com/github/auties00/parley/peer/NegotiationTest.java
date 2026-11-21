package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.sdp.BrowserFixtures;
import com.github.auties00.parley.sdp.MediaDescription;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.sdp.SdpLine;
import com.github.auties00.parley.sdp.SessionDescription;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.function.UnaryOperator;

import static com.github.auties00.parley.peer.Peers.negotiate;
import static com.github.auties00.parley.peer.Peers.parse;
import static com.github.auties00.parley.peer.Peers.peer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the negotiation fixes of the JSEP engine: the shared BUNDLE tag, the remote description checks, `a=tls-id`
/// and DTLS restarts, `a=cryptex`, RFC 8888 feedback, per-transceiver header extensions and bitrate caps.
@DisplayName("JSEP negotiation")
class NegotiationTest {
    /// {@return `sdp` with every line for which `edit` returns `null` removed and the others replaced}
    static String edit(String sdp, UnaryOperator<String> edit) {
        var result = new ArrayList<String>();
        for (var line : sdp.split("\r\n")) {
            var edited = edit.apply(line);
            if (edited != null) {
                result.add(edited);
            }
        }
        return String.join("\r\n", result) + "\r\n";
    }

    /// {@return the attributes named `name` of the first section of a description}
    static List<String> attributes(JsepDescription description, int section, String name) {
        return parse(description).media().get(section).attributes(name);
    }

    @Nested
    @DisplayName("the BUNDLE tag")
    class BundleTag {
        @Test
        @DisplayName("rejects the fuzzed offer whose first bundled section is unusable and whose tag lacks ICE credentials")
        void fuzzedOffer() throws IOException {
            String sdp;
            try (var input = Objects.requireNonNull(NegotiationTest.class.getResourceAsStream(
                    "sdp-remote-offer-NoSuchElementException.sdp"))) {
                sdp = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            }
            var b = peer();
            var offer = JsepDescription.offer(sdp);
            assertThrows(OperationErrorException.class, () -> b.pc().setRemoteDescription(offer));
            assertEquals(SignalingState.STABLE, b.pc().signalingState());
        }

        @Test
        @DisplayName("moves to the first section this side accepts when the first bundled one is unusable")
        void firstAccepted() {
            var sdp = BrowserFixtures.CHROME_OFFER.replaceFirst("m=audio 9 UDP/TLS/RTP/SAVPF",
                    "m=audio 9 RTP/SAVPF");
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(sdp));
            var answer = b.pc().createAnswer();
            var parsed = parse(answer);
            assertEquals(0, parsed.media().get(0).port(), "the unsupported profile is rejected");
            assertEquals(List.of("1", "2"), parsed.bundleGroups().getFirst().mids());
            b.pc().setLocalDescription(answer);
            var transport = b.backend().last().transports().getFirst();
            assertEquals("1", transport.id());
            assertEquals(List.of("1", "2"), transport.mids());
        }

        @Test
        @DisplayName("checks the ICE credentials of every bundled section that can become the tag")
        void everyCandidateTag() {
            var withoutVideoCredentials = new StringBuilder();
            var section = 0;
            for (var line : BrowserFixtures.CHROME_OFFER.split("\r\n")) {
                if (line.startsWith("m=")) {
                    section++;
                }
                if (section == 2 && line.startsWith("a=ice-")) {
                    continue;
                }
                withoutVideoCredentials.append(line).append("\r\n");
            }
            var b = peer();
            assertThrows(OperationErrorException.class, () -> b.pc().setRemoteDescription(
                    JsepDescription.offer(withoutVideoCredentials.toString())));
        }
    }

    @Nested
    @DisplayName("remote description checks")
    class Validation {
        @Test
        @DisplayName("answers a section without a DTLS-SRTP profile with port 0")
        void sdesOffer() {
            var sdp = BrowserFixtures.CHROME_OFFER.replaceFirst("m=video 9 UDP/TLS/RTP/SAVPF", "m=video 9 RTP/SAVP");
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(sdp));
            var answer = parse(b.pc().createAnswer());
            assertEquals(0, answer.media().get(1).port());
            assertEquals("RTP/SAVP", answer.media().get(1).protocol());
            assertFalse(answer.bundleGroups().getFirst().mids().contains("1"));
        }

        @Test
        @DisplayName("refuses an answer that accepts a section with another RTP profile")
        void sdesAnswer() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer();
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            var answer = b.pc().createAnswer().sdp().replace("UDP/TLS/RTP/SAVPF", "RTP/SAVPF");
            assertThrows(OperationErrorException.class,
                    () -> a.pc().setRemoteDescription(JsepDescription.answer(answer)));
            assertEquals(SignalingState.HAVE_LOCAL_OFFER, a.pc().signalingState());
        }

        @Test
        @DisplayName("refuses an extmap id naming two extensions")
        void duplicateExtensionIds() {
            var sdp = BrowserFixtures.CHROME_OFFER.replace(
                    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\na=extmap:3",
                    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
                            + "a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\na=extmap:3");
            assertNotEquals(BrowserFixtures.CHROME_OFFER, sdp);
            assertThrows(OperationErrorException.class,
                    () -> peer().pc().setRemoteDescription(JsepDescription.offer(sdp)));
        }

        @Test
        @DisplayName("refuses a payload type outside 0..127")
        void payloadTypeRange() {
            var sdp = BrowserFixtures.CHROME_OFFER.replace("m=audio 9 UDP/TLS/RTP/SAVPF 111 ",
                    "m=audio 9 UDP/TLS/RTP/SAVPF 200 111 ");
            assertNotEquals(BrowserFixtures.CHROME_OFFER, sdp);
            assertThrows(OperationErrorException.class,
                    () -> peer().pc().setRemoteDescription(JsepDescription.offer(sdp)));
        }

        @Test
        @DisplayName("refuses fingerprints that all use an unsupported hash, and accepts one supported among them")
        void fingerprintHashes() {
            var md2 = BrowserFixtures.CHROME_OFFER.replace("a=fingerprint:sha-256 " + BrowserFixtures.FINGERPRINT,
                    "a=fingerprint:md2 " + BrowserFixtures.FINGERPRINT.substring(0, 47));
            assertThrows(OperationErrorException.class,
                    () -> peer().pc().setRemoteDescription(JsepDescription.offer(md2)));
            var both = BrowserFixtures.CHROME_OFFER.replace("a=fingerprint:sha-256 " + BrowserFixtures.FINGERPRINT,
                    "a=fingerprint:md2 " + BrowserFixtures.FINGERPRINT.substring(0, 47) + "\r\na=fingerprint:sha-256 "
                            + BrowserFixtures.FINGERPRINT);
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(both));
            assertEquals(SignalingState.HAVE_REMOTE_OFFER, b.pc().signalingState());
        }
    }

    @Nested
    @DisplayName("tls-id and DTLS restarts")
    class TlsId {
        @Test
        @DisplayName("writes one stable tls-id per transport in offers and answers")
        void written() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            a.pc().addTrack(LocalTrack.video("cam"), List.of());
            var offer = a.pc().createOffer();
            var ids = new ArrayList<String>();
            for (var section : parse(offer).media()) {
                ids.addAll(section.attributes("tls-id"));
            }
            assertEquals(2, ids.size());
            assertEquals(ids.getFirst(), ids.get(1), "bundled sections share the tag's tls-id");
            assertTrue(ids.getFirst().length() >= 20);
            assertEquals(ids, List.of(attributes(a.pc().createOffer(), 0, "tls-id").getFirst(),
                    attributes(a.pc().createOffer(), 1, "tls-id").getFirst()));
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            var answer = b.pc().createAnswer();
            assertEquals(1, attributes(answer, 0, "tls-id").size());
            b.pc().setLocalDescription(answer);
            a.pc().setRemoteDescription(answer);
            var transport = a.backend().last().transports().getFirst();
            assertEquals(ids.getFirst(), transport.localTlsId());
            assertEquals(java.util.Optional.of(attributes(answer, 0, "tls-id").getFirst()), transport.remoteTlsId());
            assertFalse(transport.dtlsRestart());
            a.pc().restartIce();
            negotiate(a, b);
            assertFalse(a.backend().last().transports().getFirst().dtlsRestart(), "an ICE restart keeps DTLS");
            assertEquals(ids.getFirst(), a.backend().last().transports().getFirst().localTlsId());
        }

        @Test
        @DisplayName("flags a DTLS restart and answers with a new tls-id when the offerer changes its tls-id")
        void remoteRestart() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var before = b.backend().last().transports().getFirst();
            var offer = a.pc().createOffer();
            var oldId = attributes(offer, 0, "tls-id").getFirst();
            var restarted = JsepDescription.offer(offer.sdp().replace("a=tls-id:" + oldId,
                    "a=tls-id:abcdefghijklmnopqrstuvwxyz012345"));
            b.pc().setRemoteDescription(restarted);
            var answer = b.pc().createAnswer();
            assertNotEquals(before.localTlsId(), attributes(answer, 0, "tls-id").getFirst());
            b.pc().setLocalDescription(answer);
            var after = b.backend().last().transports().getFirst();
            assertTrue(after.dtlsRestart());
            assertNotEquals(before.localTlsId(), after.localTlsId());
        }

        @Test
        @DisplayName("flags a DTLS restart when the answerer changes its fingerprint")
        void fingerprintChange() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            negotiate(a, b);
            var offer = a.pc().createOffer();
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            var answer = b.pc().createAnswer();
            b.pc().setLocalDescription(answer);
            var other = SdpAttribute.Fingerprint.of("sha-256", new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});
            a.pc().setRemoteDescription(JsepDescription.answer(answer.sdp().replace(
                    FakeBackend.FINGERPRINT.toLine().value(), other.toLine().value())));
            assertTrue(a.backend().last().transports().getFirst().dtlsRestart());
        }
    }

    @Nested
    @DisplayName("cryptex and congestion control feedback")
    class SectionFlags {
        @Test
        @DisplayName("offers cryptex and ack ccfb, and the answer echoes them")
        void echoed() {
            var a = peer();
            var b = peer();
            a.pc().addTrack(LocalTrack.audio("mic"), List.of());
            var offer = a.pc().createOffer();
            assertTrue(parse(offer).media().getFirst().hasAttribute("cryptex"));
            assertTrue(attributes(offer, 0, "rtcp-fb").contains("* ack ccfb"));
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            var answer = b.pc().createAnswer();
            assertTrue(parse(answer).media().getFirst().hasAttribute("cryptex"));
            assertTrue(attributes(answer, 0, "rtcp-fb").contains("* ack ccfb"));
            b.pc().setLocalDescription(answer);
            a.pc().setRemoteDescription(answer);
            for (var media : List.of(a.backend().last().media().getFirst(), b.backend().last().media().getFirst())) {
                assertTrue(media.cryptex());
                assertTrue(media.congestionControlFeedback());
                media.codecs().forEach(codec -> assertFalse(codec.feedback().contains(CodecCatalog.CCFB)));
            }
        }

        @Test
        @DisplayName("negotiates neither when the offer omits them")
        void omitted() {
            var b = peer();
            b.pc().setRemoteDescription(JsepDescription.offer(BrowserFixtures.CHROME_OFFER));
            var answer = b.pc().createAnswer();
            assertFalse(parse(answer).media().getFirst().hasAttribute("cryptex"));
            assertFalse(attributes(answer, 0, "rtcp-fb").contains("* ack ccfb"));
            b.pc().setLocalDescription(answer);
            var media = b.backend().last().media().getFirst();
            assertFalse(media.cryptex());
            assertFalse(media.congestionControlFeedback());
        }
    }

    @Nested
    @DisplayName("header extensions per transceiver")
    class HeaderExtensions {
        @Test
        @DisplayName("offers what headerExtensionsToNegotiate lists, in its directions, and reports the outcome")
        void negotiated() {
            var a = peer();
            var b = peer();
            var transceiver = a.pc().addTransceiver(MediaKind.AUDIO, TransceiverInit.of(TransceiverDirection.SENDRECV));
            var extensions = transceiver.headerExtensionsToNegotiate();
            assertTrue(extensions.stream().allMatch(extension -> extension.direction() == TransceiverDirection.SENDRECV));
            assertFalse(extensions.stream().anyMatch(extension -> extension.uri().equals(CodecCatalog.RTP_STREAM_ID)));
            var edited = new ArrayList<RtpHeaderExtensionCapability>();
            for (var extension : extensions) {
                if (extension.uri().equals(CodecCatalog.AUDIO_LEVEL)) {
                    edited.add(extension.withDirection(TransceiverDirection.STOPPED));
                } else if (extension.uri().equals(CodecCatalog.ABS_SEND_TIME)) {
                    edited.add(extension.withDirection(TransceiverDirection.SENDONLY));
                } else {
                    edited.add(extension);
                }
            }
            transceiver.setHeaderExtensionsToNegotiate(edited);
            assertEquals(edited, transceiver.headerExtensionsToNegotiate());
            assertTrue(transceiver.negotiatedHeaderExtensions().stream()
                    .allMatch(extension -> extension.direction() == TransceiverDirection.STOPPED));
            var offer = a.pc().createOffer();
            var extmaps = parse(offer).media().getFirst().attributes(SdpAttribute.Extmap.class);
            assertFalse(extmaps.stream().anyMatch(extmap -> extmap.uri().equals(CodecCatalog.AUDIO_LEVEL)));
            var absSendTime = extmaps.stream().filter(extmap -> extmap.uri().equals(CodecCatalog.ABS_SEND_TIME))
                    .findFirst().orElseThrow();
            assertEquals(java.util.Optional.of(com.github.auties00.parley.sdp.MediaDirection.SENDONLY),
                    absSendTime.direction());
            a.pc().setLocalDescription(offer);
            b.pc().setRemoteDescription(offer);
            var answer = b.pc().createAnswer();
            var answered = parse(answer).media().getFirst().attributes(SdpAttribute.Extmap.class);
            assertEquals(java.util.Optional.of(com.github.auties00.parley.sdp.MediaDirection.RECVONLY),
                    answered.stream().filter(extmap -> extmap.uri().equals(CodecCatalog.ABS_SEND_TIME))
                            .findFirst().orElseThrow().direction());
            b.pc().setLocalDescription(answer);
            a.pc().setRemoteDescription(answer);
            var outcome = transceiver.negotiatedHeaderExtensions();
            assertEquals(TransceiverDirection.STOPPED, outcome.stream()
                    .filter(extension -> extension.uri().equals(CodecCatalog.AUDIO_LEVEL)).findFirst().orElseThrow()
                    .direction());
            assertEquals(TransceiverDirection.SENDONLY, outcome.stream()
                    .filter(extension -> extension.uri().equals(CodecCatalog.ABS_SEND_TIME)).findFirst().orElseThrow()
                    .direction());
            assertEquals(TransceiverDirection.SENDRECV, outcome.stream()
                    .filter(extension -> extension.uri().equals(CodecCatalog.MID)).findFirst().orElseThrow()
                    .direction());
        }

        @Test
        @DisplayName("refuses an unknown extension, a duplicate, and stopping sdes:mid")
        void refused() {
            var transceiver = peer().pc().addTransceiver(MediaKind.VIDEO,
                    TransceiverInit.of(TransceiverDirection.SENDRECV));
            assertThrows(InvalidModificationException.class, () -> transceiver.setHeaderExtensionsToNegotiate(
                    List.of(new RtpHeaderExtensionCapability(URI.create("urn:example:unknown")))));
            var mid = new RtpHeaderExtensionCapability(CodecCatalog.MID);
            assertThrows(InvalidModificationException.class,
                    () -> transceiver.setHeaderExtensionsToNegotiate(List.of(mid, mid)));
            assertThrows(InvalidModificationException.class, () -> transceiver.setHeaderExtensionsToNegotiate(
                    List.of(mid.withDirection(TransceiverDirection.STOPPED))));
            transceiver.setHeaderExtensionsToNegotiate(List.of(mid));
            assertEquals(1, transceiver.headerExtensionsToNegotiate().stream()
                    .filter(extension -> extension.direction() != TransceiverDirection.STOPPED).count());
        }
    }

    @Nested
    @DisplayName("bitrate caps")
    class Bitrates {
        /// {@return a remote offer with `line` written after the `c=` line of its section `index`}
        static String withBandwidth(int index, String line) {
            var section = new int[1];
            return edit(BrowserFixtures.CHROME_OFFER, text -> {
                if (text.startsWith("m=")) {
                    section[0]++;
                }
                return section[0] == index + 1 && text.startsWith("c=") ? text + "\r\n" + line : text;
            });
        }

        /// {@return the cap of the `kind` section the answerer negotiates against `offer`}
        static OptionalLong cap(String offer, MediaKind kind) {
            var b = peer();
            b.pc().addTrack(LocalTrack.video("cam"), List.of());
            b.pc().addTrack(LocalTrack.audio("mic"), List.of());
            b.pc().setRemoteDescription(JsepDescription.offer(offer));
            b.pc().setLocalDescription(b.pc().createAnswer());
            return b.backend().last().media().stream().filter(media -> media.kind() == kind)
                    .findFirst().orElseThrow().maxBitrate();
        }

        @Test
        @DisplayName("takes TIAS as is, converts AS to a payload rate, and falls back to the session level")
        void conversions() {
            assertEquals(OptionalLong.of(500_000), cap(withBandwidth(1, "b=TIAS:500000"), MediaKind.VIDEO));
            var as = 1_000_000L;
            var packets = Math.ceilDiv(as, JsepEngine.VIDEO_PACKET_BYTES * 8L);
            assertEquals(OptionalLong.of(as - packets * JsepEngine.PACKET_OVERHEAD_BYTES * 8),
                    cap(withBandwidth(1, "b=AS:1000"), MediaKind.VIDEO));
            assertEquals(OptionalLong.of(300_000), cap(withBandwidth(1, "b=AS:2000\r\nb=TIAS:300000"),
                    MediaKind.VIDEO));
            var session = BrowserFixtures.CHROME_OFFER.replace("t=0 0\r\n", "t=0 0\r\nb=TIAS:700000\r\n");
            assertEquals(OptionalLong.of(700_000), cap(session, MediaKind.VIDEO));
            assertEquals(OptionalLong.of(700_000), cap(session, MediaKind.AUDIO));
            assertEquals(OptionalLong.empty(), cap(BrowserFixtures.CHROME_OFFER, MediaKind.VIDEO));
            assertEquals(OptionalLong.of(64_000 - JsepEngine.AUDIO_PACKETS_PER_SECOND
                    * JsepEngine.PACKET_OVERHEAD_BYTES * 8), cap(withBandwidth(0, "b=AS:64"), MediaKind.AUDIO));
            assertEquals(OptionalLong.of(10_000), cap(withBandwidth(0, "b=AS:20"), MediaKind.AUDIO),
                    "the overhead never takes more than half of a small cap");
        }

        @Test
        @DisplayName("writes the receive cap as b=TIAS, which the peer applies to what it sends")
        void receiveCap() {
            var a = peer();
            var b = peer();
            a.pc().addTransceiver(MediaKind.VIDEO, TransceiverInit.builder()
                    .direction(TransceiverDirection.RECVONLY).receiveBitrateCap(800_000).build());
            var offer = a.pc().createOffer();
            assertTrue(parse(offer).media().getFirst().lines().contains(new SdpLine('b', "TIAS:800000")));
            a.pc().setLocalDescription(offer);
            b.pc().addTrack(LocalTrack.video("cam"), List.of());
            b.pc().setRemoteDescription(offer);
            b.pc().setLocalDescription(b.pc().createAnswer());
            assertEquals(OptionalLong.of(800_000), b.backend().last().media().getFirst().maxBitrate());
            assertThrows(IllegalArgumentException.class, () -> TransceiverInit.builder().receiveBitrateCap(0));
        }
    }

    @Test
    @DisplayName("keeps a remote track mode and a receive cap on the transceiver options")
    void transceiverInit() {
        var init = TransceiverInit.builder().remoteTrackMode(RemoteTrackMode.RAW_PACKETS)
                .receiveBitrateCap(64_000).build();
        assertEquals(java.util.Optional.of(RemoteTrackMode.RAW_PACKETS), init.remoteTrackMode());
        assertEquals(OptionalLong.of(64_000), init.receiveBitrateCap());
        var defaults = TransceiverInit.of(TransceiverDirection.SENDONLY);
        assertTrue(defaults.remoteTrackMode().isEmpty());
        assertTrue(defaults.receiveBitrateCap().isEmpty());
        var transceiver = peer().pc().addTransceiver(MediaKind.AUDIO, init);
        assertEquals(java.util.Optional.of(RemoteTrackMode.RAW_PACKETS), transceiver.remoteTrackMode());
    }

    /// {@return the media section of a description by index, for readability}
    static MediaDescription section(SessionDescription description, int index) {
        return description.media().get(index);
    }
}
