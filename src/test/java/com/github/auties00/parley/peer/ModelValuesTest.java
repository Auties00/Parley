package com.github.auties00.parley.peer;

import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.Priority;
import com.github.auties00.parley.media.RtcpFeedback;
import com.github.auties00.parley.media.RtpCodecParameters;
import com.github.auties00.parley.sdp.MediaDescription;
import com.github.auties00.parley.sdp.RtpCodec;
import com.github.auties00.parley.sdp.SdpLine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the value types the negotiation fixes reshaped: [Encoding] and its withers, [Priority], the SDP view
/// [RtpCodec], and the statistics ids of candidates.
@DisplayName("model values")
class ModelValuesTest {
    @Test
    @DisplayName("Encoding withers change one component each and validate it")
    void encodingWithers() {
        var vp9 = Codec.vp9();
        var encoding = Encoding.rid("h").withActive(false).withMaxBitrate(900_000).withMaxFramerate(15)
                .withScaleResolutionDownBy(2).withPriority(Priority.HIGH).withNetworkPriority(Priority.MEDIUM)
                .withScalabilityMode("L1T3").withCodec(vp9).withRid("q");
        assertEquals(new Encoding(Optional.of("q"), false, OptionalLong.of(900_000), OptionalDouble.of(15),
                OptionalDouble.of(2), Priority.HIGH, Priority.MEDIUM, Optional.of("L1T3"), Optional.of(vp9)),
                encoding);
        assertEquals(Optional.empty(), Encoding.defaults().codec());
        assertThrows(IllegalArgumentException.class, () -> encoding.withMaxBitrate(0));
        assertThrows(IllegalArgumentException.class, () -> encoding.withMaxFramerate(-1));
        assertThrows(IllegalArgumentException.class, () -> encoding.withScaleResolutionDownBy(0.5));
        assertThrows(IllegalArgumentException.class, () -> encoding.withScalabilityMode(" "));
        assertThrows(IllegalArgumentException.class, () -> encoding.withRid("a b"));
    }

    @ParameterizedTest
    @EnumSource(Priority.class)
    @DisplayName("Priority maps to its W3C value, its weight and its data channel wire value")
    void priority(Priority priority) {
        assertEquals(priority, Priority.ofValue(priority.value()));
        assertEquals(priority, Priority.ofWireValue(priority.wireValue()));
        assertTrue(priority.weight() > 0);
    }

    @Test
    @DisplayName("Priority reads wire values by range and rejects unknown W3C values")
    void priorityRanges() {
        assertEquals(Priority.VERY_LOW, Priority.ofWireValue(0));
        assertEquals(Priority.LOW, Priority.ofWireValue(129));
        assertEquals(Priority.MEDIUM, Priority.ofWireValue(512));
        assertEquals(Priority.HIGH, Priority.ofWireValue(65535));
        assertThrows(IllegalArgumentException.class, () -> Priority.ofValue("urgent"));
    }

    @Test
    @DisplayName("RtpCodec is the SDP view of codec parameters, both ways")
    void rtpCodecView() {
        var opus = RtpCodecParameters.of(111, Codec.opus().withFormatParameters(Map.of("minptime", "10")));
        var view = RtpCodec.of(opus);
        assertEquals(new RtpCodec(111, "opus", 48000, OptionalInt.of(2), Map.of("minptime", "10")), view);
        assertEquals("111 opus/48000/2", view.rtpmapValue());
        assertEquals(Optional.of("minptime=10"), view.fmtpValue());
        assertEquals(opus, view.toParameters());
        var vp8 = RtpCodec.of(96, "VP8", 90000);
        assertEquals(new RtpCodecParameters(96, Codec.vp8(), List.<RtcpFeedback>of()), vp8.toParameters());
        assertEquals(com.github.auties00.parley.media.MediaKind.VIDEO, vp8.kind());
        assertEquals(com.github.auties00.parley.media.MediaKind.AUDIO, RtpCodec.of(0, "PCMU", 8000).kind());
        assertThrows(IllegalArgumentException.class, () -> RtpCodec.of(128, "opus", 48000));
        assertThrows(IllegalArgumentException.class, () -> RtpCodec.of(96, "a/b", 90000));
    }

    @Test
    @DisplayName("RtpCodec keeps an fmtp that is not a key=value list verbatim under the empty key")
    void verbatimFmtp() {
        assertEquals(Map.of("", "111/111"), RtpCodec.parseFormatParameters("111/111"));
        assertEquals(Map.of("", "0-15"), RtpCodec.parseFormatParameters(" 0-15 "));
        assertEquals(Map.of("", "a=1;a=2"), RtpCodec.parseFormatParameters("a=1;a=2"));
        assertEquals(Map.of("apt", "96"), RtpCodec.parseFormatParameters("apt=96"));
        var section = new MediaDescription("audio", 9, "UDP/TLS/RTP/SAVPF", List.of("63", "126", "9"), List.of(
                SdpLine.attribute("rtpmap", "63 red/48000/2"), SdpLine.attribute("fmtp", "63 111/111"),
                SdpLine.attribute("rtpmap", "126 telephone-event/8000"), SdpLine.attribute("fmtp", "126 0-15")));
        var codecs = RtpCodec.of(section);
        assertEquals(Optional.of("111/111"), codecs.get(0).fmtpValue());
        assertEquals(Map.of("", "0-15"), codecs.get(1).formatParameters());
        assertEquals(Codec.telephoneEvent(8000), codecs.get(1).toParameters().codec());
        assertEquals("G722", codecs.get(2).name(), "payload type 9 is G.722 without an rtpmap");
    }

    @Test
    @DisplayName("candidate statistics ids differ for local and remote candidates and per transport")
    void candidateIds() {
        var candidate = IceCandidate.parse("candidate:1 1 udp 2122260223 192.0.2.10 46243 typ host");
        var local = StatsMapper.candidateId("0", candidate, false);
        var remote = StatsMapper.candidateId("0", candidate, true);
        assertNotEquals(local, remote);
        assertNotEquals(local, StatsMapper.candidateId("1", candidate, false));
        assertTrue(local.startsWith("IL0_"));
        assertTrue(remote.startsWith("IR0_"));
        assertFalse(local.contains(":"));
    }
}
