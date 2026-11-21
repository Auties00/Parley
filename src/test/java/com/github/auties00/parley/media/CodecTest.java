package com.github.auties00.parley.media;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the codec model: media types, format parameters, negotiation matching (RFC 6184 section 8.1 profiles), the
/// H.264 `profile-level-id` codec, encoded frames and metadata validation.
@DisplayName("media model")
class CodecTest {
    @Nested
    @DisplayName("Codec")
    class Codecs {
        @Test
        @DisplayName("lower-cases parameter names and reports kind and name")
        void normalises() {
            var codec = new Codec("video/H264", 90000, OptionalInt.empty(), Map.of("Profile-Level-Id", "42e01f"));
            assertEquals(MediaKind.VIDEO, codec.kind());
            assertEquals("H264", codec.name());
            assertEquals(Optional.of("42e01f"), codec.formatParameter("PROFILE-LEVEL-ID"));
            assertEquals(1, codec.channelCount());
        }

        @ParameterizedTest
        @ValueSource(strings = {"opus", "application/foo", "audio/", "/opus", "audio/op us", "audio/a/b"})
        @DisplayName("rejects malformed or non-media types")
        void rejectsTypes(String type) {
            assertThrows(IllegalArgumentException.class, () -> Codec.of(type, 48000));
        }

        @Test
        @DisplayName("rejects channels on video and non-positive clocks")
        void rejectsValues() {
            assertThrows(IllegalArgumentException.class, () -> Codec.of("video/VP8", 90000, 2));
            assertThrows(IllegalArgumentException.class, () -> Codec.of("audio/opus", 0));
            assertThrows(IllegalArgumentException.class,
                    () -> new Codec("audio/opus", 48000, OptionalInt.empty(), Map.of("a", "1", "A", "2")));
        }

        @Test
        @DisplayName("parses and writes a=fmtp parameters, keeping a bare value under the empty name")
        void formatParameters() {
            var parsed = Codec.parseFormatParameters(" minptime=10; useinbandfec=1 ;");
            assertEquals(Map.of("minptime", "10", "useinbandfec", "1"), parsed);
            var codec = Codec.opus().withFormatParameters(parsed);
            assertEquals("minptime=10;useinbandfec=1", codec.formatParametersLine());
            assertEquals("0-15", Codec.telephoneEvent(8000).formatParametersLine());
            assertEquals(Map.of("", "0-15"), Codec.parseFormatParameters("0-15"));
        }

        @Test
        @DisplayName("matches ignoring case, with Opus's two rtpmap channels and stereo as a preference")
        void matchesBasics() {
            assertTrue(Codec.of("audio/OPUS", 48000, 2).matches(Codec.opus().withFormatParameters(Map.of("stereo", "1"))));
            assertFalse(Codec.opus().matches(Codec.of("audio/opus", 48000)));
            assertFalse(Codec.pcmu().matches(Codec.pcma()));
            assertFalse(Codec.of("audio/G722", 16000).matches(Codec.g722()));
            assertTrue(Codec.pcmu().matches(Codec.of("audio/pcmu", 8000, 1)));
        }

        @ParameterizedTest(name = "{0} vs {1} -> {2}")
        @CsvSource({
                "42e01f, 42e01f, true",
                "42e01f, 42e00a, true",
                "42e01f, 4d801f, true",
                "42e01f, 42001f, false",
                "42e01f, 4d001f, false",
                "640c1f, 640c34, true",
                "640c1f, 64001f, false",
                "42e01f, zzzzzz, false"
        })
        @DisplayName("matches H.264 by profile, not level")
        void matchesH264Profile(String left, String right, boolean expected) {
            var a = Codec.of("video/H264", 90000).withFormatParameters(Map.of("profile-level-id", left));
            var b = Codec.of("video/H264", 90000).withFormatParameters(Map.of("profile-level-id", right));
            assertEquals(expected, a.matches(b));
        }

        @Test
        @DisplayName("matches H.264 only with the same packetization mode, absent meaning 0")
        void matchesPacketizationMode() {
            var mode1 = Codec.h264();
            var mode0 = mode1.withFormatParameters(Map.of("profile-level-id", "42e01f"));
            assertFalse(mode1.matches(mode0));
            assertTrue(mode0.matches(mode0.withFormatParameters(Map.of("profile-level-id", "42e01f",
                    "packetization-mode", "0"))));
            assertTrue(Codec.of("video/H264", 90000).matches(mode0.withFormatParameters(Map.of("profile-level-id",
                    "42e01f"))));
        }

        @Test
        @DisplayName("matches VP9 profile-id, AV1 profile, H.265 profile and tier, RTX apt")
        void matchesOthers() {
            assertTrue(Codec.vp9().matches(Codec.vp9().withFormatParameters(Map.of("profile-id", "0"))));
            assertFalse(Codec.vp9().matches(Codec.vp9().withFormatParameters(Map.of("profile-id", "2"))));
            assertFalse(Codec.av1().matches(Codec.av1().withFormatParameters(Map.of("profile", "1"))));
            assertTrue(Codec.av1().matches(Codec.av1().withFormatParameters(Map.of("level-idx", "8"))));
            assertTrue(Codec.h265().matches(Codec.h265().withFormatParameters(Map.of("profile-id", "1",
                    "level-id", "120"))));
            assertFalse(Codec.h265().matches(Codec.h265().withFormatParameters(Map.of("tier-flag", "1"))));
            var rtx = Codec.of("video/rtx", 90000).withFormatParameters(Map.of("apt", "96"));
            assertTrue(rtx.matches(rtx));
            assertFalse(rtx.matches(rtx.withFormatParameters(Map.of("apt", "97"))));
        }
    }

    @Nested
    @DisplayName("H.264 profile-level-id")
    class ProfileLevel {
        @ParameterizedTest(name = "{0}")
        @CsvSource({
                "42e01f, CONSTRAINED_BASELINE, LEVEL_3_1",
                "42C01F, CONSTRAINED_BASELINE, LEVEL_3_1",
                "4d801f, CONSTRAINED_BASELINE, LEVEL_3_1",
                "58c01f, CONSTRAINED_BASELINE, LEVEL_3_1",
                "42001f, BASELINE, LEVEL_3_1",
                "58801f, BASELINE, LEVEL_3_1",
                "4d001f, MAIN, LEVEL_3_1",
                "64001f, HIGH, LEVEL_3_1",
                "640c34, CONSTRAINED_HIGH, LEVEL_5_2",
                "f4001f, PREDICTIVE_HIGH_444, LEVEL_3_1",
                "42f00b, CONSTRAINED_BASELINE, LEVEL_1B",
                "42100b, BASELINE, LEVEL_1B",
                "4d100b, MAIN, LEVEL_1B",
                "640009, HIGH, LEVEL_1B",
                "42e00b, CONSTRAINED_BASELINE, LEVEL_1_1"
        })
        @DisplayName("parses the profile patterns and levels")
        void parses(String value, H264ProfileLevelId.Profile profile, H264ProfileLevelId.Level level) {
            var parsed = H264ProfileLevelId.parse(value).orElseThrow();
            assertEquals(profile, parsed.profile());
            assertEquals(level, parsed.level());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "42e01", "42e01f0", "zze01f", "42e000", "43e01f", "42e01g", "6e001f"})
        @DisplayName("rejects malformed values and unknown profiles or levels")
        void rejects(String value) {
            assertTrue(H264ProfileLevelId.parse(value).isEmpty());
        }

        @ParameterizedTest
        @ValueSource(strings = {"42e01f", "42001f", "4d001f", "640c1f", "64001f", "f4001f", "42f00b", "42100b",
                "4d100b", "42e034"})
        @DisplayName("writes canonical values that parse back to the same profile and level")
        void roundTrip(String value) {
            var parsed = H264ProfileLevelId.parse(value).orElseThrow();
            assertEquals(parsed, H264ProfileLevelId.parse(parsed.toString()).orElseThrow());
        }

        @Test
        @DisplayName("defaults to Constrained Baseline 3.1 and orders levels with 1b between 1 and 1.1")
        void defaults() {
            assertEquals(H264ProfileLevelId.DEFAULT, H264ProfileLevelId.of(Map.of()).orElseThrow());
            assertTrue(H264ProfileLevelId.Level.LEVEL_1B.compareTo(H264ProfileLevelId.Level.LEVEL_1) > 0);
            assertTrue(H264ProfileLevelId.Level.LEVEL_1B.compareTo(H264ProfileLevelId.Level.LEVEL_1_1) < 0);
            assertEquals("640009", new H264ProfileLevelId(H264ProfileLevelId.Profile.HIGH,
                    H264ProfileLevelId.Level.LEVEL_1B).toString());
        }
    }

    @Nested
    @DisplayName("RTCP feedback and codec parameters")
    class Feedback {
        @Test
        @DisplayName("parses and writes rtcp-fb values")
        void parses() {
            assertEquals(RtcpFeedback.PLI, RtcpFeedback.parse("nack pli"));
            assertEquals(RtcpFeedback.FIR, RtcpFeedback.parse(" ccm  fir "));
            assertEquals(RtcpFeedback.TRANSPORT_CC, RtcpFeedback.parse("transport-cc"));
            assertEquals("nack pli", RtcpFeedback.PLI.toString());
            assertThrows(IllegalArgumentException.class, () -> RtcpFeedback.parse(" "));
        }

        @Test
        @DisplayName("bounds payload types and copies feedback")
        void parameters() {
            var parameters = new RtpCodecParameters(96, Codec.vp8(), List.of(RtcpFeedback.NACK, RtcpFeedback.PLI));
            assertTrue(parameters.hasFeedback(RtcpFeedback.PLI));
            assertFalse(parameters.hasFeedback(RtcpFeedback.FIR));
            assertThrows(IllegalArgumentException.class, () -> RtpCodecParameters.of(128, Codec.vp8()));
            assertThrows(UnsupportedOperationException.class, () -> parameters.feedback().add(RtcpFeedback.FIR));
        }
    }

    @Nested
    @DisplayName("EncodedFrame and metadata")
    class Frames {
        @Test
        @DisplayName("keeps a read-only view and hands out independent duplicates")
        void readOnly() {
            var bytes = ByteBuffer.wrap(new byte[]{1, 2, 3, 4}).position(1);
            var frame = EncodedFrame.of(MediaKind.VIDEO, bytes, 0xFFFFFFFFL, true);
            assertEquals(3, frame.size());
            assertTrue(frame.data().isReadOnly());
            var view = frame.data();
            view.get();
            assertEquals(3, frame.data().remaining());
            assertEquals(2, frame.toByteArray()[0]);
            assertFalse(frame.toString().contains("[1, 2"));
            assertTrue(frame.metadata() instanceof GenericFrameMetadata);
        }

        @Test
        @DisplayName("checks the timestamp range and the metadata kind")
        void validates() {
            var data = ByteBuffer.allocate(1);
            assertThrows(IllegalArgumentException.class, () -> EncodedFrame.of(MediaKind.AUDIO, data, -1, true));
            assertThrows(IllegalArgumentException.class,
                    () -> EncodedFrame.of(MediaKind.AUDIO, data, 1L << 32, true));
            assertThrows(IllegalArgumentException.class, () -> new EncodedFrame(MediaKind.VIDEO, data, 0, true,
                    Optional.empty(), AudioFrameMetadata.none()));
        }

        @Test
        @DisplayName("withers replace one component")
        void withers() {
            var frame = EncodedFrame.of(MediaKind.AUDIO, ByteBuffer.allocate(2), 10, true);
            var time = Instant.ofEpochSecond(5);
            assertEquals(Optional.of(time), frame.withCaptureTime(time).captureTime());
            assertEquals(1, frame.withData(ByteBuffer.allocate(1)).size());
            var level = AudioFrameMetadata.ofLevel(30, true);
            assertSame(level, frame.withMetadata(level).metadata());
        }

        @Test
        @DisplayName("validates metadata ranges and dependencies")
        void metadata() {
            assertThrows(IllegalArgumentException.class, () -> AudioFrameMetadata.ofLevel(128, false));
            assertThrows(IllegalArgumentException.class, () -> Vp8FrameMetadata.ofTemporalLayer(4, false));
            assertThrows(IllegalArgumentException.class, () -> Vp9FrameMetadata.ofFlexible(false, List.of(1)));
            assertThrows(IllegalArgumentException.class, () -> Vp9FrameMetadata.ofFlexible(true, List.of(128)));
            assertThrows(IllegalArgumentException.class,
                    () -> H264FrameMetadata.none().withDependencies(5, List.of(5L)));
            assertThrows(IllegalArgumentException.class,
                    () -> H264FrameMetadata.none().withDependencies(5, List.of(-1L)));
            var resolved = Av1FrameMetadata.none().withDependencies(9, List.of(7L, 8L));
            assertEquals(OptionalLong.of(9), resolved.frameId());
            assertEquals(List.of(7L, 8L), resolved.dependencies());
            assertSame(AudioFrameMetadata.none(), AudioFrameMetadata.none().withDependencies(3, List.of()));
            assertThrows(IllegalArgumentException.class, () -> new Resolution(0, 10));
            assertEquals("640x480", new Resolution(640, 480).toString());
            assertThrows(IllegalArgumentException.class, () -> new Vp9ScalabilityStructure(2,
                    List.of(new Resolution(320, 240)), List.of()));
        }
    }
}
