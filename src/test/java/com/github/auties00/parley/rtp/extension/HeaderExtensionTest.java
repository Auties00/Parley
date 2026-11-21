package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the extension map and every typed extension codec against hand-encoded values, plus a fuzz pass over the
/// generic parser.
@DisplayName("RTP header extensions")
class HeaderExtensionTest {
    private static final HexFormat HEX = HexFormat.of();

    private static void assertCodec(String hex, HeaderExtension value) throws RtpFormatException {
        assertEquals(hex, HEX.formatHex(bytes(value.encode())));
        assertEquals(hex.length() / 2, value.encodedLength());
        assertEquals(Optional.of(value), HeaderExtension.parse(value.uri(), ByteBuffer.wrap(HEX.parseHex(hex))));
    }

    private static byte[] bytes(ByteBuffer buffer) {
        var out = new byte[buffer.remaining()];
        buffer.duplicate().get(out);
        return out;
    }

    @Nested
    @DisplayName("extension map")
    class Map_ {
        @Test
        @DisplayName("maps ids and URIs both ways and finds values in packets")
        void lookup() throws RtpFormatException {
            var map = HeaderExtensionMap.of(Map.of(1, HeaderExtensionUris.MID, 3, HeaderExtensionUris.AUDIO_LEVEL));
            assertEquals(3, map.idOf(HeaderExtensionUris.AUDIO_LEVEL).orElseThrow());
            assertEquals(HeaderExtensionUris.MID, map.uriOf(1).orElseThrow());
            assertTrue(map.uriOf(2).isEmpty());
            assertFalse(map.allowMixed());
            assertTrue(map.withAllowMixed(true).allowMixed());
            var packet = RtpPacket.parse(RtpPacketWriter.into(ByteBuffer.allocate(64))
                    .extension(1, new Mid("0").encode()).finish());
            assertEquals(new Mid("0"), Mid.parse(map.find(packet, HeaderExtensionUris.MID).orElseThrow()));
            assertTrue(map.find(packet, HeaderExtensionUris.AUDIO_LEVEL).isEmpty());
        }

        @Test
        @DisplayName("rejects out-of-range ids and duplicate URIs")
        void validation() {
            assertThrows(IllegalArgumentException.class, () -> HeaderExtensionMap.of(Map.of(0,
                    HeaderExtensionUris.MID)));
            assertThrows(IllegalArgumentException.class, () -> HeaderExtensionMap.of(Map.of(1,
                    HeaderExtensionUris.MID, 2, HeaderExtensionUris.MID)));
        }
    }

    @Nested
    @DisplayName("value codecs")
    class Codecs {
        @Test
        @DisplayName("encodes the SDES identifiers and strips zero padding")
        void identifiers() throws RtpFormatException {
            assertCodec("6175646930", new Mid("audi0"));
            assertCodec("6869", new RtpStreamId("hi"));
            assertCodec("6c6f", new RepairedRtpStreamId("lo"));
            assertEquals(new Mid("a"), Mid.parse(ByteBuffer.wrap(HEX.parseHex("610000"))));
            assertThrows(RtpFormatException.class, () -> Mid.parse(ByteBuffer.wrap(new byte[2])));
        }

        @Test
        @DisplayName("encodes abs-send-time as 6.18 fixed point seconds")
        void absSendTime() throws RtpFormatException {
            assertCodec("0c0000", new AbsSendTime(3 << 18));
            assertEquals(new AbsSendTime(3 << 18), AbsSendTime.ofNanos(3_000_000_000L));
            assertEquals(new AbsSendTime(1 << 17), AbsSendTime.ofNanos(64_500_000_000L));
            assertEquals(500_000_000L, new AbsSendTime(1 << 17).toNanos());
            var buffer = ByteBuffer.allocate(5);
            AbsSendTime.stamp(buffer, 1, 3_000_000_000L);
            assertEquals("000c000000", HEX.formatHex(buffer.array()));
        }

        @Test
        @DisplayName("encodes the transport-wide sequence number")
        void transportSequence() throws RtpFormatException {
            assertCodec("ff01", new TransportSequenceNumber(0xFF01));
            var buffer = ByteBuffer.allocate(4);
            TransportSequenceNumber.stamp(buffer, 2, 0x10203);
            assertEquals("00000203", HEX.formatHex(buffer.array()));
        }

        @Test
        @DisplayName("encodes the audio levels of RFC 6464 and RFC 6465")
        void audioLevels() throws RtpFormatException {
            assertCodec("9e", new AudioLevel(true, 30));
            assertCodec("7f", new AudioLevel(false, 127));
            assertCodec("010203", new CsrcAudioLevels(List.of(1, 2, 3)));
        }

        @Test
        @DisplayName("encodes the signed transmission time offset")
        void toffset() throws RtpFormatException {
            assertCodec("fffffe", new TransmissionTimeOffset(-2));
            assertCodec("7fffff", new TransmissionTimeOffset(0x7FFFFF));
        }

        @Test
        @DisplayName("encodes the video orientation bits")
        void orientation() throws RtpFormatException {
            assertCodec("0f", new VideoOrientation(true, true, 270));
            assertCodec("01", new VideoOrientation(false, false, 90));
        }

        @Test
        @DisplayName("encodes the absolute capture time with and without the clock offset")
        void absCaptureTime() throws RtpFormatException {
            assertCodec("0102030405060708", new AbsCaptureTime(0x0102030405060708L, OptionalLong.empty()));
            assertCodec("0102030405060708fffffffffffffffe",
                    new AbsCaptureTime(0x0102030405060708L, OptionalLong.of(-2)));
        }

        @Test
        @DisplayName("encodes the playout delay in tens of milliseconds")
        void playoutDelay() throws RtpFormatException {
            assertCodec("00a064", new PlayoutDelay(java.time.Duration.ofMillis(100), java.time.Duration.ofMillis(1000)));
            assertCodec("000000", new PlayoutDelay(java.time.Duration.ZERO, java.time.Duration.ZERO));
            assertThrows(RtpFormatException.class, () -> PlayoutDelay.parse(ByteBuffer.wrap(HEX.parseHex("064000"))));
        }

        @Test
        @DisplayName("encodes the content type and video timing")
        void contentTypeAndTiming() throws RtpFormatException {
            assertCodec("01", new VideoContentType(VideoContentType.SCREENSHARE));
            assertCodec("01000100020003000400050006", new VideoTiming(1, 1, 2, 3, 4, 5, 6));
            assertEquals(new VideoTiming(0, 1, 2, 3, 4, 5, 6),
                    VideoTiming.parse(ByteBuffer.wrap(HEX.parseHex("000100020003000400050006"))));
        }

        @Test
        @DisplayName("encodes the color space with and without HDR metadata")
        void colorSpace() throws RtpFormatException {
            assertCodec("01010126", new ColorSpace(1, 1, 1, 2, 1, 2, Optional.empty()));
            var hdr = new ColorSpace.HdrMetadata(1, 2, 3, 4, 5, 6, 7, 8, 1000, 50, 400, 200);
            assertCodec("09100902" + "0001000200030004000500060007000803e80032019000c8",
                    new ColorSpace(9, 16, 9, 0, 0, 2, Optional.of(hdr)));
        }

        @Test
        @DisplayName("returns empty for unknown URIs")
        void unknown() throws RtpFormatException {
            assertTrue(HeaderExtension.parse(URI.create("urn:example"), ByteBuffer.allocate(1)).isEmpty());
            assertTrue(HeaderExtension.parse(HeaderExtensionUris.DEPENDENCY_DESCRIPTOR, ByteBuffer.allocate(3))
                    .isEmpty());
        }
    }

    @RepeatedTest(10)
    @DisplayName("throws only RtpFormatException when parsing random values for every URI")
    void fuzz() {
        var random = new Random();
        var uris = List.of(HeaderExtensionUris.MID, HeaderExtensionUris.RTP_STREAM_ID,
                HeaderExtensionUris.REPAIRED_RTP_STREAM_ID, HeaderExtensionUris.ABS_SEND_TIME,
                HeaderExtensionUris.TRANSPORT_WIDE_CC, HeaderExtensionUris.AUDIO_LEVEL,
                HeaderExtensionUris.CSRC_AUDIO_LEVEL, HeaderExtensionUris.TOFFSET,
                HeaderExtensionUris.VIDEO_ORIENTATION, HeaderExtensionUris.ABS_CAPTURE_TIME,
                HeaderExtensionUris.PLAYOUT_DELAY, HeaderExtensionUris.VIDEO_CONTENT_TYPE,
                HeaderExtensionUris.VIDEO_TIMING, HeaderExtensionUris.COLOR_SPACE);
        for (var i = 0; i < 2_000; i++) {
            var data = new byte[random.nextInt(32)];
            random.nextBytes(data);
            var uri = uris.get(random.nextInt(uris.size()));
            try {
                var parsed = HeaderExtension.parse(uri, ByteBuffer.wrap(data));
                assertTrue(parsed.isPresent());
                parsed.get().encode();
            } catch (RtpFormatException expected) {
                // malformed values are reported, never anything else
            }
        }
    }
}
