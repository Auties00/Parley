package com.github.auties00.parley.sdp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the typed views of the description model: origin, bandwidth, directions and the accessors and withers of
/// sessions and media sections.
@DisplayName("SDP model")
class SdpModelTest {
    @Nested
    @DisplayName("Origin")
    class OriginTests {
        @Test
        @DisplayName("parses the RFC 8866 example and writes it back")
        void parse() {
            var origin = Origin.parse("jdoe 3724394400 3724394405 IN IP4 198.51.100.1").orElseThrow();
            assertEquals("jdoe", origin.username());
            assertEquals("3724394400", origin.sessionId());
            assertEquals(3724394405L, origin.sessionVersion());
            assertEquals("o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1", origin.toLine().toString());
            assertEquals(7, origin.withSessionVersion(7).sessionVersion());
        }

        @Test
        @DisplayName("rejects a line with the wrong token count or a negative version")
        void malformed() {
            assertEquals(Optional.empty(), Origin.parse("- 1 IN IP4 127.0.0.1"));
            assertEquals(Optional.empty(), Origin.parse("- 1 -1 IN IP4 127.0.0.1"));
        }
    }

    @Nested
    @DisplayName("Bandwidth")
    class BandwidthTests {
        @Test
        @DisplayName("converts AS from kilobits and TIAS as bits per second (RFC 3890)")
        void units() {
            assertEquals(OptionalLong.of(2_500_000), Bandwidth.parse("AS:2500").orElseThrow().bitsPerSecond());
            assertEquals(OptionalLong.of(64_000), Bandwidth.parse("TIAS:64000").orElseThrow().bitsPerSecond());
            assertEquals(OptionalLong.empty(), Bandwidth.parse("CT:100").orElseThrow().bitsPerSecond());
            assertEquals(OptionalLong.of(Long.MAX_VALUE),
                    new Bandwidth("AS", Long.MAX_VALUE / 10).bitsPerSecond());
        }

        @Test
        @DisplayName("rejects malformed values")
        void malformed() {
            assertEquals(Optional.empty(), Bandwidth.parse("AS"));
            assertEquals(Optional.empty(), Bandwidth.parse(":12"));
            assertEquals(Optional.empty(), Bandwidth.parse("AS:-1"));
            assertEquals(Optional.empty(), Bandwidth.parse("AS:x"));
        }
    }

    @Nested
    @DisplayName("MediaDirection")
    class Directions {
        @Test
        @DisplayName("reverses and intersects as offer/answer needs")
        void algebra() {
            assertEquals(MediaDirection.RECVONLY, MediaDirection.SENDONLY.reverse());
            assertEquals(MediaDirection.SENDRECV, MediaDirection.SENDRECV.reverse());
            assertEquals(MediaDirection.SENDONLY, MediaDirection.SENDRECV.intersect(MediaDirection.SENDONLY));
            assertEquals(MediaDirection.INACTIVE, MediaDirection.SENDONLY.intersect(MediaDirection.RECVONLY));
            for (var direction : MediaDirection.values()) {
                assertEquals(direction, MediaDirection.of(direction.sends(), direction.receives()));
                assertEquals(Optional.of(direction), MediaDirection.ofSdpName(direction.sdpName()));
            }
        }
    }

    @Nested
    @DisplayName("typed accessors")
    class Accessors {
        @Test
        @DisplayName("read the BUNDLE group, mids, directions and fingerprints of a Chrome offer")
        void chrome() {
            var offer = SessionDescription.parse(BrowserFixtures.CHROME_OFFER);
            assertEquals(List.of("0", "1", "2"), offer.bundleGroups().getFirst().mids());
            assertEquals("4611731400430051336", offer.origin().orElseThrow().sessionId());
            var video = offer.mediaByMid("1").orElseThrow();
            assertEquals(Optional.of("1"), video.mid());
            assertEquals(MediaDirection.SENDRECV, offer.direction(video));
            assertEquals(8, video.attributes(SdpAttribute.Rtpmap.class).size());
            assertEquals(1, video.attributes(SdpAttribute.SsrcGroup.class).size());
            assertTrue(offer.attribute(SdpAttribute.ExtmapAllowMixed.class).isPresent());
            assertEquals(SetupRole.ACTPASS, offer.attribute(video, SdpAttribute.Setup.class).orElseThrow().role());
        }

        @Test
        @DisplayName("fall back to the session-level fingerprint of a Firefox offer")
        void firefox() {
            var offer = SessionDescription.parse(BrowserFixtures.FIREFOX_OFFER);
            var audio = offer.media().getFirst();
            assertTrue(audio.attribute(SdpAttribute.Fingerprint.class).isEmpty());
            assertEquals(BrowserFixtures.FINGERPRINT,
                    offer.attribute(audio, SdpAttribute.Fingerprint.class).orElseThrow().fingerprint());
            var extmaps = audio.attributes(SdpAttribute.Extmap.class);
            assertEquals(Optional.of(MediaDirection.RECVONLY), extmaps.get(1).direction());
        }

        @Test
        @DisplayName("tell a rejected section from a bundle-only one")
        void rejected() {
            var rejected = new MediaDescription("video", 0, "UDP/TLS/RTP/SAVPF", List.of("96"), List.of());
            assertTrue(rejected.isRejected());
            assertFalse(rejected.withAttribute(new SdpAttribute.BundleOnly()).isRejected());
        }
    }

    @Nested
    @DisplayName("withers")
    class Withers {
        @Test
        @DisplayName("change one part of a section and keep the rest")
        void section() {
            var section = SessionDescription.parse(BrowserFixtures.LITE_SFU_OFFER).media().getFirst();
            var edited = section.withPort(9).withFormats(List.of("111")).withoutAttributes("candidate")
                    .withAttribute(new SdpAttribute.Ptime(20));
            assertEquals(9, edited.port());
            assertTrue(edited.attributes("candidate").isEmpty());
            assertEquals(20, edited.attribute(SdpAttribute.Ptime.class).orElseThrow().milliseconds());
            assertEquals(section.attributes("mid"), edited.attributes("mid"));
        }

        @Test
        @DisplayName("reject a line value with a line break")
        void lineBreak() {
            assertThrows(IllegalArgumentException.class, () -> new SdpLine('a', "x\r\ny=1"));
        }
    }
}
