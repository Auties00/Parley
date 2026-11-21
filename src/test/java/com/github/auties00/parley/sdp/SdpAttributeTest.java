package com.github.auties00.parley.sdp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Parses the typed attributes from the examples of the RFCs that define them and writes them back.
@DisplayName("SdpAttribute")
class SdpAttributeTest {
    static <T extends SdpAttribute> T parse(String text, Class<T> type) {
        var attribute = SdpAttribute.parse(text);
        assertInstanceOf(type, attribute, () -> "parsed as " + attribute);
        assertEquals("a=" + text, attribute.toLine().toString(), "canonical text");
        return type.cast(attribute);
    }

    @Nested
    @DisplayName("RTP payload formats")
    class Formats {
        @Test
        @DisplayName("reads rtpmap with and without a channel count (RFC 8866 section 6.6)")
        void rtpmap() {
            var opus = parse("rtpmap:111 opus/48000/2", SdpAttribute.Rtpmap.class);
            assertEquals(111, opus.payloadType());
            assertEquals("opus", opus.encodingName());
            assertEquals(48000, opus.clockRate());
            assertEquals(OptionalInt.of(2), opus.channels());
            var vp8 = parse("rtpmap:96 VP8/90000", SdpAttribute.Rtpmap.class);
            assertEquals(OptionalInt.empty(), vp8.channels());
        }

        @Test
        @DisplayName("reads fmtp key=value pairs and bare values")
        void fmtp() {
            var opus = parse("fmtp:111 minptime=10;useinbandfec=1", SdpAttribute.Fmtp.class);
            assertEquals(Map.of("minptime", "10", "useinbandfec", "1"), opus.parameterMap());
            assertEquals(Optional.of("1"), opus.parameter("USEINBANDFEC"));
            var red = parse("fmtp:63 111/111", SdpAttribute.Fmtp.class);
            assertEquals(Map.of("111/111", ""), red.parameterMap());
            assertEquals("a=fmtp:96 apt=97", SdpAttribute.Fmtp.of(96, Map.of("apt", "97")).toLine().toString());
        }

        @Test
        @DisplayName("reads rtcp-fb with a payload type, the wildcard and a parameter (RFC 4585 section 4.2)")
        void rtcpFb() {
            var pli = parse("rtcp-fb:96 nack pli", SdpAttribute.RtcpFb.class);
            assertEquals(OptionalInt.of(96), pli.payloadType());
            assertEquals("nack", pli.type());
            assertEquals(Optional.of("pli"), pli.parameter());
            var wildcard = parse("rtcp-fb:* trr-int 100", SdpAttribute.RtcpFb.class);
            assertEquals(OptionalInt.empty(), wildcard.payloadType());
            assertEquals(Optional.of("100"), wildcard.parameter());
        }

        @Test
        @DisplayName("rejects a payload type above 127 as invalid")
        void payloadTypeRange() {
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("rtpmap:128 x/90000"));
        }
    }

    @Nested
    @DisplayName("header extensions")
    class Extensions {
        @Test
        @DisplayName("reads extmap with a direction and extension attributes (RFC 8285 section 8)")
        void extmap() {
            var plain = parse("extmap:1 urn:ietf:params:rtp-hdrext:toffset", SdpAttribute.Extmap.class);
            assertEquals(1, plain.id());
            assertEquals(URI.create("urn:ietf:params:rtp-hdrext:toffset"), plain.uri());
            var directed = parse("extmap:2/sendrecv http://example.com/082005/ext.htm#xmeta short",
                    SdpAttribute.Extmap.class);
            assertEquals(Optional.of(MediaDirection.SENDRECV), directed.direction());
            assertEquals(Optional.of("short"), directed.attributes());
        }

        @Test
        @DisplayName("accepts ids up to 255 and the legacy answer range, nothing else")
        void extmapIds() {
            parse("extmap:255 urn:x", SdpAttribute.Extmap.class);
            parse("extmap:4096 urn:x", SdpAttribute.Extmap.class);
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("extmap:0 urn:x"));
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("extmap:256 urn:x"));
        }

        @Test
        @DisplayName("reads extmap-allow-mixed")
        void allowMixed() {
            parse("extmap-allow-mixed", SdpAttribute.ExtmapAllowMixed.class);
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("extmap-allow-mixed:1"));
        }
    }

    @Nested
    @DisplayName("sources and streams")
    class Sources {
        @Test
        @DisplayName("reads ssrc source attributes (RFC 5576 section 4.1)")
        void ssrc() {
            var cname = parse("ssrc:314159 cname:user@example.com", SdpAttribute.Ssrc.class);
            assertEquals(314159, cname.ssrc());
            assertEquals("cname", cname.attribute());
            assertEquals(Optional.of("user@example.com"), cname.value());
            var flag = parse("ssrc:4294967295 previous-ssrc", SdpAttribute.Ssrc.class);
            assertEquals(Optional.empty(), flag.value());
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("ssrc:4294967296 cname:x"));
        }

        @Test
        @DisplayName("reads ssrc-group FID, FEC-FR and SIM (RFC 5576 section 4.2, RFC 5956)")
        void ssrcGroup() {
            var fid = parse("ssrc-group:FID 2231627014 632943048", SdpAttribute.SsrcGroup.class);
            assertEquals(List.of(2231627014L, 632943048L), fid.ssrcs());
            parse("ssrc-group:FEC-FR 1 2", SdpAttribute.SsrcGroup.class);
            parse("ssrc-group:SIM 1 2 3", SdpAttribute.SsrcGroup.class);
        }

        @Test
        @DisplayName("reads msid with and without a track id (RFC 8830 section 2)")
        void msid() {
            var full = parse("msid:61317484-2ed4-49d7-9eb7-1414322a7aae f30bdb4a-5db8-49b5-bcdc-e0c9a23172e0",
                    SdpAttribute.Msid.class);
            assertEquals("61317484-2ed4-49d7-9eb7-1414322a7aae", full.streamId());
            assertEquals(Optional.of("f30bdb4a-5db8-49b5-bcdc-e0c9a23172e0"), full.trackId());
            var none = parse("msid:-", SdpAttribute.Msid.class);
            assertEquals(Optional.empty(), none.trackId());
        }

        @Test
        @DisplayName("reads mid and rejects a tag longer than 16 characters")
        void mid() {
            assertEquals("audio", parse("mid:audio", SdpAttribute.Mid.class).id());
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("mid:12345678901234567"));
        }

        @Test
        @DisplayName("reads BUNDLE and other groups (RFC 8843 section 7)")
        void group() {
            var bundle = parse("group:BUNDLE foo bar", SdpAttribute.Group.class);
            assertTrue(bundle.isBundle());
            assertEquals(List.of("foo", "bar"), bundle.mids());
            assertFalse(parse("group:LS 1 2", SdpAttribute.Group.class).isBundle());
            assertEquals(List.of(), parse("group:BUNDLE", SdpAttribute.Group.class).mids());
        }
    }

    @Nested
    @DisplayName("simulcast")
    class Simulcast {
        @Test
        @DisplayName("reads rid with payload types and restrictions (RFC 8851 section 4)")
        void rid() {
            var rid = parse("rid:5 send pt=99,102;max-br=64000;max-width=1280;max-height=720;max-fps=30",
                    SdpAttribute.Rid.class);
            assertEquals("5", rid.id());
            assertEquals(SdpAttribute.Rid.Direction.SEND, rid.direction());
            assertEquals(List.of(99, 102), rid.payloadTypes());
            assertEquals("1280", rid.restrictions().get("max-width"));
            var bare = parse("rid:hi recv", SdpAttribute.Rid.class);
            assertEquals(List.of(), bare.payloadTypes());
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("rid:a.b send"));
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("rid:a both"));
        }

        @Test
        @DisplayName("reads the simulcast example of RFC 8853 section 5.1")
        void simulcast() {
            var simulcast = parse("simulcast:send 1;~4;2,3 recv c", SdpAttribute.Simulcast.class);
            assertEquals(3, simulcast.send().size());
            assertTrue(simulcast.send().get(1).getFirst().paused());
            assertEquals(List.of(new SdpAttribute.Simulcast.Stream("2", false),
                    new SdpAttribute.Simulcast.Stream("3", false)), simulcast.send().get(2));
            assertEquals("c", simulcast.receive().getFirst().getFirst().rid());
        }

        @Test
        @DisplayName("reads a receive-only simulcast and rejects one without streams or with a repeated direction")
        void simulcastShapes() {
            var receive = parse("simulcast:recv a;b", SdpAttribute.Simulcast.class);
            assertEquals(List.of(), receive.send());
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("simulcast:send"));
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("simulcast:send a send b"));
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("simulcast:send a;;b"));
        }
    }

    @Nested
    @DisplayName("ICE and DTLS")
    class Transport {
        @Test
        @DisplayName("reads the ICE credentials, options and lite flag (RFC 8839 section 5)")
        void ice() {
            assertEquals("8hhY", parse("ice-ufrag:8hhY", SdpAttribute.IceUfrag.class).ufrag());
            var pwd = parse("ice-pwd:asd88fgpdd777uzjYhagZg", SdpAttribute.IcePwd.class);
            assertEquals("asd88fgpdd777uzjYhagZg", pwd.password());
            assertFalse(pwd.toString().contains("asd88"), "the password is redacted");
            assertEquals(List.of("trickle", "ice2"), parse("ice-options:trickle ice2",
                    SdpAttribute.IceOptions.class).options());
            parse("ice-lite", SdpAttribute.IceLite.class);
        }

        @Test
        @DisplayName("keeps a candidate verbatim and reads end-of-candidates (RFC 8840)")
        void candidate() {
            var candidate = parse("candidate:1 1 UDP 2130706431 10.0.1.1 8998 typ host", SdpAttribute.Candidate.class);
            assertEquals("1 1 UDP 2130706431 10.0.1.1 8998 typ host", candidate.value());
            parse("end-of-candidates", SdpAttribute.EndOfCandidates.class);
        }

        @Test
        @DisplayName("normalises the fingerprint case and decodes its digest (RFC 8122 section 5)")
        void fingerprint() {
            var fingerprint = SdpAttribute.parse("fingerprint:SHA-256 d2:fa:0e");
            var typed = assertInstanceOf(SdpAttribute.Fingerprint.class, fingerprint);
            assertEquals("sha-256", typed.hashFunction());
            assertEquals("D2:FA:0E", typed.fingerprint());
            assertArrayEquals(new byte[]{(byte) 0xD2, (byte) 0xFA, 0x0E}, typed.digest());
            assertEquals(typed, SdpAttribute.Fingerprint.of("sha-256", new byte[]{(byte) 0xD2, (byte) 0xFA, 0x0E}));
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("fingerprint:sha-256 ZZ:00"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"active", "passive", "actpass", "holdconn"})
        @DisplayName("reads every setup role (RFC 4145, RFC 8842)")
        void setup(String role) {
            assertEquals(role, parse("setup:" + role, SdpAttribute.Setup.class).role().sdpName());
        }

        @Test
        @DisplayName("reads tls-id, rtcp-mux, rtcp-mux-only, rtcp-rsize and rtcp")
        void misc() {
            parse("tls-id:abc3de65cddef001be82", SdpAttribute.TlsId.class);
            parse("rtcp-mux", SdpAttribute.RtcpMux.class);
            parse("rtcp-mux-only", SdpAttribute.RtcpMuxOnly.class);
            parse("rtcp-rsize", SdpAttribute.RtcpRsize.class);
            var rtcp = parse("rtcp:9 IN IP4 0.0.0.0", SdpAttribute.Rtcp.class);
            assertEquals(9, rtcp.port());
            assertEquals(Optional.of("IN IP4 0.0.0.0"), rtcp.connection());
        }
    }

    @Nested
    @DisplayName("data channels, SDES and the rest")
    class Others {
        @Test
        @DisplayName("reads sctp-port and max-message-size (RFC 8841 sections 5 and 6)")
        void sctp() {
            assertEquals(5000, parse("sctp-port:5000", SdpAttribute.SctpPort.class).port());
            assertEquals(262144, parse("max-message-size:262144", SdpAttribute.MaxMessageSize.class).size());
            assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("sctp-port:0"));
        }

        @Test
        @DisplayName("reads an SDES crypto line (RFC 4568 section 9.1) and cryptex (RFC 9335)")
        void crypto() {
            var crypto = SdpAttribute.parse("crypto:1 AES_CM_128_HMAC_SHA1_80 "
                    + "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32");
            var typed = assertInstanceOf(SdpAttribute.Crypto.class, crypto);
            assertEquals(1, typed.crypto().tag());
            assertEquals(30, typed.crypto().keySalt().length);
            parse("cryptex", SdpAttribute.Cryptex.class);
        }

        @ParameterizedTest
        @ValueSource(strings = {"sendrecv", "sendonly", "recvonly", "inactive"})
        @DisplayName("reads the direction attributes")
        void direction(String name) {
            assertEquals(name, parse(name, SdpAttribute.Direction.class).direction().sdpName());
        }

        @Test
        @DisplayName("reads bundle-only, ptime and maxptime")
        void bundleOnlyAndPtime() {
            parse("bundle-only", SdpAttribute.BundleOnly.class);
            assertEquals(20, parse("ptime:20", SdpAttribute.Ptime.class).milliseconds());
            assertEquals(120, parse("maxptime:120", SdpAttribute.MaxPtime.class).milliseconds());
        }

        @Test
        @DisplayName("keeps an unknown attribute as Other and a malformed known one as Invalid")
        void unknownAndInvalid() {
            var other = parse("x-google-flag:conference", SdpAttribute.Other.class);
            assertEquals("x-google-flag", other.name());
            parse("msid-semantic: WMS *", SdpAttribute.Other.class);
            var invalid = assertInstanceOf(SdpAttribute.Invalid.class, SdpAttribute.parse("sctp-port:abc"));
            assertEquals("sctp-port", invalid.name());
            assertEquals("a=sctp-port:abc", invalid.toLine().toString());
        }

        @Test
        @DisplayName("refuses to parse a line that is not an attribute")
        void notAnAttribute() {
            assertThrows(IllegalArgumentException.class, () -> SdpAttribute.parse(new SdpLine('m', "audio 9 x 0")));
        }
    }
}
