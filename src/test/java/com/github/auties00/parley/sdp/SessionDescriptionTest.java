package com.github.auties00.parley.sdp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Parses and re-encodes session descriptions shaped like those of a production `ice-lite` WebRTC gateway and of an
/// SDES SIP trunk; the ICE password, fingerprint and crypto key are made-up values and the addresses come from the
/// RFC 5737 documentation ranges.
@DisplayName("SessionDescription")
class SessionDescriptionTest {
    static final String LITE_WEBRTC_OFFER = String.join("\r\n",
            "v=0",
            "o=- 1724450587406497 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0",
            "a=ice-lite",
            "m=audio 3480 UDP/TLS/RTP/SAVPF 111 126",
            "c=IN IP4 203.0.113.35",
            "a=rtcp:9 IN IP4 0.0.0.0",
            "a=candidate:1775469887 1 udp 2122260223 203.0.113.35 3480 typ host generation 0 network-cost 50",
            "a=ice-ufrag:RmDDkfzkwbexPfbC",
            "a=ice-pwd:Ry1bC3ZkAgaJ3JGNgL3K8z3e",
            "a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3E:5C:7B:3E:1F:2C:8B:4E:5A:6D:7C:8B",
            "a=setup:actpass",
            "a=mid:0",
            "a=sendrecv",
            "a=rtcp-mux",
            "a=rtpmap:111 opus/48000/2",
            "a=fmtp:111 minptime=10;useinbandfec=1",
            "a=rtpmap:126 telephone-event/8000",
            "");

    static final String SDES_OFFER = String.join("\r\n",
            "v=0",
            "o=- 1724450587406497 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "m=audio 3480 RTP/SAVP 111 126",
            "c=IN IP4 203.0.113.35",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + Base64.getEncoder().encodeToString(new byte[30]) + "|2^31",
            "a=rtcp-mux",
            "a=rtpmap:111 opus/48000/2",
            "a=rtpmap:126 telephone-event/8000",
            "");

    @Nested
    @DisplayName("parse")
    class Parse {
        @Test
        @DisplayName("reads the session and media attributes of an ice-lite WebRTC offer")
        void webrtcOffer() throws SdpFormatException {
            var description = SessionDescription.parse(LITE_WEBRTC_OFFER);
            var audio = description.firstMedia("audio").orElseThrow();
            assertEquals(3480, audio.port());
            assertEquals("UDP/TLS/RTP/SAVPF", audio.protocol());
            assertEquals("", description.attribute("ice-lite").orElseThrow());
            assertEquals("RmDDkfzkwbexPfbC", description.attribute(audio, "ice-ufrag").orElseThrow());
            assertEquals("203.0.113.35", description.connectionAddress(audio).orElseThrow());
            var codecs = RtpCodec.of(audio);
            assertEquals(2, codecs.size());
            assertTrue(codecs.getFirst().is("OPUS"));
            assertEquals(java.util.OptionalInt.of(2), codecs.getFirst().channels());
            assertEquals("minptime=10;useinbandfec=1", codecs.getFirst().fmtpValue().orElseThrow());
            assertEquals(java.util.Map.of("minptime", "10", "useinbandfec", "1"),
                    codecs.getFirst().formatParameters());
            assertEquals(8000, codecs.get(1).clockRate());
        }

        @Test
        @DisplayName("round trips to the same text")
        void roundTrip() throws SdpFormatException {
            assertEquals(LITE_WEBRTC_OFFER, SessionDescription.parse(LITE_WEBRTC_OFFER).encode());
        }

        @Test
        @DisplayName("accepts bare LF line endings")
        void bareLineFeeds() throws SdpFormatException {
            var description = SessionDescription.parse(SDES_OFFER.replace("\r\n", "\n"));
            assertEquals("RTP/SAVP", description.media().getFirst().protocol());
        }

        @Test
        @DisplayName("resolves the static payload types of PCMU and PCMA without an rtpmap")
        void staticPayloadTypes() throws SdpFormatException {
            var description = SessionDescription.parse("v=0\r\nm=audio 4000 RTP/AVP 0 8\r\n");
            var codecs = RtpCodec.of(description.media().getFirst());
            assertEquals("PCMU", codecs.get(0).name());
            assertEquals("PCMA", codecs.get(1).name());
        }

        @Test
        @DisplayName("rejects a line without a type prefix")
        void malformed() {
            assertThrows(SdpFormatException.class, () -> SessionDescription.parse("v=0\r\nnonsense\r\n"));
        }
    }

    @Nested
    @DisplayName("SdesCrypto")
    class Crypto {
        @Test
        @DisplayName("parses the inline key and ignores the lifetime")
        void parse() throws SdpFormatException {
            var description = SessionDescription.parse(SDES_OFFER);
            var crypto = SdesCrypto.parse(description.media().getFirst().attribute("crypto").orElseThrow());
            assertEquals(1, crypto.tag());
            assertEquals("AES_CM_128_HMAC_SHA1_80", crypto.suite());
            assertEquals(30, crypto.keySalt().length);
        }

        @Test
        @DisplayName("generates a key that survives formatting and parsing")
        void generate() {
            var crypto = SdesCrypto.generate(2, "AES_CM_128_HMAC_SHA1_80", 16, 14);
            var parsed = SdesCrypto.parse(crypto.value());
            assertArrayEquals(crypto.keySalt(), parsed.keySalt());
            assertArrayEquals(crypto.masterKey(16), parsed.masterKey(16));
            assertEquals(14, parsed.masterSalt(16, 14).length);
        }
    }
}
