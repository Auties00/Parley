package com.github.auties00.parley.rtp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the RTP header codec, the RTCP report builder, G.711 companding and RFC 4733 events.
@DisplayName("RTP coding")
class RtpCodingTest {
    @Test
    @DisplayName("encodes and decodes an RTP packet with tailroom")
    void rtpRoundTrip() {
        var packet = new RtpPacket(111, true, 65535, 0xFFFFFFF0L, 0xDEADBEEFL, new byte[]{1, 2, 3});
        var encoded = packet.encode(10);
        assertEquals(15 + 10, encoded.length);
        var decoded = RtpPacket.decode(encoded, 0, packet.length());
        assertEquals(111, decoded.payloadType());
        assertTrue(decoded.marker());
        assertEquals(65535, decoded.sequence());
        assertEquals(0xFFFFFFF0L, decoded.timestamp());
        assertEquals(0xDEADBEEFL, decoded.ssrc());
        assertArrayEquals(new byte[]{1, 2, 3}, decoded.payload());
        assertFalse(RtpPacket.isRtcp(encoded, 0, packet.length()));
    }

    @Test
    @DisplayName("builds a compound sender report with a CNAME the demultiplexer recognises as RTCP")
    void senderReport() {
        var report = RtcpPackets.senderReport(1, 1_700_000_000_000L, 960, 50, 4000,
                new RtcpPackets.ReceptionReport(2, 0, 0, 100, 0), "parley", 20);
        var length = RtcpPackets.compoundLength(report);
        assertEquals(report.length - 20, length);
        assertEquals(0, length % 4);
        assertTrue(RtpPacket.isRtcp(report, 0, length));
        assertEquals(200, report[1] & 0xFF);
    }

    @Nested
    @DisplayName("G.711")
    class G711Coding {
        @ParameterizedTest
        @ValueSource(shorts = {0, 1, -1, 100, -100, 1000, -1000, 12345, -12345, 32767, -32768})
        @DisplayName("A-law keeps samples within its quantisation step")
        void aLaw(short sample) {
            var decoded = G711.aLawToLinear(G711.linearToALaw(sample));
            assertTrue(Math.abs(decoded - sample) <= Math.max(16, Math.abs(sample) / 16), sample + " -> " + decoded);
        }

        @ParameterizedTest
        @ValueSource(shorts = {0, 1, -1, 100, -100, 1000, -1000, 12345, -12345, 32767, -32768})
        @DisplayName("mu-law keeps samples within its quantisation step")
        void muLaw(short sample) {
            var decoded = G711.muLawToLinear(G711.linearToMuLaw(sample));
            assertTrue(Math.abs(decoded - sample) <= Math.max(16, Math.abs(sample) / 16), sample + " -> " + decoded);
        }

        @Test
        @DisplayName("maps silence to the reference codes")
        void silence() {
            assertEquals((byte) 0xD5, G711.linearToALaw((short) 0));
            assertEquals((byte) 0xFF, G711.linearToMuLaw((short) 0));
        }
    }

    @Test
    @DisplayName("encodes and decodes telephone events and maps DTMF symbols")
    void telephoneEvent() {
        var event = new TelephoneEvent(TelephoneEvent.eventOf('#').orElseThrow(), true, 10, 800);
        var decoded = TelephoneEvent.decode(event.encode());
        assertEquals(event, decoded);
        assertEquals('#', decoded.symbol().orElseThrow());
        assertEquals(12, TelephoneEvent.eventOf('a').orElseThrow());
        assertTrue(TelephoneEvent.eventOf('x').isEmpty());
    }
}
