package com.github.auties00.parley.rtp.rtcp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers every RTCP packet type against hand-encoded wire vectors built from the RFC figures, compound and
/// reduced-size parsing, and a fuzz pass that checks parsing either fails cleanly or normalizes idempotently.
@DisplayName("RTCP packets")
class RtcpPacketTest {
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] encode(RtcpPacket packet) {
        var buffer = RtcpPacket.encodeCompound(List.of(packet), 0);
        var out = new byte[buffer.remaining()];
        buffer.get(out);
        return out;
    }

    private static RtcpPacket single(String hex) throws RtcpFormatException {
        var packets = RtcpPacket.parseCompound(ByteBuffer.wrap(HEX.parseHex(hex)));
        assertEquals(1, packets.size());
        return packets.getFirst();
    }

    private static void assertVector(String hex, RtcpPacket packet) throws RtcpFormatException {
        assertEquals(hex, HEX.formatHex(encode(packet)));
        assertEquals(packet, single(hex));
        assertEquals(hex.length() / 2, packet.encodedLength());
    }

    @Nested
    @DisplayName("RFC 3550 packets")
    class Rfc3550 {
        @Test
        @DisplayName("encodes a sender report with a reception block")
        void senderReport() throws RtcpFormatException {
            var block = new ReceptionReport(2, 0x40, -3, 0x00010005L, 17, 0xAABBCCDDL, 0x00008000L);
            assertVector("81c8000c" + "00000001" + "0102030405060708" + "00000960" + "0000000a" + "00000064"
                            + "00000002" + "40fffffd" + "00010005" + "00000011" + "aabbccdd" + "00008000",
                    new SenderReport(1, 0x0102030405060708L, 2400, 10, 100, List.of(block)));
        }

        @Test
        @DisplayName("encodes an empty receiver report")
        void receiverReport() throws RtcpFormatException {
            assertVector("80c90001" + "00000007", new ReceiverReport(7, List.of()));
        }

        @Test
        @DisplayName("encodes a CNAME chunk padded to a word boundary")
        void sdes() throws RtcpFormatException {
            assertVector("81ca0003" + "00000001" + "01036162" + "63000000", SourceDescription.ofCname(1, "abc"));
        }

        @Test
        @DisplayName("keeps RtpStreamId, RepairedRtpStreamId and MID items")
        void sdesItems() throws RtcpFormatException {
            var description = new SourceDescription(List.of(new SourceDescription.Chunk(9, List.of(
                    SourceDescription.Item.cname("c"), SourceDescription.Item.rtpStreamId("hi"),
                    SourceDescription.Item.repairedRtpStreamId("lo"), SourceDescription.Item.mid("0")))));
            var parsed = (SourceDescription) single(HEX.formatHex(encode(description)));
            assertEquals(description, parsed);
            assertEquals("hi", parsed.chunks().getFirst().find(SourceDescription.Item.RTP_STREAM_ID).orElseThrow());
            assertEquals("0", parsed.chunks().getFirst().find(SourceDescription.Item.MID).orElseThrow());
        }

        @Test
        @DisplayName("encodes a goodbye with a reason")
        void bye() throws RtcpFormatException {
            assertVector("81cb0002" + "00000001" + "01780000", new Bye(List.of(1L), Optional.of("x")));
            assertVector("80cb0000", new Bye(List.of(), Optional.empty()));
        }

        @Test
        @DisplayName("encodes application data")
        void app() throws RtcpFormatException {
            assertVector("83cc0003" + "00000001" + "54455354" + "01020304",
                    new App(3, 1, "TEST", ByteBuffer.wrap(new byte[]{1, 2, 3, 4})));
        }

        @Test
        @DisplayName("encodes an extended report with RRTR and DLRR blocks")
        void extendedReport() throws RtcpFormatException {
            assertVector("80cf0004" + "00000001" + "04000002" + "0102030405060708",
                    new ExtendedReport(1, List.of(new ExtendedReport.ReceiverReferenceTime(0x0102030405060708L))));
            var report = new ExtendedReport(1, List.of(
                    new ExtendedReport.Dlrr(List.of(new ExtendedReport.DlrrEntry(2, 3, 4))),
                    new ExtendedReport.UnknownBlock(42, 7, ByteBuffer.wrap(new byte[]{9, 9, 9, 9}))));
            assertVector("80cf0007" + "00000001" + "05000003" + "000000020000000300000004" + "2a070001" + "09090909",
                    report);
        }
    }

    @Nested
    @DisplayName("feedback messages")
    class Feedback {
        @Test
        @DisplayName("packs a generic NACK into PID and BLP pairs (RFC 4585 section 6.2.1)")
        void nack() throws RtcpFormatException {
            var nack = new Nack(1, 2, List.of(100, 101, 116, 117));
            assertEquals("81cd0004" + "00000001" + "00000002" + "00648001" + "00750000", HEX.formatHex(encode(nack)));
            assertEquals(nack, single("81cd0004" + "00000001" + "00000002" + "00648001" + "00750000"));
        }

        @Test
        @DisplayName("packs NACKs across the sequence number wrap")
        void nackWrap() throws RtcpFormatException {
            var nack = new Nack(1, 2, List.of(65535, 0, 1));
            assertEquals("81cd0003" + "00000001" + "00000002" + "ffff0003", HEX.formatHex(encode(nack)));
        }

        @Test
        @DisplayName("encodes a picture loss indication (RFC 4585 section 6.3.1)")
        void pli() throws RtcpFormatException {
            assertVector("81ce0002" + "00000001" + "00000002", new PictureLossIndication(1, 2));
        }

        @Test
        @DisplayName("encodes a full intra request (RFC 5104 section 4.3.1)")
        void fir() throws RtcpFormatException {
            assertVector("84ce0004" + "00000001" + "00000000" + "00000002" + "05000000",
                    new FullIntraRequest(1, List.of(new FullIntraRequest.Entry(2, 5))));
        }

        @Test
        @DisplayName("encodes a REMB with its mantissa and exponent")
        void remb() throws RtcpFormatException {
            assertVector("8fce0005" + "00000001" + "00000000" + "52454d42" + "010bd090" + "00000011",
                    new Remb(1, 1_000_000, List.of(0x11L)));
        }

        @Test
        @DisplayName("rounds an unrepresentable REMB bitrate down to its 18 leading bits")
        void rembRounding() throws RtcpFormatException {
            var parsed = (Remb) single(HEX.formatHex(encode(new Remb(1, 1_000_001, List.of()))));
            assertEquals(1_000_000, parsed.bitrateBps());
        }

        @Test
        @DisplayName("keeps unmodelled feedback formats as unknown packets")
        void unknownFeedback() throws RtcpFormatException {
            var sli = "82ce0003" + "00000001" + "00000002" + "12345678";
            var packet = assertInstanceOf(UnknownRtcp.class, single(sli));
            assertEquals(2, packet.count());
            assertEquals(sli, HEX.formatHex(encode(packet)));
            var afb = assertInstanceOf(UnknownRtcp.class, single("8fce0003" + "00000001" + "00000000" + "41424344"));
            assertEquals(15, afb.count());
        }
    }

    @Nested
    @DisplayName("transport-wide feedback")
    class Twcc {
        @Test
        @DisplayName("encodes the 1-bit status vector example of the draft with small deltas and padding")
        void statusVectorExample() throws RtcpFormatException {
            var results = new ArrayList<TransportFeedback.PacketResult>();
            var pattern = new int[]{0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0};
            var delta = 0;
            for (var i = 0; i < pattern.length; i++) {
                results.add(pattern[i] == 0 ? TransportFeedback.PacketResult.lost(i)
                        : TransportFeedback.PacketResult.received(i, 250L * ++delta));
            }
            var feedback = new TransportFeedback(1, 2, 0, 0x000102, 3, results);
            var hex = "afcd0007" + "00000001" + "00000002" + "0000000e" + "00010203" + "9f1c"
                    + "0102030405060708" + "0002";
            assertEquals(hex, HEX.formatHex(encode(feedback)));
            assertEquals(feedback, single(hex));
        }

        @Test
        @DisplayName("uses a run-length chunk for a long run of equal statuses")
        void runLength() throws RtcpFormatException {
            var results = new ArrayList<TransportFeedback.PacketResult>();
            for (var i = 0; i < 221; i++) {
                results.add(TransportFeedback.PacketResult.received((65500 + i) & 0xFFFF, 250));
            }
            var feedback = new TransportFeedback(1, 2, 65500, 0, 0, results);
            var bytes = encode(feedback);
            assertEquals(0x20DD, ByteBuffer.wrap(bytes).getShort(20) & 0xFFFF);
            assertEquals(feedback, single(HEX.formatHex(bytes)));
        }

        @Test
        @DisplayName("uses 2-bit vectors for large and negative deltas")
        void largeDeltas() throws RtcpFormatException {
            var results = List.of(TransportFeedback.PacketResult.received(10, 250_000),
                    TransportFeedback.PacketResult.received(11, -250),
                    TransportFeedback.PacketResult.lost(12),
                    TransportFeedback.PacketResult.received(13, 0));
            var feedback = new TransportFeedback(1, 2, 10, -5, 255, results);
            var bytes = encode(feedback);
            assertEquals(0xE000 | 2 << 12 | 2 << 10 | 0 << 8 | 1 << 6, ByteBuffer.wrap(bytes).getShort(20) & 0xFFFF);
            var parsed = (TransportFeedback) single(HEX.formatHex(bytes));
            assertEquals(feedback, parsed);
            assertEquals(-5, parsed.referenceTime64ms());
            assertEquals(List.of(OptionalLong.of(-320_000 + 250_000), OptionalLong.of(-320_000 + 249_750),
                    OptionalLong.empty(), OptionalLong.of(-320_000 + 249_750)), parsed.receiveTimesMicros());
        }

        @Test
        @DisplayName("rejects results that are not consecutive or deltas beyond 16 bits")
        void validation() {
            assertThrows(IllegalArgumentException.class, () -> new TransportFeedback(1, 2, 0, 0, 0,
                    List.of(TransportFeedback.PacketResult.lost(1))));
            assertThrows(IllegalArgumentException.class, () -> new TransportFeedback(1, 2, 0, 0, 0,
                    List.of(TransportFeedback.PacketResult.received(0, 250L * 40_000))));
        }

        @RepeatedTest(30)
        @DisplayName("round-trips random feedback")
        void randomRoundTrip() throws RtcpFormatException {
            var random = new Random();
            var base = random.nextInt(65536);
            var results = new ArrayList<TransportFeedback.PacketResult>();
            for (var i = random.nextInt(1, 300); i > 0; i--) {
                var sequence = (base + results.size()) & 0xFFFF;
                results.add(switch (random.nextInt(4)) {
                    case 0 -> TransportFeedback.PacketResult.lost(sequence);
                    case 1 -> TransportFeedback.PacketResult.received(sequence, 250L * random.nextInt(-32768, 32768));
                    default -> TransportFeedback.PacketResult.received(sequence, 250L * random.nextInt(256));
                });
            }
            var feedback = new TransportFeedback(random.nextLong(1L << 32), random.nextLong(1L << 32), base,
                    random.nextLong(1 << 24), random.nextInt(256), results);
            var bytes = encode(feedback);
            assertEquals(0, bytes.length % 4);
            var parsed = (TransportFeedback) single(HEX.formatHex(bytes));
            assertEquals(feedback.results(), parsed.results());
        }
    }

    @Test
    @DisplayName("round-trips RFC 8888 congestion control feedback with odd metric counts")
    void ccfb() throws RtcpFormatException {
        var feedback = new CongestionControlFeedback(1, List.of(
                new CongestionControlFeedback.StreamReport(2, 65535, List.of(
                        new CongestionControlFeedback.Metric(true, 1, 100), CongestionControlFeedback.Metric.lost(),
                        new CongestionControlFeedback.Metric(true, 0, CongestionControlFeedback.Metric.OVER_RANGE))),
                new CongestionControlFeedback.StreamReport(3, 0, List.of())), 0x12345678L);
        assertVector("8bcd0008" + "00000001" + "00000002" + "ffff0003" + "a0640000" + "9ffe0000" + "00000003"
                + "00000000" + "12345678", feedback);
    }

    @Nested
    @DisplayName("compound packets")
    class Compound {
        @Test
        @DisplayName("parses a compound report, description and feedback in order")
        void compound() throws RtcpFormatException {
            var packets = List.of(new ReceiverReport(1, List.of()), SourceDescription.ofCname(1, "parley"),
                    new PictureLossIndication(1, 2), new Nack(1, 2, List.of(7)));
            var parsed = RtcpPacket.parseCompound(RtcpPacket.encodeCompound(packets, 16));
            assertEquals(packets, parsed);
        }

        @Test
        @DisplayName("leaves the requested tailroom after the limit")
        void tailroom() {
            var buffer = RtcpPacket.encodeCompound(List.of(new ReceiverReport(1, List.of())), 14);
            assertEquals(8, buffer.limit());
            assertEquals(22, buffer.capacity());
        }

        @Test
        @DisplayName("strips padding signaled by the P bit")
        void padding() throws RtcpFormatException {
            var packet = assertInstanceOf(App.class, single("a3cc0004" + "00000001" + "54455354" + "01020304"
                    + "00000004"));
            assertArrayEquals(new byte[]{1, 2, 3, 4}, RtpBytes.of(packet.data()));
        }

        @Test
        @DisplayName("rejects malformed packets")
        void malformed() {
            for (var hex : List.of("", "80c9", "40c90001" + "00000001", "80c90002" + "00000001",
                    "81c90001" + "00000001", "a0c90001" + "00000000", "81cd0002" + "00000001" + "00000002",
                    "81ca0001" + "00000001", "80cf0002" + "00000001" + "04000003")) {
                assertThrows(RtcpFormatException.class,
                        () -> RtcpPacket.parseCompound(ByteBuffer.wrap(HEX.parseHex(hex))), hex);
            }
        }

        @RepeatedTest(20)
        @DisplayName("either rejects random bytes or normalizes them idempotently")
        void fuzz() throws RtcpFormatException {
            var random = new Random();
            for (var i = 0; i < 2_000; i++) {
                var data = new byte[4 * random.nextInt(1, 16)];
                random.nextBytes(data);
                data[0] = (byte) (0x80 | data[0] & 0x1F);
                data[1] = (byte) (195 + random.nextInt(14));
                data[2] = 0;
                data[3] = (byte) (data.length / 4 - 1);
                List<RtcpPacket> parsed;
                try {
                    parsed = RtcpPacket.parseCompound(ByteBuffer.wrap(data));
                } catch (RtcpFormatException expected) {
                    continue;
                }
                if (parsed.stream().anyMatch(p -> p instanceof Remb r && r.bitrateBps() == Long.MAX_VALUE)) {
                    continue;
                }
                var once = RtcpPacket.parseCompound(RtcpPacket.encodeCompound(parsed, 0));
                var twice = RtcpPacket.parseCompound(RtcpPacket.encodeCompound(once, 0));
                assertEquals(once, twice);
                assertTrue(RtcpPacket.encodeCompound(once, 0).remaining() % 4 == 0);
            }
        }
    }

    /// Copies a buffer's remaining bytes.
    static final class RtpBytes {
        static byte[] of(ByteBuffer buffer) {
            var out = new byte[buffer.remaining()];
            buffer.duplicate().get(out);
            return out;
        }
    }
}
