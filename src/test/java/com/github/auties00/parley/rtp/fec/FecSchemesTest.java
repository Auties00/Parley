package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the mask types of mask encoders and the RFC 8627 row and column (`F=1`) and retransmission (`R=1`)
/// schemes, encoder against decoder, with a fuzz pass over the new header forms.
@DisplayName("FEC schemes")
class FecSchemesTest {
    private static final long SSRC = 0x55667788L;

    static RtpPacket media(int sequence) throws RtpFormatException {
        var payload = new byte[20 + sequence % 7];
        new Random(sequence).nextBytes(payload);
        return RtpPacket.parse(RtpPacketWriter.into(ByteBuffer.allocate(128)).payloadType(96).ssrc(SSRC)
                .sequence(sequence).timestamp(3000L * (sequence / 4)).marker(sequence % 4 == 3)
                .payload(ByteBuffer.wrap(payload)).finish());
    }

    /// Feeds every media packet but the lost ones and every repair payload to a decoder; returns the sequence numbers
    /// it ends up holding.
    static Set<Integer> recover(FecFormat format, List<RtpPacket> packets, List<ByteBuffer> repairs, Set<Integer> lost)
            throws RtpFormatException {
        var decoder = new FecDecoder(format, SSRC);
        var held = new java.util.TreeSet<Integer>();
        for (var packet : packets) {
            if (!lost.contains(packet.sequence())) {
                decoder.addMedia(packet);
                held.add(packet.sequence());
            }
        }
        for (var repair : repairs) {
            for (var recovered : decoder.addFec(repair)) {
                held.add(recovered.sequence());
                assertEquals(packets.get(recovered.sequence() - packets.getFirst().sequence()).buffer(),
                        recovered.buffer(), "recovered packet differs");
            }
        }
        return held;
    }

    @Test
    @DisplayName("random-loss masks recover two scattered losses that interleaved masks cannot")
    void maskTypes() throws Exception {
        var packets = new ArrayList<RtpPacket>();
        for (var sequence = 100; sequence < 108; sequence++) {
            packets.add(media(sequence));
        }
        var lost = Set.of(100, 104);
        for (var type : FecMaskType.values()) {
            var encoder = FecEncoder.create(FecFormat.ULPFEC, SSRC, 50);
            encoder.setMaskType(type);
            packets.forEach(encoder::add);
            var held = recover(FecFormat.ULPFEC, packets, encoder.flush(), lost);
            assertEquals(type == FecMaskType.RANDOM, held.size() == 8, type + " held " + held);
        }
    }

    @Test
    @DisplayName("bursty masks protect consecutive packets with different payloads")
    void burstyMask() {
        var encoder = FecEncoder.create(FecFormat.FLEXFEC, SSRC, 50);
        encoder.setMaskType(FecMaskType.BURSTY);
        for (var i = 0; i < 7; i++) {
            assertFalse(encoder.protects(0, i, 4, 8) && encoder.protects(0, i + 1, 4, 8));
        }
    }

    @Test
    @DisplayName("1-D row FEC (L=5, D=0) recovers one loss per row")
    void rows() throws Exception {
        var encoder = FecEncoder.rowColumn(SSRC, 5, 0, true);
        var packets = new ArrayList<RtpPacket>();
        for (var sequence = 0; sequence < 15; sequence++) {
            packets.add(media(sequence));
            encoder.add(packets.getLast());
        }
        var repairs = encoder.flush();
        assertEquals(3, repairs.size());
        assertEquals(0x40, repairs.getFirst().get(0) & 0xC0, "F=1, R=0");
        assertEquals(5, repairs.getFirst().get(10) & 0xFF, "L");
        assertEquals(0, repairs.getFirst().get(11) & 0xFF, "D");
        assertEquals(15, recover(FecFormat.FLEXFEC, packets, repairs, Set.of(2, 6, 14)).size());
    }

    @Test
    @DisplayName("2-D FEC (L=4, D=3) recovers a burst of two inside one row through the columns")
    void rowsAndColumns() throws Exception {
        var encoder = FecEncoder.rowColumn(SSRC, 4, 3, true);
        var packets = new ArrayList<RtpPacket>();
        for (var sequence = 0; sequence < 12; sequence++) {
            packets.add(media(sequence));
            encoder.add(packets.getLast());
        }
        var repairs = encoder.flush();
        assertEquals(7, repairs.size(), "three rows and four columns");
        assertEquals(12, recover(FecFormat.FLEXFEC, packets, repairs, Set.of(5, 6)).size());
    }

    @Test
    @DisplayName("restarts the block after a gap in the media sequence")
    void gap() throws Exception {
        var encoder = FecEncoder.rowColumn(SSRC, 3, 0, true);
        encoder.add(media(0));
        encoder.add(media(1));
        encoder.add(media(5));
        encoder.add(media(6));
        encoder.add(media(7));
        var repairs = encoder.flush();
        assertEquals(1, repairs.size());
        assertEquals(5, repairs.getFirst().getShort(8) & 0xFFFF, "SN base of the new block");
    }

    @Test
    @DisplayName("retransmission payloads (R=1) rebuild the packet they repeat, the marker packet first")
    void retransmission() throws Exception {
        var encoder = FecEncoder.retransmission(SSRC, 25);
        var packets = new ArrayList<RtpPacket>();
        for (var sequence = 0; sequence < 4; sequence++) {
            packets.add(media(sequence));
            encoder.add(packets.getLast());
        }
        var repairs = encoder.flush();
        assertEquals(1, repairs.size());
        assertEquals(0x80, repairs.getFirst().get(0) & 0xC0, "R=1, F=0");
        assertEquals(3, repairs.getFirst().getShort(2) & 0xFFFF, "the marker packet is repeated");
        assertEquals(4, recover(FecFormat.FLEXFEC, packets, repairs, Set.of(3)).size());
    }

    @ParameterizedTest
    @EnumSource(value = FecFormat.class, names = {"FLEXFEC", "FLEXFEC_03"})
    @DisplayName("decodes random repair payloads with RtpFormatException as the only failure")
    void fuzz(FecFormat format) throws Exception {
        var random = new Random(0xFEC);
        var decoder = new FecDecoder(format, SSRC);
        for (var sequence = 0; sequence < 20; sequence++) {
            decoder.addMedia(media(sequence));
        }
        for (var i = 0; i < 20_000; i++) {
            var bytes = new byte[random.nextInt(64)];
            random.nextBytes(bytes);
            if (bytes.length > 0 && random.nextBoolean()) {
                bytes[0] = (byte) (random.nextBoolean() ? 0x40 : 0x80);
            }
            try {
                decoder.addFec(ByteBuffer.wrap(bytes));
            } catch (RtpFormatException expected) {
                // malformed repair payloads fail this way only
            }
        }
        assertTrue(decoder.recoveredCount() >= 0);
    }
}
