package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.H265FrameMetadata;
import com.github.auties00.parley.rtp.RtpPacket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static com.github.auties00.parley.payload.TestPackets.packet;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the RFC 7798 packets the H.265 depacketizer accepts beyond the basic ones: decoding order numbers in single
/// NAL unit, aggregation and fragmentation packets (`sprop-max-don-diff` above zero), and PACI packets.
@DisplayName("H.265 decoding order numbers and PACI")
class H265DecodingOrderTest {
    /// A format whose stream carries decoding order numbers.
    private static final H265Format DON = new H265Format(Codec.h265().withFormatParameters(
            Map.of("sprop-max-don-diff", "4")));

    /// The format without them.
    private static final H265Format PLAIN = new H265Format(Codec.h265());

    /// A VPS, an SPS and a PPS with a byte of data each, and an IDR slice starting a picture.
    private static final byte[] VPS = {0x40, 0x01, 0x0C};
    private static final byte[] SPS = {0x42, 0x01, 0x01};
    private static final byte[] PPS = {0x44, 0x01, (byte) 0xC1};
    private static final byte[] IDR = {0x26, 0x01, (byte) 0x80, 0x11, 0x22, 0x33};

    /// {@return the concatenation of byte arrays}
    private static byte[] concat(byte[]... parts) {
        var out = new ByteArrayOutputStream();
        for (var part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /// {@return a 16-bit value as two bytes}
    private static byte[] u16(int value) {
        return new byte[]{(byte) (value >>> 8), (byte) value};
    }

    /// {@return an RTP packet of a payload, all at timestamp 0}
    private static RtpPacket rtp(int sequence, boolean marker, byte[] payload) {
        return packet(98, marker, sequence, 0, ByteBuffer.wrap(payload));
    }

    /// {@return the NAL unit types of an assembled access unit}
    private static List<Integer> types(H265Format format, List<RtpPacket> packets) throws PayloadFormatException {
        var frame = format.depacketizer().assemble(packets);
        return ((H265FrameMetadata) frame.metadata()).nalUnitTypes();
    }

    @Test
    @DisplayName("puts the NAL units of single, aggregation and fragmentation packets back in DON order")
    void reorders() throws PayloadFormatException {
        var single = concat(new byte[]{PPS[0], PPS[1]}, u16(9), new byte[]{PPS[2]});
        var aggregation = concat(new byte[]{0x60, 0x01}, u16(7), u16(VPS.length), VPS, new byte[]{0},
                u16(SPS.length), SPS);
        var fuStart = concat(new byte[]{0x62, 0x01, (byte) (0x80 | 19)}, u16(10), new byte[]{(byte) 0x80, 0x11});
        var fuEnd = concat(new byte[]{0x62, 0x01, (byte) (0x40 | 19)}, new byte[]{0x22, 0x33});
        var packets = List.of(rtp(1, false, fuStart), rtp(2, false, fuEnd), rtp(3, false, single),
                rtp(4, true, aggregation));
        assertEquals(List.of(32, 33, 34, 19), types(DON, packets));
        var frame = DON.depacketizer().assemble(packets);
        var start = new byte[]{0, 0, 0, 1};
        assertArrayEquals(concat(start, VPS, start, SPS, start, PPS, start, IDR), frame.toByteArray());
        assertTrue(frame.keyframe());
    }

    @Test
    @DisplayName("orders across a DON wrap and keeps the transmission order of a stream without numbers")
    void wrapAndPlain() throws PayloadFormatException {
        var late = concat(new byte[]{VPS[0], VPS[1]}, u16(0xFFFF), new byte[]{VPS[2]});
        var early = concat(new byte[]{SPS[0], SPS[1]}, u16(0), new byte[]{SPS[2]});
        assertEquals(List.of(32, 33), types(DON, List.of(rtp(1, false, early), rtp(2, true, late))));
        assertEquals(List.of(33, 32), types(PLAIN, List.of(rtp(1, false, SPS), rtp(2, true, VPS))));
    }

    @Test
    @DisplayName("unwraps a PACI packet around a single NAL unit and an aggregation packet")
    void paci() throws PayloadFormatException {
        var wrappedSingle = concat(new byte[]{0x64, 0x01}, new byte[]{(byte) (19 << 1), (byte) (2 << 4)},
                new byte[]{(byte) 0xAA, (byte) 0xBB}, new byte[]{(byte) 0x80, 0x11, 0x22, 0x33});
        var frame = PLAIN.depacketizer().assemble(List.of(rtp(1, true, wrappedSingle)));
        assertArrayEquals(concat(new byte[]{0, 0, 0, 1}, IDR), frame.toByteArray());
        assertTrue(PLAIN.isKeyframe(ByteBuffer.wrap(wrappedSingle)));
        var aggregation = concat(u16(VPS.length), VPS, u16(SPS.length), SPS);
        var wrappedAggregation = concat(new byte[]{0x64, 0x01}, new byte[]{(byte) (48 << 1), 0}, aggregation);
        assertEquals(List.of(32, 33), types(PLAIN, List.of(rtp(1, true, wrappedAggregation))));
        var nested = concat(new byte[]{0x64, 0x01}, new byte[]{(byte) (50 << 1), 0}, new byte[]{1, 2, 3});
        assertFalse(PLAIN.depacketizer().inspect(rtp(1, true, nested)).valid());
        var truncated = concat(new byte[]{0x64, 0x01}, new byte[]{(byte) (19 << 1), (byte) (8 << 4)}, new byte[]{1});
        assertFalse(PLAIN.depacketizer().inspect(rtp(1, true, truncated)).valid());
    }

    @Test
    @DisplayName("finds keyframes in aggregation packets with decoding order numbers")
    void keyframes() {
        var aggregation = concat(new byte[]{0x60, 0x01}, u16(1), u16(SPS.length), SPS, new byte[]{0},
                u16(IDR.length), IDR);
        assertTrue(DON.isKeyframe(ByteBuffer.wrap(aggregation)));
        assertFalse(PLAIN.isKeyframe(ByteBuffer.wrap(new byte[]{0x60, 0x01, 0, 1, 0, 3, 0x02, 0x01, 0})));
    }

    @Test
    @DisplayName("rejects truncated decoding order numbers")
    void truncated() {
        var depacketizer = DON.depacketizer();
        assertFalse(depacketizer.inspect(rtp(1, true, new byte[]{0x26, 0x01, 0x00})).valid());
        assertFalse(depacketizer.inspect(rtp(1, true, new byte[]{0x62, 0x01, (byte) (0x80 | 19), 0})).valid());
        assertFalse(depacketizer.inspect(rtp(1, true, concat(new byte[]{0x60, 0x01}, u16(1), u16(3), VPS)))
                .valid());
        assertThrows(PayloadFormatException.class, () -> depacketizer.assemble(List.of(
                rtp(1, true, new byte[]{0x26, 0x01, 0x00, 0x01}))));
    }

    @Test
    @DisplayName("never throws anything but PayloadFormatException on random payloads")
    void fuzz() {
        var random = new Random(7798);
        for (var format : List.of(DON, PLAIN)) {
            var depacketizer = format.depacketizer();
            for (var iteration = 0; iteration < 5000; iteration++) {
                var payload = new byte[1 + random.nextInt(40)];
                random.nextBytes(payload);
                payload[0] &= 0x7F;
                if (random.nextBoolean()) {
                    payload[0] = (byte) ((48 + random.nextInt(3)) << 1);
                }
                var packet = rtp(iteration, true, payload);
                depacketizer.inspect(packet);
                format.isKeyframe(ByteBuffer.wrap(payload));
                try {
                    depacketizer.assemble(List.of(packet));
                } catch (PayloadFormatException expected) {
                    // malformed input is rejected with the documented exception
                }
            }
        }
    }
}
