package com.github.auties00.parley.payload;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/// Builds RTP packets for the payload and jitter tests, independently of the RTP lane's writer: a fixed header, an
/// optional one-byte header extension block and a payload.
public final class TestPackets {
    private TestPackets() {
    }

    /// {@return a packet with no extensions}
    public static RtpPacket packet(int payloadType, boolean marker, int sequence, long timestamp, ByteBuffer payload) {
        return packet(payloadType, marker, sequence, timestamp, 0x1234_5678L, payload, Map.of(), List.of());
    }

    /// {@return a packet with one-byte header extensions (ids 1..14, values 1..16 bytes) and CSRCs}
    public static RtpPacket packet(int payloadType, boolean marker, int sequence, long timestamp, long ssrc,
                                   ByteBuffer payload, Map<Integer, byte[]> extensions, List<Long> csrcs) {
        var out = new ByteArrayOutputStream();
        var hasExtension = !extensions.isEmpty();
        out.write(0x80 | (hasExtension ? 0x10 : 0) | csrcs.size());
        out.write((marker ? 0x80 : 0) | payloadType);
        out.write(sequence >>> 8 & 0xFF);
        out.write(sequence & 0xFF);
        writeInt(out, timestamp);
        writeInt(out, ssrc);
        for (var csrc : csrcs) {
            writeInt(out, csrc);
        }
        if (hasExtension) {
            var elements = new ByteArrayOutputStream();
            for (var entry : new TreeMap<>(extensions).entrySet()) {
                elements.write(entry.getKey() << 4 | (entry.getValue().length - 1));
                elements.writeBytes(entry.getValue());
            }
            while (elements.size() % 4 != 0) {
                elements.write(0);
            }
            out.write(0xBE);
            out.write(0xDE);
            out.write(elements.size() / 4 >>> 8);
            out.write(elements.size() / 4 & 0xFF);
            out.writeBytes(elements.toByteArray());
        }
        var bytes = new byte[payload.remaining()];
        payload.duplicate().get(bytes);
        out.writeBytes(bytes);
        try {
            return RtpPacket.parse(ByteBuffer.wrap(out.toByteArray()));
        } catch (RtpFormatException exception) {
            throw new AssertionError(exception);
        }
    }

    /// {@return the packets of payloads, numbered from `firstSequence`, all at one timestamp}
    public static List<RtpPacket> packets(List<PacketizedPayload> payloads, int payloadType, int firstSequence,
                                          long timestamp) {
        var result = new ArrayList<RtpPacket>(payloads.size());
        for (var i = 0; i < payloads.size(); i++) {
            var payload = payloads.get(i);
            result.add(packet(payloadType, payload.marker(), (firstSequence + i) & 0xFFFF, timestamp,
                    payload.payload()));
        }
        return result;
    }

    /// {@return a byte buffer of the given unsigned bytes}
    public static ByteBuffer bytes(int... values) {
        var out = new byte[values.length];
        for (var i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return ByteBuffer.wrap(out);
    }

    /// {@return the remaining bytes of a buffer}
    public static byte[] array(ByteBuffer buffer) {
        var out = new byte[buffer.remaining()];
        buffer.duplicate().get(out);
        return out;
    }

    /// Writes a 32-bit big-endian value.
    private static void writeInt(ByteArrayOutputStream out, long value) {
        out.write((int) (value >>> 24) & 0xFF);
        out.write((int) (value >>> 16) & 0xFF);
        out.write((int) (value >>> 8) & 0xFF);
        out.write((int) value & 0xFF);
    }

    /// Writes bits most significant first, with Exp-Golomb codes, for building parameter sets and headers.
    public static final class BitWriter {
        /// The bytes written.
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        /// The byte being filled.
        private int current;

        /// The bits in `current`.
        private int count;

        /// Writes `bits` bits of `value`.
        public BitWriter bits(long value, int bits) {
            for (var i = bits - 1; i >= 0; i--) {
                current = current << 1 | (int) (value >>> i & 1);
                if (++count == 8) {
                    out.write(current);
                    current = 0;
                    count = 0;
                }
            }
            return this;
        }

        /// Writes an unsigned Exp-Golomb code.
        public BitWriter ue(long value) {
            var coded = value + 1;
            var length = 64 - Long.numberOfLeadingZeros(coded);
            bits(0, length - 1);
            return bits(coded, length);
        }

        /// Writes a signed Exp-Golomb code.
        public BitWriter se(long value) {
            return ue(value > 0 ? 2 * value - 1 : -2 * value);
        }

        /// {@return the bytes, padded with a stop bit and zeros}
        public byte[] toBytesWithStopBit() {
            bits(1, 1);
            while (count != 0) {
                bits(0, 1);
            }
            return out.toByteArray();
        }

        /// {@return the bytes, padded with zeros}
        public byte[] toBytes() {
            while (count != 0) {
                bits(0, 1);
            }
            return out.toByteArray();
        }
    }
}
