package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.bytes.ByteKernels;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.OptionalLong;

/// The XOR parity shared by ULPFEC and FlexFEC, and the FEC header of each format.
final class FecCodec {
    /// The kernels that XOR the parity bodies.
    private static final ByteKernels KERNELS = ByteKernels.get();

    private FecCodec() {
        throw new AssertionError("FecCodec cannot be instantiated");
    }

    /// The protected fields of a set of packets, XOR-ed together.
    ///
    /// @param bits0  the padding, extension and CSRC count bits, the low six bits of the first header byte
    /// @param bits1  the marker and payload type, the second header byte
    /// @param timestamp the timestamp
    /// @param length the packet length after the 12-byte fixed header
    /// @param body   the bytes after the fixed header, as long as the longest packet's
    record Parity(int bits0, int bits1, long timestamp, int length, byte[] body) {
        /// {@return the parity of no packet, the start of an incremental parity}
        static Parity empty() {
            return new Parity(0, 0, 0, 0, new byte[0]);
        }

        /// {@return this parity with `packet` XOR-ed in}
        ///
        /// @param packet the packet to add
        Parity plus(RtpPacket packet) {
            var bytes = packet.buffer();
            var size = packet.length() - RtpPacket.FIXED_HEADER_LENGTH;
            var grown = java.util.Arrays.copyOf(body, Math.max(size, body.length));
            KERNELS.xor(grown, 0, bytes, RtpPacket.FIXED_HEADER_LENGTH, size);
            return new Parity(bits0 ^ (bytes.get(0) & 0x3F), bits1 ^ (bytes.get(1) & 0xFF),
                    timestamp ^ packet.timestamp(), length ^ size, grown);
        }
    }

    /// A parsed FEC packet payload.
    ///
    /// @param parity             the recovery fields and the XOR body
    /// @param protectedSsrc      the SSRC the header names (FlexFEC draft 03), if any
    /// @param protectedSequences the sequence numbers the packet protects
    record Parsed(Parity parity, OptionalLong protectedSsrc, int[] protectedSequences) {
    }

    /// Writes an RFC 8627 repair payload with fixed columns and rows (`R=0, F=1`) into a new heap buffer.
    ///
    /// @param parity  the parity of the protected packets
    /// @param base    the lowest protected sequence number, `SN base`
    /// @param columns `L`, `1..255`
    /// @param rows    `D`, `0..255`
    static ByteBuffer encodeFixed(Parity parity, int base, int columns, int rows) {
        var out = ByteBuffer.allocate(12 + parity.body().length);
        out.put((byte) (0x40 | parity.bits0()));
        out.put((byte) parity.bits1());
        out.putShort((short) parity.length());
        out.putInt((int) parity.timestamp());
        out.putShort((short) base);
        out.put((byte) columns);
        out.put((byte) rows);
        out.put(parity.body());
        return out.flip();
    }

    /// Writes an RFC 8627 retransmission repair payload (`R=1`): the source packet with its version bits replaced by
    /// `R=1, F=0`, into a new heap buffer.
    ///
    /// @param packet the source packet
    static ByteBuffer encodeRetransmission(RtpPacket packet) {
        var out = ByteBuffer.allocate(packet.length());
        out.put(packet.buffer().duplicate());
        out.put(0, (byte) (0x80 | (out.get(0) & 0x3F)));
        return out.flip();
    }

    /// {@return whether an RFC 8627 repair payload is a retransmission (`R=1`)}
    ///
    /// @param payload the payload
    static boolean isRetransmission(ByteBuffer payload) {
        return payload.hasRemaining() && (payload.get(payload.position()) & 0xC0) == 0x80;
    }

    /// Rebuilds the source packet of an RFC 8627 retransmission repair payload (`R=1`).
    ///
    /// @param payload the payload
    /// @return the source packet, in a new heap buffer
    /// @throws RtpFormatException if the rebuilt packet is malformed
    static RtpPacket decodeRetransmission(ByteBuffer payload) throws RtpFormatException {
        if (payload.remaining() < RtpPacket.FIXED_HEADER_LENGTH) {
            throw new RtpFormatException("FlexFEC retransmission shorter than an RTP header");
        }
        var out = ByteBuffer.allocate(payload.remaining());
        out.put(payload.duplicate());
        out.put(0, (byte) (0x80 | (out.get(0) & 0x3F)));
        return RtpPacket.parse(out.flip());
    }

    /// Writes an FEC payload protecting `packets` into a new heap buffer.
    static ByteBuffer encode(FecFormat format, long protectedSsrc, List<RtpPacket> packets) {
        var count = packets.size();
        var buffers = new ByteBuffer[count];
        var bits0 = 0;
        var bits1 = 0;
        var timestamp = 0L;
        var length = 0;
        var longest = 0;
        var base = packets.getFirst().sequence();
        var maxOffset = 0;
        for (var index = 0; index < count; index++) {
            var packet = packets.get(index);
            var bytes = packet.buffer();
            buffers[index] = bytes;
            var size = packet.length() - RtpPacket.FIXED_HEADER_LENGTH;
            bits0 ^= bytes.get(0) & 0x3F;
            bits1 ^= bytes.get(1) & 0xFF;
            timestamp ^= packet.timestamp();
            length ^= size;
            longest = Math.max(longest, size);
            var offset = (packet.sequence() - base) & 0xFFFF;
            if (offset >= format.maxProtected()) {
                throw new IllegalArgumentException("packets span more than " + format.maxProtected() + " sequences");
            }
            maxOffset = Math.max(maxOffset, offset);
        }
        var out = switch (format) {
            case ULPFEC -> {
                var longMask = maxOffset >= 16;
                var maskBytes = longMask ? 6 : 2;
                var buffer = ByteBuffer.allocate(10 + 4 + maskBytes + longest);
                buffer.put((byte) ((longMask ? 0x40 : 0) | bits0));
                buffer.put((byte) bits1);
                buffer.putShort((short) base);
                buffer.putInt((int) timestamp);
                buffer.putShort((short) length);
                buffer.putShort((short) longest);
                var maskStart = buffer.position();
                for (var index = 0; index < count; index++) {
                    var offset = (packets.get(index).sequence() - base) & 0xFFFF;
                    var at = maskStart + offset / 8;
                    buffer.put(at, (byte) (buffer.get(at) | (0x80 >>> (offset % 8))));
                }
                yield buffer.position(maskStart + maskBytes);
            }
            case FLEXFEC, FLEXFEC_03 -> {
                var maskBytes = maxOffset < 15 ? 2 : maxOffset < 46 ? 6 : 14;
                var headerBytes = format == FecFormat.FLEXFEC_03 ? 18 : 10;
                var buffer = ByteBuffer.allocate(headerBytes + maskBytes + longest);
                buffer.put((byte) bits0);
                buffer.put((byte) bits1);
                buffer.putShort((short) length);
                buffer.putInt((int) timestamp);
                if (format == FecFormat.FLEXFEC_03) {
                    buffer.putInt(1 << 24);
                    buffer.putInt((int) protectedSsrc);
                }
                buffer.putShort((short) base);
                var maskStart = buffer.position();
                for (var index = 0; index < count; index++) {
                    var bit = flexMaskBit((packets.get(index).sequence() - base) & 0xFFFF);
                    var at = maskStart + bit / 8;
                    buffer.put(at, (byte) (buffer.get(at) | (0x80 >>> (bit % 8))));
                }
                var lastK = maskStart + (maskBytes == 2 ? 0 : maskBytes == 6 ? 2 : 6);
                buffer.put(lastK, (byte) (buffer.get(lastK) | 0x80));
                yield buffer.position(maskStart + maskBytes);
            }
        };
        // The parity body is XORed straight into the payload, which starts zeroed
        var bodyStart = out.position();
        var array = out.array();
        for (var index = 0; index < count; index++) {
            KERNELS.xor(array, bodyStart, buffers[index], RtpPacket.FIXED_HEADER_LENGTH,
                    packets.get(index).length() - RtpPacket.FIXED_HEADER_LENGTH);
        }
        return out.position(bodyStart + longest).flip();
    }

    private static int flexMaskBit(int offset) {
        if (offset < 15) {
            return 1 + offset;
        }
        if (offset < 46) {
            return 17 + (offset - 15);
        }
        return 49 + (offset - 46);
    }

    /// Parses an FEC payload.
    static Parsed parse(FecFormat format, ByteBuffer payload) throws RtpFormatException {
        var buffer = payload.duplicate();
        return switch (format) {
            case ULPFEC -> {
                if (buffer.remaining() < 14) {
                    throw new RtpFormatException("ULPFEC payload shorter than its headers");
                }
                var start = buffer.position();
                var first = buffer.get(start) & 0xFF;
                if ((first & 0x80) != 0) {
                    throw new RtpFormatException("ULPFEC extension flag set");
                }
                var longMask = (first & 0x40) != 0;
                var bits1 = buffer.get(start + 1) & 0xFF;
                var base = buffer.getShort(start + 2) & 0xFFFF;
                var timestamp = buffer.getInt(start + 4) & 0xFFFFFFFFL;
                var length = buffer.getShort(start + 8) & 0xFFFF;
                var protectionLength = buffer.getShort(start + 10) & 0xFFFF;
                var maskBytes = longMask ? 6 : 2;
                var bodyStart = start + 12 + maskBytes;
                if (bodyStart + protectionLength > buffer.limit()) {
                    throw new RtpFormatException("ULPFEC protection length overruns the payload");
                }
                var sequences = new int[maskBytes * 8];
                var count = 0;
                for (var bit = 0; bit < maskBytes * 8; bit++) {
                    if ((buffer.get(start + 12 + bit / 8) & (0x80 >>> (bit % 8))) != 0) {
                        sequences[count++] = (base + bit) & 0xFFFF;
                    }
                }
                var body = new byte[protectionLength];
                buffer.get(bodyStart, body);
                yield new Parsed(new Parity(first & 0x3F, bits1, timestamp, length, body), OptionalLong.empty(),
                        java.util.Arrays.copyOf(sequences, count));
            }
            case FLEXFEC, FLEXFEC_03 -> {
                var headerBytes = format == FecFormat.FLEXFEC_03 ? 18 : 10;
                if (buffer.remaining() < headerBytes + 2) {
                    throw new RtpFormatException("FlexFEC payload shorter than its header");
                }
                var start = buffer.position();
                var first = buffer.get(start) & 0xFF;
                if ((first & 0x80) != 0) {
                    throw new RtpFormatException("a FlexFEC retransmission is not a parity payload");
                }
                if ((first & 0x40) != 0) {
                    if (format == FecFormat.FLEXFEC_03) {
                        throw new RtpFormatException("flexfec-03 fixed (row and column) masks are not supported");
                    }
                    yield parseFixed(buffer, start, first);
                }
                var bits1 = buffer.get(start + 1) & 0xFF;
                var length = buffer.getShort(start + 2) & 0xFFFF;
                var timestamp = buffer.getInt(start + 4) & 0xFFFFFFFFL;
                var ssrc = OptionalLong.empty();
                if (format == FecFormat.FLEXFEC_03) {
                    var ssrcCount = buffer.get(start + 8) & 0xFF;
                    if (ssrcCount != 1) {
                        throw new RtpFormatException("FlexFEC packets protecting " + ssrcCount
                                + " SSRCs are not supported");
                    }
                    ssrc = OptionalLong.of(buffer.getInt(start + 12) & 0xFFFFFFFFL);
                }
                var base = buffer.getShort(start + headerBytes - 2) & 0xFFFF;
                var maskStart = start + headerBytes;
                int maskBytes;
                if ((buffer.get(maskStart) & 0x80) != 0) {
                    maskBytes = 2;
                } else if (buffer.remaining() >= headerBytes + 6 && (buffer.get(maskStart + 2) & 0x80) != 0) {
                    maskBytes = 6;
                } else if (buffer.remaining() >= headerBytes + 14 && (buffer.get(maskStart + 6) & 0x80) != 0) {
                    maskBytes = 14;
                } else {
                    throw new RtpFormatException("FlexFEC mask without a final k bit");
                }
                var sequences = new int[109];
                var count = 0;
                for (var offset = 0; offset < (maskBytes == 2 ? 15 : maskBytes == 6 ? 46 : 109); offset++) {
                    var bit = flexMaskBit(offset);
                    if ((buffer.get(maskStart + bit / 8) & (0x80 >>> (bit % 8))) != 0) {
                        sequences[count++] = (base + offset) & 0xFFFF;
                    }
                }
                var body = new byte[buffer.limit() - maskStart - maskBytes];
                buffer.get(maskStart + maskBytes, body);
                yield new Parsed(new Parity(first & 0x3F, bits1, timestamp, length, body), ssrc,
                        java.util.Arrays.copyOf(sequences, count));
            }
        };
    }

    /// Parses an RFC 8627 repair payload with fixed columns and rows (`R=0, F=1`, Figure 14).
    private static Parsed parseFixed(ByteBuffer buffer, int start, int first) throws RtpFormatException {
        if (buffer.limit() - start < 12) {
            throw new RtpFormatException("FlexFEC fixed header shorter than 12 bytes");
        }
        var bits1 = buffer.get(start + 1) & 0xFF;
        var length = buffer.getShort(start + 2) & 0xFFFF;
        var timestamp = buffer.getInt(start + 4) & 0xFFFFFFFFL;
        var base = buffer.getShort(start + 8) & 0xFFFF;
        var columns = buffer.get(start + 10) & 0xFF;
        var rows = buffer.get(start + 11) & 0xFF;
        int[] sequences;
        if (columns == 0) {
            sequences = new int[0];
        } else if (rows <= 1) {
            sequences = new int[columns];
            for (var i = 0; i < columns; i++) {
                sequences[i] = (base + i) & 0xFFFF;
            }
        } else {
            sequences = new int[rows];
            for (var i = 0; i < rows; i++) {
                sequences[i] = (base + i * columns) & 0xFFFF;
            }
        }
        var body = new byte[buffer.limit() - start - 12];
        buffer.get(start + 12, body);
        return new Parsed(new Parity(first & 0x3F, bits1, timestamp, length, body), OptionalLong.empty(), sequences);
    }

    /// Rebuilds the one packet a parity block misses from the others it protects.
    static RtpPacket recover(Parity fec, List<RtpPacket> present, int sequence, long ssrc)
            throws RtpFormatException {
        var count = present.size();
        var buffers = new ByteBuffer[count];
        var bits0 = fec.bits0();
        var bits1 = fec.bits1();
        var timestamp = fec.timestamp();
        var length = fec.length();
        for (var index = 0; index < count; index++) {
            var packet = present.get(index);
            var bytes = packet.buffer();
            buffers[index] = bytes;
            bits0 ^= bytes.get(0) & 0x3F;
            bits1 ^= bytes.get(1) & 0xFF;
            timestamp ^= packet.timestamp();
            length ^= packet.length() - RtpPacket.FIXED_HEADER_LENGTH;
        }
        var body = fec.body();
        if (length > body.length) {
            throw new RtpFormatException("recovered length " + length + " exceeds the protected length");
        }
        // Only the first `length` bytes of the parity survive, so only they are XORed, in the packet itself
        var out = new byte[RtpPacket.FIXED_HEADER_LENGTH + length];
        System.arraycopy(body, 0, out, RtpPacket.FIXED_HEADER_LENGTH, length);
        for (var index = 0; index < count; index++) {
            var size = Math.min(length, present.get(index).length() - RtpPacket.FIXED_HEADER_LENGTH);
            KERNELS.xor(out, RtpPacket.FIXED_HEADER_LENGTH, buffers[index], RtpPacket.FIXED_HEADER_LENGTH, size);
        }
        var header = ByteBuffer.wrap(out);
        header.put((byte) (0x80 | bits0 & 0x3F));
        header.put((byte) bits1);
        header.putShort((short) sequence);
        header.putInt((int) timestamp);
        header.putInt((int) ssrc);
        return RtpPacket.parse(header.clear());
    }
}
