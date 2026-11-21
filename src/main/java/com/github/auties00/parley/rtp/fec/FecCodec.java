package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.OptionalLong;

/// The XOR parity shared by ULPFEC and FlexFEC, and the FEC header of each format.
final class FecCodec {
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
        static Parity of(List<RtpPacket> packets) {
            var longest = 0;
            for (var packet : packets) {
                longest = Math.max(longest, packet.length() - RtpPacket.FIXED_HEADER_LENGTH);
            }
            var bits0 = 0;
            var bits1 = 0;
            var timestamp = 0L;
            var length = 0;
            var body = new byte[longest];
            for (var packet : packets) {
                var bytes = packet.buffer();
                bits0 ^= bytes.get(0) & 0x3F;
                bits1 ^= bytes.get(1) & 0xFF;
                timestamp ^= packet.timestamp();
                var size = packet.length() - RtpPacket.FIXED_HEADER_LENGTH;
                length ^= size;
                for (var i = 0; i < size; i++) {
                    body[i] ^= bytes.get(RtpPacket.FIXED_HEADER_LENGTH + i);
                }
            }
            return new Parity(bits0, bits1, timestamp, length, body);
        }
    }

    /// A parsed FEC packet payload.
    ///
    /// @param parity             the recovery fields and the XOR body
    /// @param protectedSsrc      the SSRC the header names (FlexFEC draft 03), if any
    /// @param protectedSequences the sequence numbers the packet protects
    record Parsed(Parity parity, OptionalLong protectedSsrc, int[] protectedSequences) {
    }

    /// Writes an FEC payload protecting `packets` into a new heap buffer.
    static ByteBuffer encode(FecFormat format, long protectedSsrc, List<RtpPacket> packets) {
        var parity = Parity.of(packets);
        var base = packets.getFirst().sequence();
        var maxOffset = 0;
        for (var packet : packets) {
            var offset = (packet.sequence() - base) & 0xFFFF;
            if (offset >= format.maxProtected()) {
                throw new IllegalArgumentException("packets span more than " + format.maxProtected() + " sequences");
            }
            maxOffset = Math.max(maxOffset, offset);
        }
        return switch (format) {
            case ULPFEC -> {
                var longMask = maxOffset >= 16;
                var maskBytes = longMask ? 6 : 2;
                var out = ByteBuffer.allocate(10 + 4 + maskBytes + parity.body().length);
                out.put((byte) ((longMask ? 0x40 : 0) | parity.bits0()));
                out.put((byte) parity.bits1());
                out.putShort((short) base);
                out.putInt((int) parity.timestamp());
                out.putShort((short) parity.length());
                out.putShort((short) parity.body().length);
                var mask = new byte[maskBytes];
                for (var packet : packets) {
                    var offset = (packet.sequence() - base) & 0xFFFF;
                    mask[offset / 8] |= (byte) (0x80 >>> (offset % 8));
                }
                out.put(mask);
                out.put(parity.body());
                yield out.flip();
            }
            case FLEXFEC, FLEXFEC_03 -> {
                var maskBytes = maxOffset < 15 ? 2 : maxOffset < 46 ? 6 : 14;
                var headerBytes = format == FecFormat.FLEXFEC_03 ? 18 : 10;
                var out = ByteBuffer.allocate(headerBytes + maskBytes + parity.body().length);
                out.put((byte) parity.bits0());
                out.put((byte) parity.bits1());
                out.putShort((short) parity.length());
                out.putInt((int) parity.timestamp());
                if (format == FecFormat.FLEXFEC_03) {
                    out.putInt(1 << 24);
                    out.putInt((int) protectedSsrc);
                }
                out.putShort((short) base);
                var mask = new byte[maskBytes];
                for (var packet : packets) {
                    var offset = (packet.sequence() - base) & 0xFFFF;
                    var bit = flexMaskBit(offset);
                    mask[bit / 8] |= (byte) (0x80 >>> (bit % 8));
                }
                var lastK = maskBytes == 2 ? 0 : maskBytes == 6 ? 2 : 6;
                mask[lastK] |= (byte) 0x80;
                out.put(mask);
                out.put(parity.body());
                yield out.flip();
            }
        };
    }

    /// {@return the bit index, in the mask bytes, of a sequence offset, skipping the `k` bits at bits 0, 16 and 48}
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
                    throw new RtpFormatException("FlexFEC retransmission packets are not supported");
                }
                if ((first & 0x40) != 0) {
                    throw new RtpFormatException("FlexFEC fixed (row and column) masks are not supported");
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

    /// Rebuilds the one packet a parity block misses from the others it protects.
    static RtpPacket recover(Parity fec, List<RtpPacket> present, int sequence, long ssrc)
            throws RtpFormatException {
        var bits0 = fec.bits0();
        var bits1 = fec.bits1();
        var timestamp = fec.timestamp();
        var length = fec.length();
        var body = fec.body().clone();
        for (var packet : present) {
            var bytes = packet.buffer();
            bits0 ^= bytes.get(0) & 0x3F;
            bits1 ^= bytes.get(1) & 0xFF;
            timestamp ^= packet.timestamp();
            var size = packet.length() - RtpPacket.FIXED_HEADER_LENGTH;
            length ^= size;
            for (var i = 0; i < size && i < body.length; i++) {
                body[i] ^= bytes.get(RtpPacket.FIXED_HEADER_LENGTH + i);
            }
        }
        if (length > body.length) {
            throw new RtpFormatException("recovered length " + length + " exceeds the protected length");
        }
        var out = ByteBuffer.allocate(RtpPacket.FIXED_HEADER_LENGTH + length);
        out.put((byte) (0x80 | bits0 & 0x3F));
        out.put((byte) bits1);
        out.putShort((short) sequence);
        out.putInt((int) timestamp);
        out.putInt((int) ssrc);
        out.put(body, 0, length);
        return RtpPacket.parse(out.flip());
    }
}
