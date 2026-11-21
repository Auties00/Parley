package com.github.auties00.parley.payload;

/// Reads bits most significant first from a byte array, with the Exp-Golomb codes of H.264 and H.265 and the
/// variable-length codes of AV1.
///
/// Reading past the end throws [IndexOutOfBoundsException], which the header parsers turn into "unknown".
final class BitReader {
    /// The bytes.
    private final byte[] data;

    /// The index after the last readable byte.
    private final int end;

    /// The position in bits from the start of `data`.
    private long position;

    /// Creates a reader over `data[offset..offset+length)`.
    BitReader(byte[] data, int offset, int length) {
        this.data = data;
        this.end = offset + length;
        this.position = (long) offset * 8;
    }

    /// {@return the next bit}
    int bit() {
        if (position >= (long) end * 8) {
            throw new IndexOutOfBoundsException("read past the end of the bitstream");
        }
        var value = (data[(int) (position >>> 3)] >>> (7 - (int) (position & 7))) & 1;
        position++;
        return value;
    }

    /// {@return whether the next bit is set}
    boolean flag() {
        return bit() != 0;
    }

    /// {@return the next `count` bits as an unsigned value, `count` at most 32}
    long bits(int count) {
        var value = 0L;
        for (var i = 0; i < count; i++) {
            value = value << 1 | bit();
        }
        return value;
    }

    /// {@return the next `count` bits as an int, `count` at most 31}
    int bitsInt(int count) {
        return (int) bits(count);
    }

    /// Skips bits.
    void skip(long count) {
        if (position + count > (long) end * 8) {
            throw new IndexOutOfBoundsException("skip past the end of the bitstream");
        }
        position += count;
    }

    /// {@return the next unsigned Exp-Golomb code, `ue(v)`}
    long ue() {
        var zeros = 0;
        while (bit() == 0) {
            if (++zeros > 31) {
                throw new IndexOutOfBoundsException("Exp-Golomb code too long");
            }
        }
        return (1L << zeros) - 1 + bits(zeros);
    }

    /// {@return the next signed Exp-Golomb code, `se(v)`}
    long se() {
        var code = ue();
        return (code & 1) != 0 ? (code + 1) / 2 : -(code / 2);
    }

    /// {@return the next AV1 `uvlc()` value}
    long uvlc() {
        var zeros = 0;
        while (bit() == 0) {
            zeros++;
        }
        if (zeros >= 32) {
            return 0xFFFFFFFFL;
        }
        return bits(zeros) + (1L << zeros) - 1;
    }
}
