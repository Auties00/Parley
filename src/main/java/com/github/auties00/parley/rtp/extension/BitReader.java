package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.nio.ByteBuffer;

/// Reads big-endian bit fields, most significant bit first, from a byte range.
final class BitReader {
    private final ByteBuffer source;
    private final int start;
    private final int bitLength;
    private int bit;

    BitReader(ByteBuffer source) {
        this.source = source;
        this.start = source.position();
        this.bitLength = source.remaining() * 8;
    }

    /// {@return the next `count` bits, `0..32`, as an unsigned value}
    long read(int count) throws RtpFormatException {
        if (bit + count > bitLength) {
            throw new RtpFormatException("bit field overruns the value: " + count + " bits at " + bit);
        }
        var value = 0L;
        for (var i = 0; i < count; i++) {
            var index = bit + i;
            var b = source.get(start + index / 8) >>> (7 - index % 8) & 1;
            value = value << 1 | b;
        }
        bit += count;
        return value;
    }

    int readInt(int count) throws RtpFormatException {
        return (int) read(count);
    }

    boolean readFlag() throws RtpFormatException {
        return read(1) != 0;
    }

    /// Reads a non-symmetric unsigned value in `0..n - 1`, the `ns(n)` element of the AV1 specification.
    int readNonSymmetric(int n) throws RtpFormatException {
        var w = 0;
        for (var x = n; x != 0; x >>= 1) {
            w++;
        }
        var m = (1 << w) - n;
        var v = readInt(w - 1);
        if (v < m) {
            return v;
        }
        var extra = readInt(1);
        return (v << 1) - m + extra;
    }

    int position() {
        return bit;
    }
}
