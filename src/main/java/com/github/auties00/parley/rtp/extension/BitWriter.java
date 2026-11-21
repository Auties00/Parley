package com.github.auties00.parley.rtp.extension;

import java.util.Arrays;

/// Writes big-endian bit fields, most significant bit first, into a growing byte array.
final class BitWriter {
    private byte[] bytes = new byte[16];
    private int bit;

    void write(long value, int count) {
        for (var i = count - 1; i >= 0; i--) {
            writeBit((int) (value >>> i) & 1);
        }
    }

    void writeFlag(boolean flag) {
        writeBit(flag ? 1 : 0);
    }

    /// Writes `value` in `0..n - 1` as the `ns(n)` element of the AV1 specification.
    void writeNonSymmetric(int value, int n) {
        var w = 0;
        for (var x = n; x != 0; x >>= 1) {
            w++;
        }
        var m = (1 << w) - n;
        if (value < m) {
            write(value, w - 1);
        } else {
            write((value + m) >>> 1, w - 1);
            write((value + m) & 1, 1);
        }
    }

    private void writeBit(int b) {
        var index = bit / 8;
        if (index >= bytes.length) {
            bytes = Arrays.copyOf(bytes, bytes.length * 2);
        }
        if (b != 0) {
            bytes[index] |= (byte) (1 << (7 - bit % 8));
        }
        bit++;
    }

    int bitLength() {
        return bit;
    }

    /// {@return the written bytes, the last one zero-padded}
    byte[] toByteArray() {
        return Arrays.copyOf(bytes, (bit + 7) / 8);
    }
}
