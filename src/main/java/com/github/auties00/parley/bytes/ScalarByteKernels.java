package com.github.auties00.parley.bytes;

import java.nio.ByteBuffer;

/// The scalar byte kernels, which every JVM runs.
///
/// The loops are plain indexed loops over arrays, which C2's superword pass already turns into vector instructions
/// where the hardware has them, except the start code search, whose skip-ahead it cannot vectorize.
final class ScalarByteKernels implements ByteKernels {
    /// The only instance.
    static final ScalarByteKernels INSTANCE = new ScalarByteKernels();

    /// The per-thread array a buffer without an accessible array is copied into before XOR.
    private static final ThreadLocal<byte[]> SCRATCH = ThreadLocal.withInitial(() -> new byte[2048]);

    private ScalarByteKernels() {
    }

    @Override
    public void xor(byte[] target, int targetOffset, byte[] source, int sourceOffset, int length) {
        for (var i = 0; i < length; i++) {
            target[targetOffset + i] ^= source[sourceOffset + i];
        }
    }

    @Override
    public void xor(byte[] target, int targetOffset, ByteBuffer source, int sourceIndex, int length) {
        if (source.hasArray()) {
            xor(target, targetOffset, source.array(), source.arrayOffset() + sourceIndex, length);
            return;
        }
        // A buffer without an accessible array is copied in chunks into a per-thread scratch array, with the bulk
        // copy intrinsic, and XORed from there: both loops compile to vector code in every caller, where a byte-wise
        // get loop or reading longs through a memory segment were each measured slow in one of the FEC paths
        var scratch = SCRATCH.get();
        for (var done = 0; done < length; ) {
            var chunk = Math.min(scratch.length, length - done);
            source.get(sourceIndex + done, scratch, 0, chunk);
            xor(target, targetOffset + done, scratch, 0, chunk);
            done += chunk;
        }
    }

    @Override
    public int indexOfStartCode(ByteBuffer buffer, int from, int to) {
        if (buffer.hasArray()) {
            var offset = buffer.arrayOffset();
            var index = indexOfStartCode(buffer.array(), offset + from, offset + to);
            return index < 0 ? -1 : index - offset;
        }
        for (var i = from; i + 2 < to; i++) {
            // The third byte of a start code is 1, so a larger byte rules out the three positions ending at it
            if ((buffer.get(i + 2) & 0xFF) > 1) {
                i += 2;
                continue;
            }
            if (buffer.get(i) == 0 && buffer.get(i + 1) == 0 && buffer.get(i + 2) == 1) {
                return i;
            }
        }
        return -1;
    }

    /// {@return the first start code in `bytes[from, to)`, or `-1`}
    ///
    /// @param bytes the bytes
    /// @param from  the first index
    /// @param to    the index the search ends before
    static int indexOfStartCode(byte[] bytes, int from, int to) {
        for (var i = from; i + 2 < to; i++) {
            if ((bytes[i + 2] & 0xFF) > 1) {
                i += 2;
                continue;
            }
            if (bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public boolean isVectorized() {
        return false;
    }

    @Override
    public String toString() {
        return "ScalarByteKernels";
    }
}
