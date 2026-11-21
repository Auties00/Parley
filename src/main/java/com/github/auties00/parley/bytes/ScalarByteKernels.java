package com.github.auties00.parley.bytes;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/// The scalar byte kernels, which every JVM runs.
///
/// The array loops are plain indexed loops, which C2's superword pass already turns into vector instructions where
/// the hardware has them; a buffer without an accessible array (direct or read-only) is read eight bytes at a time
/// through a memory segment.
final class ScalarByteKernels implements ByteKernels {
    /// The only instance.
    static final ScalarByteKernels INSTANCE = new ScalarByteKernels();

    /// Eight bytes of a `byte[]` as one `long`, in native order like [ValueLayout#JAVA_LONG_UNALIGNED].
    private static final VarHandle LONGS = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.nativeOrder());

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
        var segment = MemorySegment.ofBuffer(source);
        var base = (long) sourceIndex - source.position();
        var i = 0;
        for (; i + Long.BYTES <= length; i += Long.BYTES) {
            var value = segment.get(ValueLayout.JAVA_LONG_UNALIGNED, base + i);
            LONGS.set(target, targetOffset + i, (long) LONGS.get(target, targetOffset + i) ^ value);
        }
        for (; i < length; i++) {
            target[targetOffset + i] ^= segment.get(ValueLayout.JAVA_BYTE, base + i);
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
