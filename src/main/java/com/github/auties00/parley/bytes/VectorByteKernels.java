package com.github.auties00.parley.bytes;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorSpecies;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/// The byte kernels on the incubating Vector API, in the preferred species of the platform.
///
/// Only [KernelSelection] creates them, after checking that the `jdk.incubator.vector` module is present, so this
/// class is never linked without it. Each kernel processes whole vectors and finishes the tail with the scalar code.
final class VectorByteKernels implements ByteKernels {
    /// The preferred species: 256 bits on AVX2, 512 on AVX-512, 128 on NEON.
    private static final VectorSpecies<Byte> SPECIES = ByteVector.SPECIES_PREFERRED;

    /// The species length in bytes.
    private static final int LANES = SPECIES.length();

    private VectorByteKernels() {
    }

    /// {@return the vectorized kernels, or `null` when the preferred species is 64 bits or narrower, where they
    /// would not beat the scalar ones}
    static ByteKernels create() {
        return SPECIES.vectorBitSize() > 64 ? new VectorByteKernels() : null;
    }

    @Override
    public void xor(byte[] target, int targetOffset, byte[] source, int sourceOffset, int length) {
        var i = 0;
        for (var bound = SPECIES.loopBound(length); i < bound; i += LANES) {
            ByteVector.fromArray(SPECIES, target, targetOffset + i)
                    .lanewise(VectorOperators.XOR, ByteVector.fromArray(SPECIES, source, sourceOffset + i))
                    .intoArray(target, targetOffset + i);
        }
        for (; i < length; i++) {
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
        for (var bound = SPECIES.loopBound(length); i < bound; i += LANES) {
            ByteVector.fromArray(SPECIES, target, targetOffset + i)
                    .lanewise(VectorOperators.XOR, ByteVector.fromMemorySegment(SPECIES, segment, base + i,
                            ByteOrder.nativeOrder()))
                    .intoArray(target, targetOffset + i);
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
        var segment = MemorySegment.ofBuffer(buffer);
        var base = (long) buffer.position();
        var i = from;
        // Three loads at i, i + 1 and i + 2 read up to i + LANES + 1, which must stay below `to`
        for (var bound = to - 2 - LANES; i <= bound; i += LANES) {
            var third = ByteVector.fromMemorySegment(SPECIES, segment, i + 2 - base, ByteOrder.nativeOrder())
                    .compare(VectorOperators.EQ, (byte) 1);
            if (!third.anyTrue()) {
                continue;
            }
            var match = third
                    .and(ByteVector.fromMemorySegment(SPECIES, segment, i - base, ByteOrder.nativeOrder())
                            .compare(VectorOperators.EQ, (byte) 0))
                    .and(ByteVector.fromMemorySegment(SPECIES, segment, i + 1 - base, ByteOrder.nativeOrder())
                            .compare(VectorOperators.EQ, (byte) 0));
            if (match.anyTrue()) {
                return i + match.firstTrue();
            }
        }
        for (; i + 2 < to; i++) {
            if (buffer.get(i) == 0 && buffer.get(i + 1) == 0 && buffer.get(i + 2) == 1) {
                return i;
            }
        }
        return -1;
    }

    /// {@return the first start code in `bytes[from, to)`, or `-1`}
    private static int indexOfStartCode(byte[] bytes, int from, int to) {
        var i = from;
        for (var bound = to - 2 - LANES; i <= bound; i += LANES) {
            var third = ByteVector.fromArray(SPECIES, bytes, i + 2).compare(VectorOperators.EQ, (byte) 1);
            if (!third.anyTrue()) {
                continue;
            }
            var match = third
                    .and(ByteVector.fromArray(SPECIES, bytes, i).compare(VectorOperators.EQ, (byte) 0))
                    .and(ByteVector.fromArray(SPECIES, bytes, i + 1).compare(VectorOperators.EQ, (byte) 0));
            if (match.anyTrue()) {
                return i + match.firstTrue();
            }
        }
        return ScalarByteKernels.indexOfStartCode(bytes, i, to);
    }

    @Override
    public boolean isVectorized() {
        return true;
    }

    @Override
    public String toString() {
        return "VectorByteKernels[" + SPECIES.vectorBitSize() + " bits]";
    }
}
