package com.github.auties00.parley.bytes;

import java.nio.ByteBuffer;

/// The byte kernels of the packet paths, vectorized or scalar.
///
/// Every method checks nothing but what its contract names: the callers pass ranges they already bounded, and an
/// out-of-range index fails with an [IndexOutOfBoundsException] as an array or buffer access would.
///
/// # Threading
///
/// The kernels are stateless and may be called from any thread.
public sealed interface ByteKernels permits ScalarByteKernels, VectorByteKernels {
    /// The system property that, set to `false`, forces the scalar kernels.
    String VECTOR_PROPERTY = "parley.vector";

    /// {@return the kernels this process uses, chosen on first use}
    ///
    /// The vectorized kernels when the `jdk.incubator.vector` module is present, its preferred species is wider than
    /// 64 bits and {@systemProperty parley.vector} is not `false`; the scalar kernels otherwise.
    static ByteKernels get() {
        return KernelSelection.INSTANCE;
    }

    /// {@return the scalar kernels, which every process can run}
    static ByteKernels scalar() {
        return ScalarByteKernels.INSTANCE;
    }

    /// XORs `length` bytes of `source` from `sourceOffset` into `target` from `targetOffset`.
    ///
    /// @param target       the bytes XORed into
    /// @param targetOffset the first byte of `target`
    /// @param source       the bytes XORed in
    /// @param sourceOffset the first byte of `source`
    /// @param length       the number of bytes
    void xor(byte[] target, int targetOffset, byte[] source, int sourceOffset, int length);

    /// XORs `length` bytes of `source` from its absolute index `sourceIndex` into `target` from `targetOffset`,
    /// whatever the buffer's backing (heap, read-only or direct); the buffer's position and limit do not change.
    ///
    /// @param target       the bytes XORed into
    /// @param targetOffset the first byte of `target`
    /// @param source       the bytes XORed in, between its position and its limit
    /// @param sourceIndex  the absolute index of the first byte of `source`, at or after its position
    /// @param length       the number of bytes
    void xor(byte[] target, int targetOffset, ByteBuffer source, int sourceIndex, int length);

    /// {@return the absolute index of the first three-byte start code `00 00 01` that starts at or after `from` and
    /// ends before `to`, or `-1` when there is none}
    ///
    /// @param buffer the bytes, heap, read-only or direct; its position and limit do not change
    /// @param from   the absolute index the search starts at, at or after the buffer's position
    /// @param to     the absolute index the search ends before, at or before the buffer's limit
    int indexOfStartCode(ByteBuffer buffer, int from, int to);

    /// {@return whether these are the vectorized kernels}
    boolean isVectorized();
}
