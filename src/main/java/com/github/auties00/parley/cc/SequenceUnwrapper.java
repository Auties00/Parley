package com.github.auties00.parley.cc;

/// Extends a wrapping unsigned counter of a fixed bit width into a monotonic `long`, assuming consecutive values
/// are less than half the counter range apart.
final class SequenceUnwrapper {
    /// The counter modulus, `2^bits`.
    private final long modulus;

    /// The last unwrapped value, or `Long.MIN_VALUE` before the first one.
    private long last;

    /// Creates an unwrapper for a counter of `bits` bits.
    ///
    /// @param bits the counter width, 1 to 62
    SequenceUnwrapper(int bits) {
        if (bits < 1 || bits > 62) {
            throw new IllegalArgumentException("bits must be in 1..62: " + bits);
        }
        this.modulus = 1L << bits;
        this.last = Long.MIN_VALUE;
    }

    /// Unwraps `value` against the previous one and remembers the result.
    ///
    /// @param value the wrapped value, `0` to `2^bits - 1`
    /// @return the unwrapped value; the first call returns `value` itself
    long unwrap(long value) {
        var result = peek(value);
        last = result;
        return result;
    }

    /// Unwraps `value` against the previous one without remembering it.
    ///
    /// @param value the wrapped value
    /// @return the unwrapped value nearest to the previous one
    long peek(long value) {
        var wrapped = Math.floorMod(value, modulus);
        if (last == Long.MIN_VALUE) {
            return wrapped;
        }
        return nearest(last, wrapped, modulus);
    }

    /// {@return the value congruent to `wrapped` modulo `modulus` that is nearest to `reference`}
    ///
    /// @param reference the unwrapped reference value
    /// @param wrapped   the wrapped value
    /// @param modulus   the counter modulus
    static long nearest(long reference, long wrapped, long modulus) {
        var delta = Math.floorMod(wrapped - reference, modulus);
        if (delta >= modulus / 2) {
            delta -= modulus;
        }
        return reference + delta;
    }
}
