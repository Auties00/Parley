package com.github.auties00.parley.payload;

/// Extends a wrapping counter (a 16-bit frame number, a 15-bit picture id) to a monotonic `long`, taking each new
/// value as the nearest one to the last.
final class Unwrapper {
    /// The modulus of the counter.
    private final long modulus;

    /// The last unwrapped value, or `-1` before the first.
    private long last = -1;

    /// Creates an unwrapper for a counter of `bits` bits.
    Unwrapper(int bits) {
        this.modulus = 1L << bits;
    }

    /// {@return the unwrapped value of a counter value; the first value unwraps to itself plus one modulus, so values
    /// slightly before it stay non-negative}
    long unwrap(int value) {
        if (last < 0) {
            last = modulus + value;
            return last;
        }
        var delta = Math.floorMod(value - last, modulus);
        if (delta > modulus / 2) {
            delta -= modulus;
        }
        var result = last + delta;
        if (result > last) {
            last = result;
        }
        return result;
    }
}
