package com.github.auties00.parley.jitter;

/// Extends a wrapping counter (a 32-bit timestamp, a 16-bit sequence number, a 15-bit picture id, an 8-bit
/// `TL0PICIDX`) to a monotonic `long`, taking each new value as the nearest one to the newest seen.
final class Unwrapper {
    /// The modulus of the counter.
    private final long modulus;

    /// The newest unwrapped value, or `-1` before the first.
    private long newest = -1;

    /// Creates an unwrapper for a counter of `bits` bits.
    Unwrapper(int bits) {
        this.modulus = 1L << bits;
    }

    /// {@return the unwrapped value of a counter value; the first unwraps to itself plus one modulus, so values
    /// slightly before it stay non-negative}
    long unwrap(long value) {
        if (newest < 0) {
            newest = modulus + Math.floorMod(value, modulus);
            return newest;
        }
        var delta = Math.floorMod(value - newest, modulus);
        if (delta > modulus / 2) {
            delta -= modulus;
        }
        var result = newest + delta;
        if (result > newest) {
            newest = result;
        }
        return result;
    }
}
