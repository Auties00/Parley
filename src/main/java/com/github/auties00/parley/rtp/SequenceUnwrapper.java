package com.github.auties00.parley.rtp;

import java.util.OptionalLong;

/// Extends wrapping RTP counters (16-bit sequence numbers or 32-bit timestamps) to monotonic 64-bit values.
///
/// Each value is placed at the unwrapped position closest to the last one returned, so a packet that arrives late
/// or out of order across a wrap keeps its place: after `65535` unwraps to `65535`, `0` unwraps to `65536` and a late
/// `65534` to `65534`. The first value unwraps to itself. An unwrapper is not thread-safe.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public final class SequenceUnwrapper {
    private final int bits;
    private final long modulus;
    private final long mask;
    private long last;
    private boolean started;

    private SequenceUnwrapper(int bits) {
        this.bits = bits;
        this.modulus = 1L << bits;
        this.mask = modulus - 1;
    }

    /// {@return a new unwrapper for 16-bit RTP sequence numbers}
    public static SequenceUnwrapper forSequenceNumbers() {
        return new SequenceUnwrapper(16);
    }

    /// {@return a new unwrapper for 32-bit RTP timestamps}
    public static SequenceUnwrapper forTimestamps() {
        return new SequenceUnwrapper(32);
    }

    /// Unwraps a value and remembers it as the reference for the next call.
    ///
    /// @param value the wrapped value; only its low 16 or 32 bits are used
    /// @return the unwrapped value, never negative
    public long unwrap(long value) {
        var result = peek(value);
        last = result;
        started = true;
        return result;
    }

    /// Unwraps a value without remembering it.
    ///
    /// @param value the wrapped value; only its low 16 or 32 bits are used
    /// @return the unwrapped value, never negative
    public long peek(long value) {
        value &= mask;
        if (!started) {
            return value;
        }
        var delta = (value - last) & mask;
        long signed = delta >= modulus / 2 ? delta - modulus : delta;
        var result = last + signed;
        return result < 0 ? result + modulus : result;
    }

    /// {@return the last value [#unwrap(long)] returned; empty before the first call}
    public OptionalLong last() {
        return started ? OptionalLong.of(last) : OptionalLong.empty();
    }

    /// Forgets the reference, so the next value unwraps to itself.
    public void reset() {
        started = false;
        last = 0;
    }

    @Override
    public String toString() {
        return "SequenceUnwrapper[bits=" + bits + ", last=" + (started ? last : "none") + "]";
    }
}
