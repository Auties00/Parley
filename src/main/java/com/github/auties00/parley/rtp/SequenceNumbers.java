package com.github.auties00.parley.rtp;

/// Modular arithmetic on RTP sequence numbers (16 bits) and timestamps (32 bits).
///
/// Both wrap around, so "newer" means "ahead by less than half the number space", the serial number arithmetic RTP
/// receivers use to order packets across a wrap.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc1982.html RFC 1982: Serial Number Arithmetic
public final class SequenceNumbers {
    private SequenceNumbers() {
        throw new AssertionError("SequenceNumbers cannot be instantiated");
    }

    /// {@return whether `sequence` comes after `reference`: ahead of it by `1..32767` modulo 65536}
    ///
    /// When the two are exactly 32768 apart, the one with the larger value is considered newer, so the relation is
    /// antisymmetric.
    ///
    /// @param sequence  a sequence number, `0..65535`
    /// @param reference a sequence number, `0..65535`
    public static boolean isNewer(int sequence, int reference) {
        var delta = (sequence - reference) & 0xFFFF;
        if (delta == 0x8000) {
            return sequence > reference;
        }
        return delta != 0 && delta < 0x8000;
    }

    /// {@return the signed distance from `reference` to `sequence`, in `-32768..32767`}
    ///
    /// @param sequence  a sequence number, `0..65535`
    /// @param reference a sequence number, `0..65535`
    public static int difference(int sequence, int reference) {
        return (short) (sequence - reference);
    }

    /// {@return `sequence + delta` modulo 65536}
    ///
    /// @param sequence a sequence number, `0..65535`
    /// @param delta    the signed offset
    public static int add(int sequence, int delta) {
        return (sequence + delta) & 0xFFFF;
    }

    /// {@return whether `timestamp` comes after `reference`: ahead of it by `1..2^31 - 1` modulo `2^32`}
    ///
    /// @param timestamp a timestamp, an unsigned 32-bit value
    /// @param reference a timestamp, an unsigned 32-bit value
    public static boolean isNewerTimestamp(long timestamp, long reference) {
        var delta = (timestamp - reference) & 0xFFFFFFFFL;
        if (delta == 0x80000000L) {
            return timestamp > reference;
        }
        return delta != 0 && delta < 0x80000000L;
    }

    /// {@return the signed distance from `reference` to `timestamp`, in `-2^31..2^31 - 1`}
    ///
    /// @param timestamp a timestamp, an unsigned 32-bit value
    /// @param reference a timestamp, an unsigned 32-bit value
    public static long timestampDifference(long timestamp, long reference) {
        return (int) (timestamp - reference);
    }
}
