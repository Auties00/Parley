package com.github.auties00.parley.rtp;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/// Conversions between [Instant] and the NTP timestamp formats RTP and RTCP use.
///
/// The 64-bit format ("UQ32.32") counts seconds since 1900-01-01 in its high 32 bits and fractions of a second in its
/// low 32 bits; RTCP sender reports carry it, and the middle 32 bits ("UQ16.16", the compact format) are the
/// `LSR`/`DLSR` fields of reception reports and the round-trip time computation built on them.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc5905.html RFC 5905: Network Time Protocol Version 4: Protocol and Algorithms Specification
public final class NtpTime {
    /// The seconds between 1900-01-01, the NTP epoch, and 1970-01-01, the Unix epoch.
    public static final long UNIX_EPOCH_OFFSET_SECONDS = 2_208_988_800L;

    private NtpTime() {
        throw new AssertionError("NtpTime cannot be instantiated");
    }

    /// {@return the 64-bit NTP timestamp of an instant, as an unsigned value held in a `long`}
    ///
    /// The fraction is truncated to `2^-32` seconds (about 233 picoseconds).
    ///
    /// @param instant an instant between 1900 and 2036, the range of NTP era 0
    public static long fromInstant(Instant instant) {
        Objects.requireNonNull(instant, "instant cannot be null");
        var seconds = instant.getEpochSecond() + UNIX_EPOCH_OFFSET_SECONDS;
        var fraction = (((long) instant.getNano()) << 32) / 1_000_000_000L;
        return (seconds << 32) | fraction;
    }

    /// {@return the instant of a 64-bit NTP timestamp, read in era 0}
    ///
    /// @param ntp the timestamp, an unsigned 64-bit value held in a `long`
    public static Instant toInstant(long ntp) {
        var seconds = (ntp >>> 32) - UNIX_EPOCH_OFFSET_SECONDS;
        var nanos = ((ntp & 0xFFFFFFFFL) * 1_000_000_000L) >>> 32;
        return Instant.ofEpochSecond(seconds, nanos);
    }

    /// {@return the middle 32 bits of a 64-bit NTP timestamp, the compact form of the `LSR` field}
    ///
    /// @param ntp the timestamp
    public static long compact(long ntp) {
        return (ntp >>> 16) & 0xFFFFFFFFL;
    }

    /// {@return a duration in the compact NTP format: units of `1/65536` second, saturated to 32 bits}
    ///
    /// @param duration a non-negative duration
    /// @throws IllegalArgumentException if `duration` is negative
    public static long compactOf(Duration duration) {
        Objects.requireNonNull(duration, "duration cannot be null");
        if (duration.isNegative()) {
            throw new IllegalArgumentException("duration cannot be negative: " + duration);
        }
        return compactOfNanos(duration.toNanos());
    }

    /// {@return a non-negative number of nanoseconds in the compact NTP format, saturated to 32 bits}
    ///
    /// @param nanos the nanoseconds
    public static long compactOfNanos(long nanos) {
        if (nanos <= 0) {
            return 0;
        }
        var seconds = nanos / 1_000_000_000L;
        if (seconds >= 65536) {
            return 0xFFFFFFFFL;
        }
        var remainder = nanos % 1_000_000_000L;
        return (seconds << 16) | ((remainder << 16) / 1_000_000_000L);
    }

    /// {@return the nanoseconds of a compact NTP value}
    ///
    /// @param compact the value in units of `1/65536` second, an unsigned 32-bit value
    public static long compactToNanos(long compact) {
        compact &= 0xFFFFFFFFL;
        return (compact >>> 16) * 1_000_000_000L + (((compact & 0xFFFF) * 1_000_000_000L) >>> 16);
    }
}
