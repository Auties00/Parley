package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.NtpTime;
import com.github.auties00.parley.rtp.SequenceNumbers;

import java.time.Instant;

/// The correspondence between a remote sender's wall clock and its RTP timestamps, from its last sender report: what
/// lip synchronization and playout timestamps are computed from.
///
/// @param ntpTimestamp the sender's wall clock at the report, a 64-bit NTP timestamp
/// @param rtpTimestamp the RTP timestamp corresponding to `ntpTimestamp`
/// @param clockRate    the stream's RTP clock rate in hertz
/// @param arrivalNanos when the report arrived, in nanoseconds of the session's clock
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record NtpRtpMapping(long ntpTimestamp, long rtpTimestamp, int clockRate, long arrivalNanos) {
    /// Validates the clock rate.
    ///
    /// @throws IllegalArgumentException if `clockRate` is not positive
    public NtpRtpMapping {
        SessionChecks.clockRate(clockRate);
    }

    /// {@return the sender's wall clock time of a sample with an RTP timestamp, extrapolated from the report}
    ///
    /// Timestamps within half the 32-bit range before or after the report's are placed on the nearest side.
    ///
    /// @param timestamp the RTP timestamp, an unsigned 32-bit value
    public Instant senderTimeOf(long timestamp) {
        var ticks = SequenceNumbers.timestampDifference(timestamp, rtpTimestamp);
        var nanos = Math.multiplyExact(ticks, 1_000_000_000L) / clockRate;
        return NtpTime.toInstant(ntpTimestamp).plusNanos(nanos);
    }
}
