package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.rtcp.ReceptionReport;

/// The reception statistics of one incoming SSRC, as RFC 3550 appendix A defines them: sequence validation (A.1),
/// loss accounting (A.3) and the interarrival jitter estimator (A.8).
///
/// Not thread-safe: the owning stream serializes access.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
final class ReceptionStatistics {
    /// A forward jump larger than this restarts the sequence (RFC 3550 A.1 `MAX_DROPOUT`).
    static final int MAX_DROPOUT = 3000;
    /// A backward jump larger than this is a restart too (RFC 3550 A.1 `MAX_MISORDER`).
    static final int MAX_MISORDER = 100;
    private static final int SEQUENCE_MOD = 1 << 16;

    private boolean started;
    private int maxSequence;
    private long cycles;
    private long baseSequence;
    private long badSequence = SEQUENCE_MOD + 1;
    private long received;
    private long expectedPrior;
    private long receivedPrior;
    private long duplicates;
    private long reordered;

    /// The jitter in RTP timestamp units, scaled by 16 (RFC 3550 A.8).
    private long jitterQ4;
    private long lastTransit;
    private boolean hasTransit;
    private long firstArrivalNanos;

    private int lastFractionLost;
    private long lastReportNanos = -1;

    /// Records one packet received for the first time on the network (not recovered or retransmitted).
    ///
    /// @return whether the packet was accepted into the statistics, `false` for the first packet of a suspected
    ///         restart
    boolean update(int sequence, long rtpTimestamp, long arrivalNanos, int clockRate) {
        if (!started) {
            started = true;
            maxSequence = sequence;
            baseSequence = sequence;
            cycles = 0;
            received = 1;
            firstArrivalNanos = arrivalNanos;
            updateJitter(rtpTimestamp, arrivalNanos, clockRate);
            return true;
        }
        var delta = (sequence - maxSequence) & 0xFFFF;
        if (delta == 0) {
            duplicates++;
            received++;
            return true;
        }
        if (delta < MAX_DROPOUT) {
            if (sequence < maxSequence) {
                cycles += SEQUENCE_MOD;
            }
            maxSequence = sequence;
        } else if (delta <= SEQUENCE_MOD - MAX_MISORDER) {
            if (sequence == badSequence) {
                restart(sequence, arrivalNanos);
            } else {
                badSequence = (sequence + 1) & 0xFFFF;
                return false;
            }
        } else {
            reordered++;
        }
        received++;
        updateJitter(rtpTimestamp, arrivalNanos, clockRate);
        return true;
    }

    private void restart(int sequence, long arrivalNanos) {
        maxSequence = sequence;
        baseSequence = sequence;
        cycles = 0;
        received = 0;
        expectedPrior = 0;
        receivedPrior = 0;
        badSequence = SEQUENCE_MOD + 1;
        hasTransit = false;
        firstArrivalNanos = arrivalNanos;
    }

    private void updateJitter(long rtpTimestamp, long arrivalNanos, int clockRate) {
        var elapsed = arrivalNanos - firstArrivalNanos;
        var arrival = (elapsed / 1_000_000_000L) * clockRate + (elapsed % 1_000_000_000L) * clockRate / 1_000_000_000L;
        var transit = arrival - rtpTimestamp;
        if (hasTransit) {
            var d = (int) (transit - lastTransit);
            d = Math.abs(d);
            jitterQ4 += d - ((jitterQ4 + 8) >> 4);
        }
        lastTransit = transit;
        hasTransit = true;
    }

    boolean started() {
        return started;
    }

    /// {@return the extended highest sequence number received}
    long extendedHighestSequence() {
        return cycles + maxSequence;
    }

    long expected() {
        return started ? extendedHighestSequence() - baseSequence + 1 : 0;
    }

    long received() {
        return received;
    }

    long cumulativeLost() {
        return expected() - received;
    }

    long duplicates() {
        return duplicates;
    }

    long reordered() {
        return reordered;
    }

    /// {@return the interarrival jitter in RTP timestamp units}
    long jitter() {
        return jitterQ4 >> 4;
    }

    int lastFractionLost() {
        return lastFractionLost;
    }

    /// Builds a reception report block and starts a new reporting interval.
    ///
    /// @param lastSenderReport  the `LSR` field, `0` when no sender report was received
    /// @param delaySinceLsrNanos the delay since that sender report arrived, ignored without one
    ReceptionReport report(long ssrc, long lastSenderReport, long delaySinceLsrNanos, long nowNanos) {
        var expected = expected();
        var expectedInterval = expected - expectedPrior;
        expectedPrior = expected;
        var receivedInterval = received - receivedPrior;
        receivedPrior = received;
        var lostInterval = expectedInterval - receivedInterval;
        var fraction = expectedInterval == 0 || lostInterval <= 0 ? 0 : (int) ((lostInterval << 8) / expectedInterval);
        lastFractionLost = Math.min(fraction, 255);
        lastReportNanos = nowNanos;
        var lost = Math.clamp(cumulativeLost(), -0x800000L, 0x7FFFFFL);
        var dlsr = lastSenderReport == 0 ? 0 : com.github.auties00.parley.rtp.NtpTime.compactOfNanos(delaySinceLsrNanos);
        return new ReceptionReport(ssrc, lastFractionLost, (int) lost, extendedHighestSequence() & 0xFFFFFFFFL,
                jitter() & 0xFFFFFFFFL, lastSenderReport, dlsr);
    }
}
