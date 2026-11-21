package com.github.auties00.parley.cc;

/// The over-use detector of GCC: compares the delay-gradient estimate against an adaptive threshold and signals
/// [BandwidthUsage#OVERUSING] only once the estimate has stayed above it for [#OVERUSE_TIME_NANOS] over more than one
/// sample.
///
/// The threshold `del_var_th` follows the estimate with gain [#K_UP] when the estimate is above it and [#K_DOWN]
/// below, clamped to `[6, 600]` ms, which keeps GCC from starving against loss-based TCP flows (section 5.4 of the
/// draft).
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class OveruseDetector {
    /// The threshold gain while the estimate is above the threshold.
    static final double K_UP = 0.0087;

    /// The threshold gain while the estimate is below the threshold.
    static final double K_DOWN = 0.039;

    /// The initial threshold, in milliseconds.
    static final double INITIAL_THRESHOLD_MS = 12.5;

    /// The lower clamp of the threshold, in milliseconds.
    static final double MIN_THRESHOLD_MS = 6;

    /// The upper clamp of the threshold, in milliseconds.
    static final double MAX_THRESHOLD_MS = 600;

    /// An estimate further than this above the threshold does not adapt it (a spike, not a trend), in milliseconds.
    static final double MAX_ADAPT_OFFSET_MS = 15;

    /// How long the estimate must stay above the threshold before over-use is signalled: 10 ms.
    static final long OVERUSE_TIME_NANOS = 10_000_000L;

    /// The longest step of one threshold update, so one late sample cannot swing the threshold.
    private static final long MAX_TIME_DELTA_NANOS = 100_000_000L;

    private double thresholdMs;
    private long lastUpdateNanos;
    private boolean updated;
    private double timeOverUsingMs;
    private int overuseCounter;
    private double previousTrend;
    private BandwidthUsage state;

    /// Creates a detector in the [BandwidthUsage#NORMAL] state with the initial threshold.
    OveruseDetector() {
        this.thresholdMs = INITIAL_THRESHOLD_MS;
        this.timeOverUsingMs = -1;
        this.state = BandwidthUsage.NORMAL;
    }

    /// Feeds one modified trend sample.
    ///
    /// @param modifiedTrend the trend scaled by the sample count and threshold gain, in milliseconds
    /// @param trend         the raw trend, used to require a non-decreasing trend before signalling over-use
    /// @param sampleDeltaMs the send-time spacing of the groups that produced the sample
    /// @param nowNanos      the arrival time of the sample
    /// @return the detector state after the sample
    BandwidthUsage detect(double modifiedTrend, double trend, double sampleDeltaMs, long nowNanos) {
        if (modifiedTrend > thresholdMs) {
            if (timeOverUsingMs == -1) {
                timeOverUsingMs = sampleDeltaMs / 2;
            } else {
                timeOverUsingMs += sampleDeltaMs;
            }
            overuseCounter++;
            if (timeOverUsingMs > OVERUSE_TIME_NANOS / 1e6 && overuseCounter > 1 && trend >= previousTrend) {
                timeOverUsingMs = 0;
                overuseCounter = 0;
                state = BandwidthUsage.OVERUSING;
            }
        } else if (modifiedTrend < -thresholdMs) {
            timeOverUsingMs = -1;
            overuseCounter = 0;
            state = BandwidthUsage.UNDERUSING;
        } else {
            timeOverUsingMs = -1;
            overuseCounter = 0;
            state = BandwidthUsage.NORMAL;
        }
        previousTrend = trend;
        updateThreshold(modifiedTrend, nowNanos);
        return state;
    }

    /// {@return the current detector state}
    BandwidthUsage state() {
        return state;
    }

    /// {@return the current adaptive threshold, in milliseconds}
    double thresholdMs() {
        return thresholdMs;
    }

    private void updateThreshold(double modifiedTrend, long nowNanos) {
        if (!updated) {
            updated = true;
            lastUpdateNanos = nowNanos;
        }
        var magnitude = Math.abs(modifiedTrend);
        if (magnitude > thresholdMs + MAX_ADAPT_OFFSET_MS) {
            lastUpdateNanos = nowNanos;
            return;
        }
        var gain = magnitude < thresholdMs ? K_DOWN : K_UP;
        var deltaMs = Math.min(Math.max(nowNanos - lastUpdateNanos, 0), MAX_TIME_DELTA_NANOS) / 1e6;
        thresholdMs += gain * (magnitude - thresholdMs) * deltaMs;
        thresholdMs = Math.clamp(thresholdMs, MIN_THRESHOLD_MS, MAX_THRESHOLD_MS);
        lastUpdateNanos = nowNanos;
    }
}
