package com.github.auties00.parley.cc;

/// The loss-based controller of GCC (draft-ietf-rmcat-gcc-02 section 6): raises the rate by 5% when less than 2% of
/// packets are lost, lowers it by `rate * (1 - 0.5 * loss)` when more than 10% are lost, and holds it in between.
///
/// Loss samples accumulate until they cover at least [#MIN_PACKETS] packets, so a feedback message about a handful of
/// packets cannot trigger a decrease on its own. A decrease is applied at most once per [#DECREASE_INTERVAL_NANOS] plus
/// one round-trip time, the time the sender needs to see the effect of the previous one.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class LossBasedController {
    /// The loss fraction under which the rate increases.
    static final double LOW_LOSS = 0.02;

    /// The loss fraction over which the rate decreases.
    static final double HIGH_LOSS = 0.10;

    /// The increase factor of a low-loss sample.
    static final double INCREASE_FACTOR = 1.05;

    /// The fewest packets one loss sample must cover.
    static final int MIN_PACKETS = 20;

    /// The shortest spacing of two decreases, before the round-trip time is added.
    static final long DECREASE_INTERVAL_NANOS = 300_000_000L;

    /// The shortest spacing of two increases, so a burst of feedback cannot compound the 5% steps.
    static final long INCREASE_INTERVAL_NANOS = 200_000_000L;

    private final long minBitrateBps;
    private long maxBitrateBps;
    private long bitrateBps;
    private long pendingExpected;
    private long pendingLost;
    private double lastLossRatio;
    private long lastDecreaseNanos;
    private long lastIncreaseNanos;
    private boolean decreasedOnce;
    private boolean increasedOnce;

    /// Creates a controller starting at `startBitrateBps`.
    ///
    /// @param minBitrateBps   the floor
    /// @param startBitrateBps the initial rate
    /// @param maxBitrateBps   the ceiling
    LossBasedController(long minBitrateBps, long startBitrateBps, long maxBitrateBps) {
        this.minBitrateBps = minBitrateBps;
        this.maxBitrateBps = maxBitrateBps;
        this.bitrateBps = Math.clamp(startBitrateBps, minBitrateBps, maxBitrateBps);
    }

    /// Feeds a loss observation.
    ///
    /// @param expected the packets the observation covers
    /// @param lost     how many of them were lost
    /// @param rttNanos the round-trip time
    /// @param nowNanos the current time
    /// @return whether a complete sample was evaluated
    boolean onLoss(long expected, long lost, long rttNanos, long nowNanos) {
        if (expected <= 0) {
            return false;
        }
        pendingExpected += expected;
        pendingLost += Math.clamp(lost, 0, expected);
        if (pendingExpected < MIN_PACKETS) {
            return false;
        }
        lastLossRatio = (double) pendingLost / pendingExpected;
        pendingExpected = 0;
        pendingLost = 0;
        if (lastLossRatio < LOW_LOSS) {
            if (!increasedOnce || nowNanos - lastIncreaseNanos >= INCREASE_INTERVAL_NANOS) {
                bitrateBps = (long) (bitrateBps * INCREASE_FACTOR) + 1_000;
                lastIncreaseNanos = nowNanos;
                increasedOnce = true;
            }
        } else if (lastLossRatio > HIGH_LOSS) {
            if (!decreasedOnce || nowNanos - lastDecreaseNanos >= DECREASE_INTERVAL_NANOS + rttNanos) {
                bitrateBps = (long) (bitrateBps * (1 - 0.5 * lastLossRatio));
                lastDecreaseNanos = nowNanos;
                decreasedOnce = true;
            }
        }
        bitrateBps = Math.clamp(bitrateBps, minBitrateBps, maxBitrateBps);
        return true;
    }

    /// Caps the rate at `limitBps`: the loss-based estimate never exceeds the delay-based one.
    ///
    /// @param limitBps the cap
    void capAt(long limitBps) {
        bitrateBps = Math.clamp(Math.min(bitrateBps, limitBps), minBitrateBps, maxBitrateBps);
    }

    /// Changes the ceiling.
    ///
    /// @param maxBitrateBps the new ceiling
    void setMaxBitrate(long maxBitrateBps) {
        this.maxBitrateBps = Math.max(maxBitrateBps, minBitrateBps);
        bitrateBps = Math.min(bitrateBps, this.maxBitrateBps);
    }

    /// Raises the rate to at least `bitrateBps`, as a successful probe does, unless the last sample showed heavy
    /// loss: a probe measures capacity, not whether the loss stopped.
    ///
    /// @param bitrateBps the floor to raise to
    void raiseTo(long bitrateBps) {
        if (lastLossRatio > HIGH_LOSS) {
            return;
        }
        this.bitrateBps = Math.clamp(Math.max(this.bitrateBps, bitrateBps), minBitrateBps, maxBitrateBps);
    }

    /// {@return the current loss-based rate, in bits per second}
    long estimate() {
        return bitrateBps;
    }

    /// {@return the loss fraction of the last complete sample, `0` to `1`}
    double lossRatio() {
        return lastLossRatio;
    }
}
