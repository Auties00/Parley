package com.github.auties00.parley.cc;

import java.util.OptionalLong;

/// The additive-increase, multiplicative-decrease rate controller of GCC's delay-based estimator.
///
/// The detector's signal moves a three-state machine: [BandwidthUsage#OVERUSING] decreases, [BandwidthUsage#NORMAL]
/// increases, [BandwidthUsage#UNDERUSING] holds. An increase is multiplicative (8% per second) while the rate is far
/// from the estimated link capacity, and additive (about one packet per response time) once it is close; a decrease
/// sets the rate to [#BETA] times the acknowledged throughput and updates the link capacity estimate from that
/// throughput.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class AimdRateController {
    /// The multiplicative decrease factor of section 5.5.
    static final double BETA = 0.85;

    /// The multiplicative increase per second, `eta` of section 5.5.
    static final double MULTIPLICATIVE_INCREASE = 1.08;

    /// The smallest additive increase per second, in bits per second.
    static final long MIN_ADDITIVE_INCREASE_BPS = 4_000;

    /// The assumed RTP packet size of the additive increase, in bits.
    private static final double PACKET_SIZE_BITS = 1200 * 8;

    /// The increase is capped at this multiple of the acknowledged throughput (plus [#THROUGHPUT_MARGIN_BPS]), so the
    /// estimate cannot run away from what the link actually delivered.
    private static final double THROUGHPUT_LIMIT_FACTOR = 1.5;

    private static final long THROUGHPUT_MARGIN_BPS = 10_000;

    /// The smoothing of the link capacity estimate.
    private static final double CAPACITY_ALPHA = 0.05;

    private enum State {
        HOLD, INCREASE, DECREASE
    }

    private final long minBitrateBps;
    private long maxBitrateBps;
    private long currentBitrateBps;
    private State state;
    private long lastChangeNanos;
    private boolean changed;
    private long lastDecreaseNanos;
    private boolean decreased;
    private double capacityEstimateKbps;
    private double capacityVariance;
    private boolean capacityKnown;

    /// Creates a controller starting at `startBitrateBps`.
    ///
    /// @param minBitrateBps   the floor of the estimate
    /// @param startBitrateBps the initial estimate
    /// @param maxBitrateBps   the ceiling of the estimate
    AimdRateController(long minBitrateBps, long startBitrateBps, long maxBitrateBps) {
        this.minBitrateBps = minBitrateBps;
        this.maxBitrateBps = maxBitrateBps;
        this.currentBitrateBps = Math.clamp(startBitrateBps, minBitrateBps, maxBitrateBps);
        this.state = State.INCREASE;
        this.capacityVariance = 0.4;
    }

    /// Applies one detector signal.
    ///
    /// @param usage            the detector state
    /// @param ackedBitrateBps  the acknowledged throughput, if known
    /// @param rttNanos         the round-trip time
    /// @param nowNanos         the current time
    /// @return the new estimate, in bits per second
    long update(BandwidthUsage usage, OptionalLong ackedBitrateBps, long rttNanos, long nowNanos) {
        if (!changed) {
            changed = true;
            lastChangeNanos = nowNanos;
        }
        state = switch (usage) {
            case NORMAL -> state == State.HOLD ? State.INCREASE : state == State.DECREASE ? State.HOLD : state;
            case OVERUSING -> state != State.DECREASE ? State.DECREASE : state;
            case UNDERUSING -> State.HOLD;
        };
        var newBitrate = currentBitrateBps;
        switch (state) {
            case HOLD -> {
            }
            case INCREASE -> {
                if (ackedBitrateBps.isPresent() && capacityKnown
                        && ackedBitrateBps.getAsLong() / 1000.0 > capacityEstimateKbps + 3 * capacityStdKbps()) {
                    capacityKnown = false;
                }
                var elapsedNanos = Math.min(nowNanos - lastChangeNanos, 1_000_000_000L);
                if (capacityKnown) {
                    newBitrate += additiveIncrease(rttNanos, elapsedNanos);
                } else {
                    newBitrate += multiplicativeIncrease(elapsedNanos);
                }
                if (ackedBitrateBps.isPresent()) {
                    var limit = (long) (THROUGHPUT_LIMIT_FACTOR * ackedBitrateBps.getAsLong()) + THROUGHPUT_MARGIN_BPS;
                    if (newBitrate > limit) {
                        newBitrate = Math.max(currentBitrateBps, limit);
                    }
                }
                lastChangeNanos = nowNanos;
            }
            case DECREASE -> {
                if (canReduceFurther(ackedBitrateBps, rttNanos, nowNanos)) {
                    var base = ackedBitrateBps.isPresent() ? ackedBitrateBps.getAsLong() : currentBitrateBps;
                    newBitrate = (long) (BETA * base);
                    if (newBitrate > currentBitrateBps && capacityKnown) {
                        newBitrate = (long) (BETA * capacityEstimateKbps * 1000);
                    }
                    newBitrate = Math.min(newBitrate, currentBitrateBps);
                    if (ackedBitrateBps.isPresent()) {
                        updateCapacity(ackedBitrateBps.getAsLong());
                    }
                    lastDecreaseNanos = nowNanos;
                    decreased = true;
                }
                state = State.HOLD;
                lastChangeNanos = nowNanos;
            }
        }
        currentBitrateBps = Math.clamp(newBitrate, minBitrateBps, maxBitrateBps);
        return currentBitrateBps;
    }

    /// Forces the estimate, as a probe result or a REMB does; the state machine is unchanged.
    ///
    /// @param bitrateBps the new estimate
    /// @param nowNanos   the current time
    void setEstimate(long bitrateBps, long nowNanos) {
        currentBitrateBps = Math.clamp(bitrateBps, minBitrateBps, maxBitrateBps);
        lastChangeNanos = nowNanos;
        changed = true;
    }

    /// Changes the ceiling of the estimate.
    ///
    /// @param maxBitrateBps the new ceiling
    void setMaxBitrate(long maxBitrateBps) {
        this.maxBitrateBps = Math.max(maxBitrateBps, minBitrateBps);
        currentBitrateBps = Math.min(currentBitrateBps, this.maxBitrateBps);
    }

    /// {@return the current estimate, in bits per second}
    long estimate() {
        return currentBitrateBps;
    }

    /// {@return the link capacity estimate, if a decrease has produced one}
    OptionalLong linkCapacity() {
        return capacityKnown ? OptionalLong.of((long) (capacityEstimateKbps * 1000)) : OptionalLong.empty();
    }

    /// {@return whether the controller is in the multiplicative (far from capacity) increase regime}
    boolean multiplicativeRegime() {
        return !capacityKnown;
    }

    private boolean canReduceFurther(OptionalLong ackedBitrateBps, long rttNanos, long nowNanos) {
        if (!decreased) {
            return true;
        }
        var interval = Math.clamp(rttNanos, 10_000_000L, 200_000_000L);
        if (nowNanos - lastDecreaseNanos >= interval) {
            return true;
        }
        return ackedBitrateBps.isPresent() && currentBitrateBps / 2 > ackedBitrateBps.getAsLong();
    }

    private long multiplicativeIncrease(long elapsedNanos) {
        var alpha = Math.pow(MULTIPLICATIVE_INCREASE, elapsedNanos / 1e9);
        return Math.max((long) (currentBitrateBps * (alpha - 1)), 1_000L * elapsedNanos / 1_000_000_000L);
    }

    private long additiveIncrease(long rttNanos, long elapsedNanos) {
        var bitsPerFrame = currentBitrateBps / 30.0;
        var packetsPerFrame = Math.ceil(bitsPerFrame / PACKET_SIZE_BITS);
        var packetSizeBits = bitsPerFrame / Math.max(packetsPerFrame, 1);
        var responseTimeSeconds = (rttNanos + 100_000_000L) / 1e9;
        var perSecond = Math.max(MIN_ADDITIVE_INCREASE_BPS, packetSizeBits / responseTimeSeconds);
        return (long) (perSecond * elapsedNanos / 1e9);
    }

    private void updateCapacity(long ackedBitrateBps) {
        var sampleKbps = ackedBitrateBps / 1000.0;
        if (!capacityKnown) {
            capacityEstimateKbps = sampleKbps;
            capacityKnown = true;
        } else {
            if (sampleKbps < capacityEstimateKbps - 3 * capacityStdKbps()) {
                capacityEstimateKbps = sampleKbps;
            } else {
                capacityEstimateKbps = (1 - CAPACITY_ALPHA) * capacityEstimateKbps + CAPACITY_ALPHA * sampleKbps;
            }
        }
        var normalization = Math.max(capacityEstimateKbps, 1.0);
        var error = capacityEstimateKbps - sampleKbps;
        capacityVariance = (1 - CAPACITY_ALPHA) * capacityVariance + CAPACITY_ALPHA * error * error / normalization;
        capacityVariance = Math.clamp(capacityVariance, 0.4, 2.5);
    }

    private double capacityStdKbps() {
        return Math.sqrt(capacityVariance * capacityEstimateKbps);
    }
}
