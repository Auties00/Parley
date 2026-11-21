package com.github.auties00.parley.cc;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/// Decides when to probe and at what rate.
///
/// - At start it sends two probes, at [#INITIAL_PROBE_FACTORS] times the start rate, and enters exponential
///   probing: while each new estimate reaches [#FURTHER_PROBE_THRESHOLD] of the last probed rate, it probes again at
///   twice the estimate, so the estimate reaches the link capacity in a few round trips instead of the tens of
///   seconds the 8% per second increase would take.
/// - While the sender is application-limited (ALR), the estimate cannot grow from media alone, so it probes at
///   [#ALR_PROBE_FACTOR] times the estimate every [#ALR_PROBE_INTERVAL_NANOS].
/// - When the maximum rate is raised while the estimate sits at the old maximum, it probes at the new maximum.
///
/// Every probe is capped at the maximum rate.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class ProbeController {
    /// The multiples of the start rate the initial probes are sent at.
    static final double[] INITIAL_PROBE_FACTORS = {3, 6};

    /// The factor of the estimate a further exponential probe is sent at.
    static final double EXPONENTIAL_PROBE_FACTOR = 2;

    /// An estimate at or above this fraction of the last probe rate triggers a further probe.
    static final double FURTHER_PROBE_THRESHOLD = 0.7;

    /// The factor of the estimate an ALR probe is sent at.
    static final double ALR_PROBE_FACTOR = 2;

    /// The spacing of ALR probes: 5 s.
    static final long ALR_PROBE_INTERVAL_NANOS = 5_000_000_000L;

    /// How long exponential probing waits for a probe result before giving up.
    static final long PROBE_TIMEOUT_NANOS = 1_000_000_000L;

    private long maxBitrateBps;
    private long estimateBps;
    private boolean exponentialProbing;
    private long lastProbeBitrateBps;
    private long lastProbeNanos;
    private boolean probed;
    private int nextClusterId;

    /// Creates a controller with the given ceiling.
    ///
    /// @param maxBitrateBps the ceiling every probe is capped at
    ProbeController(long maxBitrateBps) {
        this.maxBitrateBps = maxBitrateBps;
    }

    /// Starts probing from `startBitrateBps`.
    ///
    /// @param startBitrateBps the start rate
    /// @param nowNanos        the current time
    /// @return the initial probe clusters
    List<ProbeCluster> onStart(long startBitrateBps, long nowNanos) {
        estimateBps = startBitrateBps;
        exponentialProbing = true;
        var clusters = new ArrayList<ProbeCluster>();
        for (var factor : INITIAL_PROBE_FACTORS) {
            probe((long) (startBitrateBps * factor), nowNanos).ifPresent(clusters::add);
        }
        return clusters;
    }

    /// Reports a new estimate.
    ///
    /// @param estimateBps the new estimate
    /// @param nowNanos    the current time
    /// @return the probes the estimate triggers
    List<ProbeCluster> onEstimate(long estimateBps, long nowNanos) {
        this.estimateBps = estimateBps;
        if (!exponentialProbing) {
            return List.of();
        }
        if (estimateBps >= FURTHER_PROBE_THRESHOLD * lastProbeBitrateBps && lastProbeBitrateBps < maxBitrateBps) {
            var cluster = probe((long) (estimateBps * EXPONENTIAL_PROBE_FACTOR), nowNanos);
            if (cluster.isPresent()) {
                return List.of(cluster.get());
            }
        }
        if (nowNanos - lastProbeNanos > PROBE_TIMEOUT_NANOS) {
            exponentialProbing = false;
        }
        return List.of();
    }

    /// Checks whether an application-limited sender is due for a probe.
    ///
    /// @param alrStartNanos when the sender became application-limited, empty when it is not
    /// @param nowNanos      the current time
    /// @return the probes due
    List<ProbeCluster> onProcess(OptionalLong alrStartNanos, long nowNanos) {
        if (exponentialProbing && probed && nowNanos - lastProbeNanos > PROBE_TIMEOUT_NANOS) {
            exponentialProbing = false;
        }
        if (alrStartNanos.isEmpty() || exponentialProbing) {
            return List.of();
        }
        var since = Math.max(alrStartNanos.getAsLong(), probed ? lastProbeNanos : Long.MIN_VALUE);
        if (nowNanos - since < ALR_PROBE_INTERVAL_NANOS) {
            return List.of();
        }
        return probe((long) (estimateBps * ALR_PROBE_FACTOR), nowNanos).map(List::of).orElse(List.of());
    }

    /// Changes the ceiling, probing at the new one when the estimate sat at the old one.
    ///
    /// @param maxBitrateBps the new ceiling
    /// @param nowNanos      the current time
    /// @return the probes the change triggers
    List<ProbeCluster> onMaxBitrate(long maxBitrateBps, long nowNanos) {
        var previous = this.maxBitrateBps;
        this.maxBitrateBps = maxBitrateBps;
        if (maxBitrateBps > previous && estimateBps >= previous) {
            return probe(maxBitrateBps, nowNanos).map(List::of).orElse(List.of());
        }
        return List.of();
    }

    /// {@return whether exponential probing is still running}
    boolean exponentialProbing() {
        return exponentialProbing;
    }

    private Optional<ProbeCluster> probe(long bitrateBps, long nowNanos) {
        var capped = Math.min(bitrateBps, maxBitrateBps);
        if (capped <= 0) {
            return Optional.empty();
        }
        lastProbeBitrateBps = capped;
        lastProbeNanos = nowNanos;
        probed = true;
        var cluster = ProbeCluster.of(nextClusterId, capped, nowNanos);
        nextClusterId = (nextClusterId + 1) & Integer.MAX_VALUE;
        return Optional.of(cluster);
    }
}
