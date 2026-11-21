package com.github.auties00.parley.cc;

/// A probe the pacer sends: a short burst of packets at a rate above the current estimate whose arrival spacing
/// tells whether the link can carry that rate.
///
/// @param id          the cluster id the sent packets are tagged with, non-negative
/// @param bitrateBps  the rate the burst is sent at
/// @param minPackets  the fewest packets the burst contains
/// @param minBytes    the fewest bytes the burst contains
/// @param createdNanos when the cluster was created
record ProbeCluster(int id, long bitrateBps, int minPackets, long minBytes, long createdNanos) {
    /// The fewest packets in a probe.
    static final int MIN_PACKETS = 5;

    /// The burst duration a probe's byte count is sized for: 15 ms.
    static final long DURATION_NANOS = 15_000_000L;

    /// Validates the cluster.
    ProbeCluster {
        if (id < 0) {
            throw new IllegalArgumentException("id must not be negative: " + id);
        }
        if (bitrateBps <= 0) {
            throw new IllegalArgumentException("bitrateBps must be positive: " + bitrateBps);
        }
    }

    /// {@return a cluster of at least [#MIN_PACKETS] packets and [#DURATION_NANOS] worth of bytes at `bitrateBps`}
    ///
    /// @param id           the cluster id
    /// @param bitrateBps   the probe rate
    /// @param createdNanos the creation time
    static ProbeCluster of(int id, long bitrateBps, long createdNanos) {
        var minBytes = Math.max(1, bitrateBps * DURATION_NANOS / 8 / 1_000_000_000L);
        return new ProbeCluster(id, bitrateBps, MIN_PACKETS, minBytes, createdNanos);
    }
}
