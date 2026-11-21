package com.github.auties00.parley.cc;

import java.util.HashMap;
import java.util.Map;
import java.util.OptionalLong;

/// Turns the feedback about a probe cluster's packets into a capacity estimate.
///
/// A cluster yields an estimate once at least [#MIN_RECEIVED_RATIO] of its packets and bytes were received. The send
/// rate and the receive rate are measured over the cluster (excluding the last sent and the first received packet,
/// which delimit the intervals); a receive rate more than [#MAX_VALID_RATIO] times the send rate means the
/// measurement is broken and is dropped. The estimate is the smaller of the two rates, or [#TARGET_UTILIZATION] of
/// the receive rate when the receive rate fell clearly below the send rate, meaning the probe saturated the link.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class ProbeBitrateEstimator {
    /// The fraction of a cluster's packets and bytes that must be received for an estimate.
    static final double MIN_RECEIVED_RATIO = 0.8;

    /// The largest plausible receive-to-send rate ratio.
    static final double MAX_VALID_RATIO = 2.0;

    /// Under this receive-to-send ratio the link is considered saturated by the probe.
    static final double MIN_RATIO_FOR_UNSATURATED_LINK = 0.9;

    /// The fraction of the receive rate taken as the estimate of a saturating probe.
    static final double TARGET_UTILIZATION = 0.95;

    /// The longest send or receive interval of a valid probe.
    private static final long MAX_INTERVAL_NANOS = 1_000_000_000L;

    /// How long cluster statistics are kept.
    private static final long CLUSTER_HISTORY_NANOS = 1_000_000_000L;

    private static final class Aggregate {
        int packets;
        long bytes;
        long firstSendNanos = Long.MAX_VALUE;
        long lastSendNanos = Long.MIN_VALUE;
        int lastSendSize;
        long firstReceiveNanos = Long.MAX_VALUE;
        long lastReceiveNanos = Long.MIN_VALUE;
        int firstReceiveSize;
        long updatedNanos;
    }

    private final Map<Integer, Aggregate> clusters;

    /// Creates an estimator with no cluster.
    ProbeBitrateEstimator() {
        this.clusters = new HashMap<>();
    }

    /// Feeds one received probe packet.
    ///
    /// @param cluster      the cluster it was sent in
    /// @param sendNanos    its departure time
    /// @param arrivalNanos its arrival time
    /// @param sizeBytes    its size
    /// @param nowNanos     the current time, to expire old clusters
    /// @return the cluster's estimate, if this packet completed enough of it
    OptionalLong onProbePacket(ProbeCluster cluster, long sendNanos, long arrivalNanos, int sizeBytes, long nowNanos) {
        clusters.values().removeIf(aggregate -> nowNanos - aggregate.updatedNanos > CLUSTER_HISTORY_NANOS);
        var aggregate = clusters.computeIfAbsent(cluster.id(), _ -> new Aggregate());
        aggregate.updatedNanos = nowNanos;
        aggregate.packets++;
        aggregate.bytes += sizeBytes;
        if (sendNanos < aggregate.firstSendNanos) {
            aggregate.firstSendNanos = sendNanos;
        }
        if (sendNanos > aggregate.lastSendNanos) {
            aggregate.lastSendNanos = sendNanos;
            aggregate.lastSendSize = sizeBytes;
        }
        if (arrivalNanos < aggregate.firstReceiveNanos) {
            aggregate.firstReceiveNanos = arrivalNanos;
            aggregate.firstReceiveSize = sizeBytes;
        }
        if (arrivalNanos > aggregate.lastReceiveNanos) {
            aggregate.lastReceiveNanos = arrivalNanos;
        }
        if (aggregate.packets < cluster.minPackets() * MIN_RECEIVED_RATIO
                || aggregate.bytes < cluster.minBytes() * MIN_RECEIVED_RATIO) {
            return OptionalLong.empty();
        }
        var sendInterval = aggregate.lastSendNanos - aggregate.firstSendNanos;
        var receiveInterval = aggregate.lastReceiveNanos - aggregate.firstReceiveNanos;
        if (sendInterval <= 0 || sendInterval > MAX_INTERVAL_NANOS
                || receiveInterval <= 0 || receiveInterval > MAX_INTERVAL_NANOS) {
            return OptionalLong.empty();
        }
        var sendRate = (aggregate.bytes - aggregate.lastSendSize) * 8e9 / sendInterval;
        var receiveRate = (aggregate.bytes - aggregate.firstReceiveSize) * 8e9 / receiveInterval;
        if (receiveRate > MAX_VALID_RATIO * sendRate) {
            return OptionalLong.empty();
        }
        var estimate = Math.min(sendRate, receiveRate);
        if (receiveRate < MIN_RATIO_FOR_UNSATURATED_LINK * sendRate) {
            estimate = TARGET_UTILIZATION * receiveRate;
        }
        return OptionalLong.of((long) estimate);
    }
}
