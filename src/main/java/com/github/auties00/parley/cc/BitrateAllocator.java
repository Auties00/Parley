package com.github.auties00.parley.cc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/// Splits a [TargetBitrate] across senders and their simulcast encodings.
///
/// The allocation runs in three passes over the active encodings:
///
/// 1. In descending priority, each sender's smallest encoding (largest `scaleResolutionDownBy`) receives its minimum
///    rate while the target lasts; a sender whose smallest encoding does not fit is suspended entirely.
/// 2. The rest of the target is shared among the senders in proportion to their priority (the highest priority of
///    their active encodings). Within a sender the share fills the encodings bottom-up: an encoding is filled to its
///    maximum before the next larger one is enabled, and the next one is enabled only when the share covers its
///    minimum.
/// 3. Whatever a sender could not absorb in proportion (because its next encoding needed more than its share) is
///    offered again, in priority order, to the senders that can still use it.
///
/// To keep an encoding from flapping on and off around its minimum, an encoding that was not allocated anything by
/// the previous call is enabled only once its minimum plus [#ENABLE_HYSTERESIS] of it is available.
///
/// A sender may have a ceiling ([#allocate(long, List, Map)]): the cap its m-section's `b=AS` or `b=TIAS` puts on
/// all its encodings together. Its encodings then share at most the ceiling, filled bottom-up as above, and a
/// ceiling below the smallest encoding's minimum lowers that minimum to the ceiling rather than suspend the sender:
/// the remote asked for less than the encoder's floor, and a slower stream is better than none.
///
/// # Threading
///
/// Instances are safe for use from several threads; calls are serialized, since each depends on the encodings the
/// previous one enabled.
///
/// @spec https://www.w3.org/TR/webrtc/#dom-rtcrtpencodingparameters WebRTC: Real-Time Communication in Browsers, RTCRtpEncodingParameters
public final class BitrateAllocator {
    /// The fraction of its minimum an encoding that was off needs on top of the minimum to be enabled: 15%.
    public static final double ENABLE_HYSTERESIS = 0.15;

    private final ReentrantLock lock;
    private Set<AllocationKey> enabled;

    /// Creates an allocator with no allocation history.
    public BitrateAllocator() {
        this.lock = new ReentrantLock();
        this.enabled = Set.of();
    }

    /// Splits `targetBps` among `demands`.
    ///
    /// @param targetBps the rate to split, in bits per second
    /// @param demands   one demand per encoding
    /// @return an unmodifiable map from every demand's key to its rate in bits per second, in the order of
    ///         `demands`; inactive and suspended encodings map to `0`, and the rates sum to at most `targetBps`
    /// @throws IllegalArgumentException if `targetBps` is negative or two demands have the same key
    public Map<AllocationKey, Long> allocate(long targetBps, List<EncodingDemand> demands) {
        return allocate(targetBps, demands, Map.of());
    }

    /// Splits `targetBps` among `demands`, keeping each sender within its ceiling.
    ///
    /// @param targetBps the rate to split, in bits per second
    /// @param demands   one demand per encoding
    /// @param ceilings  the highest rate all the encodings of a sender may share together, by sender id, in bits per
    ///                  second; a sender without an entry has no ceiling
    /// @return an unmodifiable map from every demand's key to its rate in bits per second, in the order of
    ///         `demands`; inactive and suspended encodings map to `0`, the rates sum to at most `targetBps`, and the
    ///         rates of one sender to at most its ceiling
    /// @throws IllegalArgumentException if `targetBps` or a ceiling is negative, or two demands have the same key
    /// @spec https://www.rfc-editor.org/rfc/rfc3890.html RFC 3890: A Transport Independent Bandwidth Modifier for the Session Description Protocol (SDP)
    public Map<AllocationKey, Long> allocate(long targetBps, List<EncodingDemand> demands, Map<String, Long> ceilings) {
        Objects.requireNonNull(demands, "demands");
        Objects.requireNonNull(ceilings, "ceilings");
        for (var ceiling : ceilings.entrySet()) {
            if (ceiling.getValue() < 0) {
                throw new IllegalArgumentException("ceiling must not be negative: " + ceiling);
            }
        }
        if (targetBps < 0) {
            throw new IllegalArgumentException("targetBps must not be negative: " + targetBps);
        }
        var keys = new HashSet<AllocationKey>();
        for (var demand : demands) {
            Objects.requireNonNull(demand, "demands contains null");
            if (!keys.add(demand.key())) {
                throw new IllegalArgumentException("duplicate allocation key: " + demand.key());
            }
        }
        lock.lock();
        try {
            return allocateLocked(targetBps, demands, ceilings);
        } finally {
            lock.unlock();
        }
    }

    private Map<AllocationKey, Long> allocateLocked(long targetBps, List<EncodingDemand> demands,
                                                    Map<String, Long> ceilings) {
        var senders = new LinkedHashMap<String, Sender>();
        for (var demand : demands) {
            if (demand.active()) {
                senders.computeIfAbsent(demand.key().senderId(), Sender::new).layers.add(demand);
            }
        }
        var ordered = new ArrayList<>(senders.values());
        for (var sender : ordered) {
            var ceiling = ceilings.get(sender.id);
            sender.prepare(enabled, ceiling == null ? Double.POSITIVE_INFINITY : ceiling);
        }
        ordered.sort(Comparator.comparingDouble((Sender sender) -> sender.priority).reversed());
        double remaining = targetBps;
        var running = new ArrayList<Sender>();
        for (var sender : ordered) {
            if (sender.floor(0) > 0 && remaining >= sender.threshold(0)) {
                sender.allocation[0] = sender.floor(0);
                sender.enabledLayers = 1;
                remaining -= sender.floor(0);
                running.add(sender);
            }
        }
        var unsaturated = new ArrayList<>(running);
        for (var round = 0; round < 64 && remaining > 0.5 && !unsaturated.isEmpty(); round++) {
            var totalPriority = unsaturated.stream().mapToDouble(sender -> sender.priority).sum();
            double used = 0;
            var stillUnsaturated = new ArrayList<Sender>();
            for (var sender : unsaturated) {
                var share = remaining * sender.priority / totalPriority;
                var took = sender.absorb(share);
                used += took;
                if (took >= share - 1e-6) {
                    stillUnsaturated.add(sender);
                }
            }
            remaining -= used;
            unsaturated = stillUnsaturated;
            if (used <= 1e-9) {
                break;
            }
        }
        var progress = true;
        while (remaining > 0.5 && progress) {
            progress = false;
            for (var sender : running) {
                var took = sender.absorb(remaining);
                if (took > 0) {
                    remaining -= took;
                    progress = true;
                }
            }
        }
        var result = new LinkedHashMap<AllocationKey, Long>();
        var nowEnabled = new HashSet<AllocationKey>();
        for (var demand : demands) {
            result.put(demand.key(), 0L);
        }
        for (var sender : running) {
            for (var index = 0; index < sender.enabledLayers; index++) {
                var key = sender.layers.get(index).key();
                result.put(key, (long) Math.floor(sender.allocation[index]));
                nowEnabled.add(key);
            }
        }
        enabled = nowEnabled;
        return Collections.unmodifiableMap(result);
    }

    /// The active encodings of one sender during one allocation.
    private static final class Sender {
        final String id;
        final List<EncodingDemand> layers;
        double priority;
        double ceiling;
        double[] allocation;
        double[] floors;
        double[] thresholds;
        int enabledLayers;

        Sender(String id) {
            this.id = id;
            this.layers = new ArrayList<>();
        }

        void prepare(Set<AllocationKey> previouslyEnabled, double ceiling) {
            layers.sort(Comparator.comparingDouble(EncodingDemand::scaleResolutionDownBy).reversed());
            priority = layers.stream().mapToDouble(EncodingDemand::priority).max().orElse(1);
            this.ceiling = ceiling;
            allocation = new double[layers.size()];
            floors = new double[layers.size()];
            thresholds = new double[layers.size()];
            for (var index = 0; index < layers.size(); index++) {
                var layer = layers.get(index);
                var min = index == 0 ? Math.min(layer.minBitrateBps(), ceiling) : (double) layer.minBitrateBps();
                floors[index] = min;
                thresholds[index] = previouslyEnabled.contains(layer.key()) ? min : min * (1 + ENABLE_HYSTERESIS);
            }
        }

        double floor(int index) {
            return floors[index];
        }

        double threshold(int index) {
            return thresholds[index];
        }

        double total() {
            double sum = 0;
            for (var index = 0; index < enabledLayers; index++) {
                sum += allocation[index];
            }
            return sum;
        }

        double absorb(double amount) {
            double took = 0;
            while (amount - took > 1e-9) {
                var headroom = ceiling - total();
                if (headroom <= 1e-9) {
                    break;
                }
                var top = enabledLayers - 1;
                var room = Math.min(Math.min(layers.get(top).maxBitrateBps(), ceiling) - allocation[top], headroom);
                if (room > 1e-9) {
                    var add = Math.min(room, amount - took);
                    allocation[top] += add;
                    took += add;
                    continue;
                }
                if (enabledLayers == layers.size()) {
                    break;
                }
                if (amount - took + 1e-9 < thresholds[enabledLayers] || headroom + 1e-9 < floors[enabledLayers]) {
                    break;
                }
                allocation[enabledLayers] = floors[enabledLayers];
                took += floors[enabledLayers];
                enabledLayers++;
            }
            return took;
        }
    }
}
