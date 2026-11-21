package com.github.auties00.parley.cc;

import java.util.Optional;

/// Groups packets sent in short bursts and computes the inter-group delay variation of the GCC arrival-time model:
/// the difference between the inter-arrival time and the inter-departure time of two consecutive groups.
///
/// A group spans packets sent within [#GROUP_LENGTH_NANOS] of its first packet. A packet that arrives within
/// [#BURST_DELTA_NANOS] of the previous one with a non-positive propagation delta joins the current group even when
/// it was sent later, because a burst that left a queue together carries no delay information of its own.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class InterArrival {
    /// The send-time span of one group: 5 ms, the burst time of draft-ietf-rmcat-gcc-02 section 5.2.
    static final long GROUP_LENGTH_NANOS = 5_000_000L;

    /// The arrival spacing under which a packet is considered part of a burst.
    static final long BURST_DELTA_NANOS = 5_000_000L;

    /// The longest a burst may last before a new group is forced.
    static final long MAX_BURST_DURATION_NANOS = 100_000_000L;

    /// The arrival-minus-send jump after which the history is considered broken (clock jump or reordering) and reset.
    static final long ARRIVAL_JUMP_NANOS = 3_000_000_000L;

    /// The deltas between two complete groups.
    ///
    /// @param sendDeltaNanos    the departure spacing of the last packets of the two groups
    /// @param arrivalDeltaNanos the arrival spacing of the last packets of the two groups
    /// @param sizeDeltaBytes    the size difference of the two groups
    /// @param arrivalNanos      the arrival time of the newer group's last packet
    record Deltas(long sendDeltaNanos, long arrivalDeltaNanos, long sizeDeltaBytes, long arrivalNanos) {
        /// {@return the delay variation, arrival delta minus send delta, in nanoseconds}
        long delayVariationNanos() {
            return arrivalDeltaNanos - sendDeltaNanos;
        }
    }

    /// One packet group under construction or complete.
    private static final class Group {
        long firstSendNanos;
        long lastSendNanos;
        long firstArrivalNanos;
        long lastArrivalNanos;
        long sizeBytes;
    }

    /// The group being built; `null` before the first packet.
    private Group current;

    /// The last complete group; `null` until two groups were seen.
    private Group previous;

    /// Feeds one received packet, in arrival order.
    ///
    /// @param sendNanos    the departure time on the sender's clock
    /// @param arrivalNanos the arrival time on the receiver's clock
    /// @param sizeBytes    the packet size
    /// @return the deltas between the two groups completed by this packet, if it completed one
    Optional<Deltas> onPacket(long sendNanos, long arrivalNanos, int sizeBytes) {
        if (current == null) {
            current = newGroup(sendNanos, arrivalNanos, sizeBytes);
            return Optional.empty();
        }
        if (sendNanos < current.firstSendNanos) {
            return Optional.empty();
        }
        Optional<Deltas> result = Optional.empty();
        if (startsNewGroup(sendNanos, arrivalNanos)) {
            if (previous != null) {
                var sendDelta = current.lastSendNanos - previous.lastSendNanos;
                var arrivalDelta = current.lastArrivalNanos - previous.lastArrivalNanos;
                var sizeDelta = current.sizeBytes - previous.sizeBytes;
                if (Math.abs(arrivalDelta - sendDelta) > ARRIVAL_JUMP_NANOS || arrivalDelta < 0) {
                    previous = null;
                    current = newGroup(sendNanos, arrivalNanos, sizeBytes);
                    return Optional.empty();
                }
                result = Optional.of(new Deltas(sendDelta, arrivalDelta, sizeDelta, current.lastArrivalNanos));
            }
            previous = current;
            current = newGroup(sendNanos, arrivalNanos, sizeBytes);
        } else {
            current.lastSendNanos = Math.max(current.lastSendNanos, sendNanos);
            current.lastArrivalNanos = Math.max(current.lastArrivalNanos, arrivalNanos);
            current.sizeBytes += sizeBytes;
        }
        return result;
    }

    /// Forgets every group, as after a long gap in feedback.
    void reset() {
        current = null;
        previous = null;
    }

    private boolean startsNewGroup(long sendNanos, long arrivalNanos) {
        if (belongsToBurst(sendNanos, arrivalNanos)) {
            return false;
        }
        return sendNanos - current.firstSendNanos > GROUP_LENGTH_NANOS;
    }

    private boolean belongsToBurst(long sendNanos, long arrivalNanos) {
        var arrivalDelta = arrivalNanos - current.lastArrivalNanos;
        var sendDelta = sendNanos - current.lastSendNanos;
        if (sendDelta == 0) {
            return true;
        }
        var propagationDelta = arrivalDelta - sendDelta;
        return propagationDelta < 0
                && arrivalDelta <= BURST_DELTA_NANOS
                && arrivalNanos - current.firstArrivalNanos < MAX_BURST_DURATION_NANOS;
    }

    private static Group newGroup(long sendNanos, long arrivalNanos, int sizeBytes) {
        var group = new Group();
        group.firstSendNanos = sendNanos;
        group.lastSendNanos = sendNanos;
        group.firstArrivalNanos = arrivalNanos;
        group.lastArrivalNanos = arrivalNanos;
        group.sizeBytes = sizeBytes;
        return group;
    }
}
