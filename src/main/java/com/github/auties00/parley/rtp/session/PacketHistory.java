package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.RtpPacket;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/// The packets a send stream sent recently, kept so NACKs can be served, by sequence number.
///
/// Entries leave when older than the history length or when more than [#MAX_PACKETS] are kept. Not thread-safe:
/// the owning stream serializes access.
final class PacketHistory {
    /// The most packets kept, whatever their age: 2^15, half the sequence space, so a number is never ambiguous.
    static final int MAX_PACKETS = 1 << 15;

    private final long maxAgeNanos;
    private final Map<Integer, Entry> bySequence = new HashMap<>();
    private final ArrayDeque<Entry> order = new ArrayDeque<>();

    /// One stored packet.
    static final class Entry {
        final RtpPacket packet;
        final long storedNanos;
        final OutgoingPacketScheduler.Priority priority;
        long lastResentNanos = Long.MIN_VALUE;
        int resends;

        Entry(RtpPacket packet, long storedNanos, OutgoingPacketScheduler.Priority priority) {
            this.packet = packet;
            this.storedNanos = storedNanos;
            this.priority = priority;
        }
    }

    PacketHistory(long maxAgeNanos) {
        this.maxAgeNanos = maxAgeNanos;
    }

    /// Stores an independent copy of a packet.
    void store(RtpPacket packet, long nowNanos, OutgoingPacketScheduler.Priority priority) {
        prune(nowNanos);
        var entry = new Entry(packet, nowNanos, priority);
        var previous = bySequence.put(packet.sequence(), entry);
        if (previous != null) {
            order.remove(previous);
        }
        order.addLast(entry);
        while (order.size() > MAX_PACKETS) {
            bySequence.remove(order.removeFirst().packet.sequence());
        }
    }

    Optional<Entry> find(int sequence, long nowNanos) {
        prune(nowNanos);
        return Optional.ofNullable(bySequence.get(sequence));
    }

    /// {@return the most recently stored packets, newest first, up to `limit`}
    java.util.List<Entry> newest(int limit) {
        var out = new java.util.ArrayList<Entry>(Math.min(limit, order.size()));
        var iterator = order.descendingIterator();
        while (iterator.hasNext() && out.size() < limit) {
            out.add(iterator.next());
        }
        return out;
    }

    int size() {
        return order.size();
    }

    private void prune(long nowNanos) {
        while (!order.isEmpty() && nowNanos - order.peekFirst().storedNanos > maxAgeNanos) {
            bySequence.remove(order.removeFirst().packet.sequence());
        }
    }
}
