package com.github.auties00.parley.rtp.session;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/// Tracks the missing packets of one incoming stream and decides when to NACK them again.
///
/// A gap is NACKed as soon as it is seen. A packet still missing is NACKed again once a retransmission had a round
/// trip to arrive, up to the retry limit; a packet that runs out of retries, or a gap too large to track, asks the
/// stream for a keyframe instead. Sequence numbers are unwrapped. Not thread-safe: the owning stream serializes
/// access.
final class NackTracker {
    /// The most missing packets tracked; a larger gap clears the list and asks for a keyframe.
    static final int MAX_MISSING = 1000;
    /// The retry interval while no round-trip time is known.
    static final long DEFAULT_RTT_NANOS = 100_000_000L;
    /// The shortest retry interval, however short the round trip.
    static final long MIN_RETRY_NANOS = 10_000_000L;

    private final int maxRetries;
    private final TreeMap<Long, Missing> missing = new TreeMap<>();
    private long highest = Long.MIN_VALUE;
    private boolean keyframeNeeded;

    private static final class Missing {
        long lastSentNanos = Long.MIN_VALUE;
        int retries;
    }

    NackTracker(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    /// Records a packet.
    ///
    /// @param sequence  the unwrapped sequence number
    /// @param recovered whether the packet came from RTX, FEC or RED rather than the media stream itself, which says
    ///                  nothing about later packets
    /// @return whether the packet had been NACKed, so it is most likely a retransmission
    boolean onPacket(long sequence, boolean recovered) {
        var entry = missing.remove(sequence);
        var nacked = entry != null && entry.lastSentNanos != Long.MIN_VALUE;
        if (recovered) {
            return nacked;
        }
        if (highest == Long.MIN_VALUE) {
            highest = sequence;
            return nacked;
        }
        if (sequence <= highest) {
            return nacked;
        }
        var gap = sequence - highest - 1;
        if (gap > 0) {
            if (missing.size() + gap > MAX_MISSING) {
                missing.clear();
                keyframeNeeded = true;
            } else {
                for (var s = highest + 1; s < sequence; s++) {
                    missing.put(s, new Missing());
                }
            }
        }
        highest = sequence;
        return nacked;
    }

    /// {@return the missing sequence numbers due for a NACK now, oldest first, and marks them sent}
    ///
    /// @param rttNanos the current round-trip time, or a negative value when unknown
    List<Long> due(long nowNanos, long rttNanos) {
        var interval = Math.max(MIN_RETRY_NANOS, rttNanos < 0 ? DEFAULT_RTT_NANOS : rttNanos);
        var out = new ArrayList<Long>();
        for (Iterator<Map.Entry<Long, Missing>> iterator = missing.entrySet().iterator(); iterator.hasNext(); ) {
            var entry = iterator.next();
            var state = entry.getValue();
            if (state.lastSentNanos != Long.MIN_VALUE && nowNanos - state.lastSentNanos < interval) {
                continue;
            }
            if (state.retries >= maxRetries) {
                iterator.remove();
                keyframeNeeded = true;
                continue;
            }
            state.retries++;
            state.lastSentNanos = nowNanos;
            out.add(entry.getKey());
        }
        return out;
    }

    /// {@return the earliest time a retry or give-up is due, or [Long#MAX_VALUE] when nothing is missing}
    long nextDeadline(long rttNanos) {
        var interval = Math.max(MIN_RETRY_NANOS, rttNanos < 0 ? DEFAULT_RTT_NANOS : rttNanos);
        var earliest = Long.MAX_VALUE;
        for (var state : missing.values()) {
            var due = state.lastSentNanos == Long.MIN_VALUE ? Long.MIN_VALUE : state.lastSentNanos + interval;
            earliest = Math.min(earliest, due);
        }
        return earliest;
    }

    /// {@return whether the tracker gave up on a packet since the last call, and clears the flag}
    boolean takeKeyframeNeeded() {
        var needed = keyframeNeeded;
        keyframeNeeded = false;
        return needed;
    }

    /// Forgets every missing packet, after a keyframe made them useless.
    void clear() {
        missing.clear();
    }

    int missingCount() {
        return missing.size();
    }
}
