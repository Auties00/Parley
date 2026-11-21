package com.github.auties00.parley.jitter;

import java.time.Instant;
import java.util.OptionalLong;

/// The synchronization state one jitter buffer keeps for its [SyncGroup]: its measured delay, the extra delay the
/// group asks of it, and the group itself.
///
/// It has its own lock, so the group never takes a buffer's lock: a buffer records under its lock and notifies the
/// group after releasing it.
final class SyncState implements SyncGroup.Member {
    /// The lock that guards every field below.
    private final Object lock = new Object();
    /// The group, or `null`.
    private SyncGroup group;
    /// The delay from capture to playout of the last frame recorded, in nanoseconds, valid when [#known].
    private long delayNanos;
    /// When the last frame was recorded, on the buffer's clock.
    private long recordedNanos;
    /// Whether a delay was measured.
    private boolean known;
    /// The extra delay the group asks for, in nanoseconds.
    private long syncDelayNanos;

    /// Records a frame handed out at `playoutNanos` (the buffer's clock) that was captured at `capture` (the sender's
    /// clock).
    void record(long playoutNanos, Instant capture) {
        synchronized (lock) {
            delayNanos = playoutNanos - CaptureClock.epochNanos(capture);
            recordedNanos = playoutNanos;
            known = true;
        }
    }

    /// Updates the group, if any, after a frame was handed out; called outside the buffer's lock.
    void notifyPlayout() {
        SyncGroup current;
        long now;
        synchronized (lock) {
            current = group;
            now = recordedNanos;
        }
        if (current != null) {
            current.update(now);
        }
    }

    /// Leaves the group, if any, and clears the extra delay.
    void leave() {
        SyncGroup current;
        synchronized (lock) {
            current = group;
            group = null;
            syncDelayNanos = 0;
        }
        if (current != null) {
            current.detach(this);
        }
    }

    @Override
    public OptionalLong delayNanos() {
        synchronized (lock) {
            return known ? OptionalLong.of(delayNanos) : OptionalLong.empty();
        }
    }

    @Override
    public long syncDelayNanos() {
        synchronized (lock) {
            return syncDelayNanos;
        }
    }

    @Override
    public void setSyncDelayNanos(long nanos) {
        synchronized (lock) {
            syncDelayNanos = nanos;
        }
    }

    @Override
    public void joinGroup(SyncGroup newGroup) {
        SyncGroup previous;
        synchronized (lock) {
            previous = group;
            group = newGroup;
        }
        if (previous != null && previous != newGroup) {
            previous.detach(this);
        }
    }
}
