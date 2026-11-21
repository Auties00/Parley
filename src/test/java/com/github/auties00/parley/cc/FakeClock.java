package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;

/// A manually advanced clock for deterministic tests.
final class FakeClock implements MonotonicClock {
    private long now;

    FakeClock(long start) {
        this.now = start;
    }

    @Override
    public long nanos() {
        return now;
    }

    void set(long nanos) {
        this.now = nanos;
    }

    void advanceMillis(long millis) {
        now += millis * 1_000_000L;
    }
}
