package com.github.auties00.parley.net;

/// A source of monotonic time in nanoseconds, the time base of every timer and timestamp in Parley.
///
/// Values are meaningful only as differences between two readings of the same clock, like [System#nanoTime()]. Tests
/// pass a clock they advance by hand to make timers deterministic.
@FunctionalInterface
public interface MonotonicClock {
    /// {@return the current time in nanoseconds, never smaller than a previous reading of the same clock}
    long nanos();

    /// {@return the clock backed by [System#nanoTime()]}
    static MonotonicClock system() {
        return System::nanoTime;
    }
}
