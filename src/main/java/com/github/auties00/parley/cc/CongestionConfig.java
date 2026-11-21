package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ThreadFactory;

/// The configuration of a [CongestionController] and its [Pacer].
///
/// {@snippet lang = java :
/// var config = CongestionConfig.defaults()
///         .withBitrates(50_000, 800_000, 4_000_000)
///         .withThreadFactory(Thread.ofVirtual().name("parley-pacer-", 0).factory());
/// var controller = CongestionController.gcc(config);
/// }
///
/// @param minBitrateBps   the lowest target the controller ever reports, in bits per second
/// @param startBitrateBps the target before any feedback arrives
/// @param maxBitrateBps   the highest target the controller ever reports, and the cap of every probe
/// @param pacingFactor    the pacer's rate as a multiple of the target, so encoder overshoot drains quickly;
///                        at least `1`
/// @param maxQueueTime    the longest a packet should wait in the pacer: when the queue would take longer to drain,
///                        the pacer raises its rate above the target to meet this bound
/// @param paceAudio       whether audio packets wait for the pacing budget; when `false` (the default) they are sent
///                        as soon as they are scheduled, since audio is small and latency-critical
/// @param clock           the clock every time in the controller is read from
/// @param threadFactory   the factory of the pacer's thread
public record CongestionConfig(long minBitrateBps, long startBitrateBps, long maxBitrateBps, double pacingFactor,
                               Duration maxQueueTime, boolean paceAudio, MonotonicClock clock,
                               ThreadFactory threadFactory) {
    /// The default lowest target: 30 kbit/s.
    public static final long DEFAULT_MIN_BITRATE_BPS = 30_000;

    /// The default start target: 300 kbit/s.
    public static final long DEFAULT_START_BITRATE_BPS = 300_000;

    /// The default highest target: 10 Mbit/s.
    public static final long DEFAULT_MAX_BITRATE_BPS = 10_000_000;

    /// The default pacing factor, 2.5.
    public static final double DEFAULT_PACING_FACTOR = 2.5;

    /// The default queue time bound: 2 s.
    public static final Duration DEFAULT_MAX_QUEUE_TIME = Duration.ofSeconds(2);

    /// Validates the configuration.
    ///
    /// @throws IllegalArgumentException if `minBitrateBps` is not positive, the bitrates are not ordered
    ///                                  `min <= start <= max`, `pacingFactor` is below `1` or `maxQueueTime` is not
    ///                                  positive
    public CongestionConfig {
        Objects.requireNonNull(maxQueueTime, "maxQueueTime");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(threadFactory, "threadFactory");
        if (minBitrateBps <= 0) {
            throw new IllegalArgumentException("minBitrateBps must be positive: " + minBitrateBps);
        }
        if (startBitrateBps < minBitrateBps || maxBitrateBps < startBitrateBps) {
            throw new IllegalArgumentException("bitrates must satisfy min <= start <= max: "
                    + minBitrateBps + ", " + startBitrateBps + ", " + maxBitrateBps);
        }
        if (!(pacingFactor >= 1)) {
            throw new IllegalArgumentException("pacingFactor must be at least 1: " + pacingFactor);
        }
        if (maxQueueTime.isNegative() || maxQueueTime.isZero()) {
            throw new IllegalArgumentException("maxQueueTime must be positive: " + maxQueueTime);
        }
    }

    /// {@return the default configuration}: 30 kbit/s to 10 Mbit/s starting at 300 kbit/s, pacing factor 2.5, a 2 s
    /// queue bound, unpaced audio, the system clock and virtual threads named `parley-pacer-<n>`
    public static CongestionConfig defaults() {
        return new CongestionConfig(DEFAULT_MIN_BITRATE_BPS, DEFAULT_START_BITRATE_BPS, DEFAULT_MAX_BITRATE_BPS,
                DEFAULT_PACING_FACTOR, DEFAULT_MAX_QUEUE_TIME, false, System::nanoTime,
                Thread.ofVirtual().name("parley-pacer-", 0).factory());
    }

    /// {@return a copy with the given bitrate bounds}
    ///
    /// @param minBitrateBps   the lowest target
    /// @param startBitrateBps the start target
    /// @param maxBitrateBps   the highest target
    /// @throws IllegalArgumentException if the bitrates are not positive and ordered
    public CongestionConfig withBitrates(long minBitrateBps, long startBitrateBps, long maxBitrateBps) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, clock, threadFactory);
    }

    /// {@return a copy with the given pacing factor}
    ///
    /// @param pacingFactor the pacing factor, at least `1`
    /// @throws IllegalArgumentException if `pacingFactor` is below `1`
    public CongestionConfig withPacingFactor(double pacingFactor) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, clock, threadFactory);
    }

    /// {@return a copy with the given queue time bound}
    ///
    /// @param maxQueueTime the queue time bound, positive
    /// @throws IllegalArgumentException if `maxQueueTime` is not positive
    public CongestionConfig withMaxQueueTime(Duration maxQueueTime) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, clock, threadFactory);
    }

    /// {@return a copy that paces audio or not}
    ///
    /// @param paceAudio whether audio waits for the pacing budget
    public CongestionConfig withPaceAudio(boolean paceAudio) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, clock, threadFactory);
    }

    /// {@return a copy reading time from `clock`}
    ///
    /// @param clock the clock
    public CongestionConfig withClock(MonotonicClock clock) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, clock, threadFactory);
    }

    /// {@return a copy starting the pacer's thread from `threadFactory`}
    ///
    /// @param threadFactory the thread factory
    public CongestionConfig withThreadFactory(ThreadFactory threadFactory) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, clock, threadFactory);
    }
}
