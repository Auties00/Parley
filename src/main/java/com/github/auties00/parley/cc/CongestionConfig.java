package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ThreadFactory;
import java.util.function.Consumer;

/// The configuration of a [CongestionController] and its [Pacer], listeners included, so nothing the controller
/// computes can be raised before a listener exists.
///
/// {@snippet lang = java :
/// var config = CongestionConfig.defaults()
///         .withBitrates(50_000, 800_000, 4_000_000)
///         .withThreadFactory(Thread.ofVirtual().name("parley-pacer-", 0).factory())
///         .withTargetListener(target -> allocator.allocate(target.bitsPerSecond(), demands))
///         .withFailureListener(cause -> connection.fail(cause));
/// var controller = CongestionController.gcc(config);
/// }
///
/// @param minBitrateBps    the lowest target the controller ever reports, in bits per second
/// @param startBitrateBps  the target before any feedback arrives
/// @param maxBitrateBps    the highest target the controller ever reports, and the cap of every probe
/// @param pacingFactor     the pacer's rate as a multiple of the target, so encoder overshoot drains quickly; at
///                         least `1`
/// @param maxQueueTime     the longest a packet should wait in the pacer: when the queue would take longer to drain,
///                         the pacer raises its rate above the target to meet this bound, and it drops packets that
///                         waited twice as long
/// @param paceAudio        whether audio packets wait for the pacing budget; when `false` (the default) they are sent
///                         as soon as they are scheduled, since audio is small and latency-critical
/// @param congestionWindow whether the congestion window pushback runs: when more bytes are in flight than the
///                         target rate sends in one round trip plus [CongestionController#WINDOW_QUEUE_ALLOWANCE],
///                         the pacer holds every packet but audio and the target is lowered until the window drains
/// @param clock            the clock every time in the controller is read from
/// @param threadFactory    the factory of the pacer's thread, the only thread the controller starts
/// @param targetListener   told of every new target; see [CongestionController] for its threading
/// @param failureListener  told once, on the pacer's thread, when the pacer stops after a failure it cannot go on
///                         from; the controller then sends nothing more
public record CongestionConfig(long minBitrateBps, long startBitrateBps, long maxBitrateBps, double pacingFactor,
                               Duration maxQueueTime, boolean paceAudio, boolean congestionWindow,
                               MonotonicClock clock, ThreadFactory threadFactory,
                               Consumer<? super TargetBitrate> targetListener,
                               Consumer<? super Throwable> failureListener) {
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
        Objects.requireNonNull(targetListener, "targetListener");
        Objects.requireNonNull(failureListener, "failureListener");
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
    /// queue bound, unpaced audio, the congestion window on, the system clock, virtual threads named
    /// `parley-pacer-<n>`, and listeners that ignore what they are told
    public static CongestionConfig defaults() {
        return new CongestionConfig(DEFAULT_MIN_BITRATE_BPS, DEFAULT_START_BITRATE_BPS, DEFAULT_MAX_BITRATE_BPS,
                DEFAULT_PACING_FACTOR, DEFAULT_MAX_QUEUE_TIME, false, true, System::nanoTime,
                Thread.ofVirtual().name("parley-pacer-", 0).factory(), _ -> {
        }, _ -> {
        });
    }

    /// {@return a copy with the given bitrate bounds}
    ///
    /// @param minBitrateBps   the lowest target
    /// @param startBitrateBps the start target
    /// @param maxBitrateBps   the highest target
    /// @throws IllegalArgumentException if the bitrates are not positive and ordered
    public CongestionConfig withBitrates(long minBitrateBps, long startBitrateBps, long maxBitrateBps) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy with the given pacing factor}
    ///
    /// @param pacingFactor the pacing factor, at least `1`
    /// @throws IllegalArgumentException if `pacingFactor` is below `1`
    public CongestionConfig withPacingFactor(double pacingFactor) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy with the given queue time bound}
    ///
    /// @param maxQueueTime the queue time bound, positive
    /// @throws IllegalArgumentException if `maxQueueTime` is not positive
    public CongestionConfig withMaxQueueTime(Duration maxQueueTime) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy that paces audio or not}
    ///
    /// @param paceAudio whether audio waits for the pacing budget
    public CongestionConfig withPaceAudio(boolean paceAudio) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy with the congestion window pushback on or off}
    ///
    /// @param congestionWindow whether the congestion window pushback runs
    public CongestionConfig withCongestionWindow(boolean congestionWindow) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy reading time from `clock`}
    ///
    /// @param clock the clock
    public CongestionConfig withClock(MonotonicClock clock) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy starting the pacer's thread from `threadFactory`}
    ///
    /// @param threadFactory the thread factory
    public CongestionConfig withThreadFactory(ThreadFactory threadFactory) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy telling `targetListener` of every new target}
    ///
    /// @param targetListener the listener
    public CongestionConfig withTargetListener(Consumer<? super TargetBitrate> targetListener) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }

    /// {@return a copy telling `failureListener` when the pacer stops after a failure}
    ///
    /// @param failureListener the listener
    public CongestionConfig withFailureListener(Consumer<? super Throwable> failureListener) {
        return new CongestionConfig(minBitrateBps, startBitrateBps, maxBitrateBps, pacingFactor, maxQueueTime,
                paceAudio, congestionWindow, clock, threadFactory, targetListener, failureListener);
    }
}
