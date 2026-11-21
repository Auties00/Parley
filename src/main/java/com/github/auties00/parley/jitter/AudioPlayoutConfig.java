package com.github.auties00.parley.jitter;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.DepacketizerConfig;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/// The settings of an [AudioPlayoutBuffer].
///
/// @param clock                the clock that times playout and arrivals; arrivals passed to the buffer must come
///                             from it
/// @param minimumDelay         the lowest target delay, at least zero
/// @param maximumDelay         the highest target delay, and the longest the buffer conceals an outage before it stops
///                             the schedule and waits for packets; positive, at least `minimumDelay`
/// @param jitterBufferTarget   the application's preferred delay, the W3C `jitterBufferTarget`, `0..4000` ms: the
///                             target never goes below it (nor above `maximumDelay`); empty to let the buffer decide
/// @param defaultFrameDuration the frame duration assumed until packets tell it, positive
/// @param maxPackets           the most packets held at once; older ones are discarded beyond it; positive
/// @param depacketizer         the header extensions the buffer's depacketizer reads
/// @spec https://www.w3.org/TR/webrtc-extensions/#dom-rtcrtpreceiver-jitterbuffertarget W3C WebRTC Extensions: jitterBufferTarget
public record AudioPlayoutConfig(MonotonicClock clock, Duration minimumDelay, Duration maximumDelay,
                                 Optional<Duration> jitterBufferTarget, Duration defaultFrameDuration, int maxPackets,
                                 DepacketizerConfig depacketizer) {
    /// The largest `jitterBufferTarget` the W3C extension accepts.
    public static final Duration MAX_JITTER_BUFFER_TARGET = Duration.ofMillis(4000);

    /// Creates settings.
    ///
    /// @param clock                the clock
    /// @param minimumDelay         the lowest target delay
    /// @param maximumDelay         the highest target delay
    /// @param jitterBufferTarget   the preferred delay
    /// @param defaultFrameDuration the default frame duration
    /// @param maxPackets           the packet limit
    /// @param depacketizer         the depacketizer settings
    /// @throws IllegalArgumentException if a value is outside its range
    public AudioPlayoutConfig {
        Objects.requireNonNull(clock, "clock cannot be null");
        Objects.requireNonNull(minimumDelay, "minimumDelay cannot be null");
        Objects.requireNonNull(maximumDelay, "maximumDelay cannot be null");
        Objects.requireNonNull(jitterBufferTarget, "jitterBufferTarget cannot be null");
        Objects.requireNonNull(defaultFrameDuration, "defaultFrameDuration cannot be null");
        Objects.requireNonNull(depacketizer, "depacketizer cannot be null");
        if (minimumDelay.isNegative() || !maximumDelay.isPositive() || maximumDelay.compareTo(minimumDelay) < 0) {
            throw new IllegalArgumentException("invalid delay range " + minimumDelay + ".." + maximumDelay);
        }
        checkTarget(jitterBufferTarget);
        if (!defaultFrameDuration.isPositive() || maxPackets <= 0) {
            throw new IllegalArgumentException("frame duration and packet limit must be positive");
        }
    }

    /// {@return the settings of a typical call: the system clock, delays from zero to two seconds, no preferred delay,
    /// 20 ms frames until told otherwise, at most 500 packets}
    public static AudioPlayoutConfig defaults() {
        return new AudioPlayoutConfig(MonotonicClock.system(), Duration.ZERO, Duration.ofSeconds(2), Optional.empty(),
                Duration.ofMillis(20), 500, DepacketizerConfig.none());
    }

    /// {@return a copy with another clock}
    ///
    /// @param newClock the clock
    public AudioPlayoutConfig withClock(MonotonicClock newClock) {
        return new AudioPlayoutConfig(newClock, minimumDelay, maximumDelay, jitterBufferTarget, defaultFrameDuration,
                maxPackets, depacketizer);
    }

    /// {@return a copy with other delay bounds}
    ///
    /// @param minimum the lowest target delay
    /// @param maximum the highest target delay
    /// @throws IllegalArgumentException if the range is invalid
    public AudioPlayoutConfig withDelayRange(Duration minimum, Duration maximum) {
        return new AudioPlayoutConfig(clock, minimum, maximum, jitterBufferTarget, defaultFrameDuration, maxPackets,
                depacketizer);
    }

    /// {@return a copy with a preferred delay}
    ///
    /// @param target the preferred delay, `0..4000` ms
    /// @throws IllegalArgumentException if `target` is out of range
    public AudioPlayoutConfig withJitterBufferTarget(Duration target) {
        return new AudioPlayoutConfig(clock, minimumDelay, maximumDelay, Optional.of(target), defaultFrameDuration,
                maxPackets, depacketizer);
    }

    /// {@return a copy without a preferred delay, which lets the buffer decide}
    public AudioPlayoutConfig withoutJitterBufferTarget() {
        return new AudioPlayoutConfig(clock, minimumDelay, maximumDelay, Optional.empty(), defaultFrameDuration,
                maxPackets, depacketizer);
    }

    /// {@return a copy with other depacketizer settings}
    ///
    /// @param config the depacketizer settings
    public AudioPlayoutConfig withDepacketizer(DepacketizerConfig config) {
        return new AudioPlayoutConfig(clock, minimumDelay, maximumDelay, jitterBufferTarget, defaultFrameDuration,
                maxPackets, config);
    }

    /// Checks a `jitterBufferTarget`.
    ///
    /// @throws IllegalArgumentException if it is negative or above four seconds
    static void checkTarget(Optional<Duration> target) {
        Objects.requireNonNull(target, "jitterBufferTarget cannot be null");
        if (target.isPresent() && (target.get().isNegative() || target.get().compareTo(MAX_JITTER_BUFFER_TARGET) > 0)) {
            throw new IllegalArgumentException("jitterBufferTarget out of range 0..4000 ms: " + target.get());
        }
    }
}
