package com.github.auties00.parley.cc;

import java.time.Duration;
import java.util.Objects;

/// A send-rate target produced by a [CongestionController]: what the senders together may send now.
///
/// @param bitsPerSecond       the target rate the encoders should split among themselves, in bits per second
/// @param stableBitsPerSecond a more conservative rate the link has sustained, for decisions that are expensive to
///                            revert (enabling a simulcast layer, raising a resolution); at most `bitsPerSecond`
/// @param lossRatio           the fraction of packets lost in the last loss sample, `0` to `1`
/// @param rtt                 the round-trip time the controller currently assumes
/// @param atNanos             when the target was computed, on the controller's clock
public record TargetBitrate(long bitsPerSecond, long stableBitsPerSecond, double lossRatio, Duration rtt,
                            long atNanos) {
    /// Validates the target.
    ///
    /// @throws IllegalArgumentException if a rate is negative, `stableBitsPerSecond` exceeds `bitsPerSecond`,
    ///                                  `lossRatio` is outside `[0, 1]` or `rtt` is negative
    public TargetBitrate {
        Objects.requireNonNull(rtt, "rtt");
        if (bitsPerSecond < 0 || stableBitsPerSecond < 0) {
            throw new IllegalArgumentException("rates must not be negative");
        }
        if (stableBitsPerSecond > bitsPerSecond) {
            throw new IllegalArgumentException("stableBitsPerSecond must not exceed bitsPerSecond");
        }
        if (!(lossRatio >= 0 && lossRatio <= 1)) {
            throw new IllegalArgumentException("lossRatio must be in [0, 1]: " + lossRatio);
        }
        if (rtt.isNegative()) {
            throw new IllegalArgumentException("rtt must not be negative: " + rtt);
        }
    }
}
