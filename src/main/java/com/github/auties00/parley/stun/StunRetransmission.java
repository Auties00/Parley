package com.github.auties00.parley.stun;

import java.time.Duration;
import java.util.Objects;

/// The retransmission schedule of a STUN client transaction.
///
/// Over an unreliable transport a request is sent up to `Rc` times: the first wait is `RTO`, each later one doubles,
/// and after the last transmission the client waits `Rm * RTO` before giving up. With the defaults of RFC 8489
/// section 6.2.1 (`RTO` 500 ms, `Rc` 7, `Rm` 16) requests go out at 0, 500, 1500, 3500, 7500, 15500 and 31500 ms and
/// the transaction fails at 39500 ms. Over a reliable transport the request is sent once and the client waits the
/// transaction timeout `Ti`, 39.5 seconds by default.
///
/// @param initialRto        the first retransmission timeout, `RTO` (or `Ti` when `reliable`)
/// @param maxTransmissions  the number of transmissions, `Rc`; `1` when `reliable`
/// @param lastWaitMultiplier the multiple of `initialRto` waited after the last transmission, `Rm`; `1` when
///                          `reliable`
/// @param reliable          whether the transport is reliable, so the request is never retransmitted
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public record StunRetransmission(Duration initialRto, int maxTransmissions, int lastWaitMultiplier, boolean reliable) {
    /// The schedule of RFC 8489 over UDP: `RTO` 500 ms, `Rc` 7, `Rm` 16.
    public static final StunRetransmission UDP = new StunRetransmission(Duration.ofMillis(500), 7, 16, false);

    /// The schedule of RFC 8489 over TCP and TLS: one transmission, `Ti` 39.5 seconds.
    public static final StunRetransmission RELIABLE = reliable(Duration.ofMillis(39_500));

    /// Creates a schedule.
    ///
    /// @param initialRto         the first retransmission timeout
    /// @param maxTransmissions   the number of transmissions
    /// @param lastWaitMultiplier the multiple of `initialRto` waited after the last transmission
    /// @param reliable           whether the transport is reliable
    /// @throws IllegalArgumentException if `initialRto` is not positive, `maxTransmissions` or `lastWaitMultiplier`
    ///                                  is below `1`, or a reliable schedule has more than one transmission
    public StunRetransmission {
        Objects.requireNonNull(initialRto, "initialRto cannot be null");
        if (initialRto.isNegative() || initialRto.isZero() || maxTransmissions < 1 || lastWaitMultiplier < 1) {
            throw new IllegalArgumentException("invalid retransmission schedule");
        }
        if (reliable && maxTransmissions != 1) {
            throw new IllegalArgumentException("a reliable transport sends a request once");
        }
    }

    /// {@return the schedule of an unreliable transport with a given `RTO` and the default `Rc` and `Rm`}
    ///
    /// @param initialRto the first retransmission timeout
    public static StunRetransmission unreliable(Duration initialRto) {
        return new StunRetransmission(initialRto, 7, 16, false);
    }

    /// {@return the schedule of a reliable transport with a given transaction timeout}
    ///
    /// @param transactionTimeout the time to wait for the response, `Ti`
    public static StunRetransmission reliable(Duration transactionTimeout) {
        return new StunRetransmission(transactionTimeout, 1, 1, true);
    }

    /// {@return the time to wait after transmission number `transmission` (from `0`) before the next one, or before
    /// the transaction fails after the last one}
    ///
    /// @param transmission the transmission number, `0..maxTransmissions - 1`
    /// @throws IllegalArgumentException if `transmission` is out of range
    public Duration waitAfter(int transmission) {
        if (transmission < 0 || transmission >= maxTransmissions) {
            throw new IllegalArgumentException("transmission out of range: " + transmission);
        }
        if (transmission == maxTransmissions - 1) {
            return initialRto.multipliedBy(lastWaitMultiplier);
        }
        return initialRto.multipliedBy(1L << Math.min(transmission, 30));
    }

    /// {@return a schedule that ends no later than `total` after the first transmission}
    ///
    /// An unreliable schedule keeps the transmissions whose doubling waits fit in `total` and shortens the wait after
    /// the last one so the schedule ends at `total` (but never below one `RTO`, and never above `Rm * RTO`); a
    /// reliable one waits `total`. A schedule that already fits is returned unchanged.
    ///
    /// @param total the longest time the transaction may take
    /// @throws IllegalArgumentException if `total` is not positive
    public StunRetransmission truncatedTo(Duration total) {
        Objects.requireNonNull(total, "total cannot be null");
        if (total.isNegative() || total.isZero()) {
            throw new IllegalArgumentException("total must be positive");
        }
        if (totalTimeout().compareTo(total) <= 0) {
            return this;
        }
        if (reliable) {
            return reliable(total);
        }
        var rto = initialRto.toNanos();
        var left = total.toNanos();
        var spent = 0L;
        var transmissions = 0;
        while (transmissions < maxTransmissions) {
            var wait = rto << Math.min(transmissions, 30);
            if (spent + wait > left) {
                break;
            }
            spent += wait;
            transmissions++;
        }
        if (transmissions == 0) {
            return new StunRetransmission(total, 1, 1, false);
        }
        var beforeLast = spent - (rto << Math.min(transmissions - 1, 30));
        var multiplier = Math.clamp((left - beforeLast) / rto, 1, lastWaitMultiplier);
        return new StunRetransmission(initialRto, transmissions, multiplier, false);
    }

    /// {@return the total time from the first transmission until the transaction fails without a response}
    public Duration totalTimeout() {
        var total = Duration.ZERO;
        for (var i = 0; i < maxTransmissions; i++) {
            total = total.plus(waitAfter(i));
        }
        return total;
    }
}
