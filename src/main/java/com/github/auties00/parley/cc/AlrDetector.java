package com.github.auties00.parley.cc;

import java.util.OptionalLong;

/// Detects application-limited regions: periods in which the sender sends clearly less than the target rate because
/// the application has nothing more to send, so feedback says nothing about the link above the sent rate.
///
/// A budget accrues at [#BANDWIDTH_USAGE_RATIO] of the target rate over a [#WINDOW_NANOS] window and every sent byte
/// spends from it. The region starts when more than [#START_BUDGET_RATIO] of the window's budget is unspent and ends
/// when less than [#STOP_BUDGET_RATIO] is.
final class AlrDetector {
    /// The fraction of the target rate the budget accrues at.
    static final double BANDWIDTH_USAGE_RATIO = 0.65;

    /// The unspent budget fraction that starts a region.
    static final double START_BUDGET_RATIO = 0.80;

    /// The unspent budget fraction that ends a region.
    static final double STOP_BUDGET_RATIO = 0.50;

    /// The budget window: 500 ms.
    static final long WINDOW_NANOS = 500_000_000L;

    private long targetBitrateBps;
    private double bytesRemaining;
    private long lastNanos;
    private boolean started;
    private long alrStartNanos;
    private boolean inAlr;

    /// Creates a detector for a target rate.
    ///
    /// @param targetBitrateBps the initial target rate
    AlrDetector(long targetBitrateBps) {
        this.targetBitrateBps = targetBitrateBps;
    }

    /// Changes the target rate.
    ///
    /// @param targetBitrateBps the new target rate
    void setTargetBitrate(long targetBitrateBps) {
        this.targetBitrateBps = targetBitrateBps;
    }

    /// Records `bytes` sent at `nowNanos`; zero bytes only advances time.
    ///
    /// @param bytes    the bytes sent
    /// @param nowNanos the current time
    void onBytesSent(long bytes, long nowNanos) {
        if (!started) {
            started = true;
            lastNanos = nowNanos;
        }
        var maxBytes = maxBytes();
        var elapsed = Math.max(0, nowNanos - lastNanos);
        lastNanos = nowNanos;
        bytesRemaining = Math.min(bytesRemaining + BANDWIDTH_USAGE_RATIO * targetBitrateBps * elapsed / 8e9, maxBytes);
        bytesRemaining = Math.max(bytesRemaining - bytes, -maxBytes);
        var ratio = maxBytes <= 0 ? 0 : bytesRemaining / maxBytes;
        if (!inAlr && ratio > START_BUDGET_RATIO) {
            inAlr = true;
            alrStartNanos = nowNanos;
        } else if (inAlr && ratio < STOP_BUDGET_RATIO) {
            inAlr = false;
        }
    }

    /// {@return when the current application-limited region started, empty outside one}
    OptionalLong alrStartNanos() {
        return inAlr ? OptionalLong.of(alrStartNanos) : OptionalLong.empty();
    }

    private double maxBytes() {
        return BANDWIDTH_USAGE_RATIO * targetBitrateBps * WINDOW_NANOS / 8e9;
    }
}
