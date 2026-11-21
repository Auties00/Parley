package com.github.auties00.parley.cc;

import java.util.OptionalLong;

/// Estimates the throughput the receiver acknowledged, from the sizes and arrival times of the packets transport
/// feedback reports as received.
///
/// Bytes are summed over a window ([#INITIAL_WINDOW_NANOS] for the first sample, [#WINDOW_NANOS] afterwards) and each
/// window's rate updates the estimate by a scalar Bayesian filter whose sample uncertainty grows with the sample's
/// distance from the estimate, so single outliers move it little while a sustained change moves it within a few
/// windows.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class AcknowledgedBitrateEstimator {
    /// The window of the first sample.
    static final long INITIAL_WINDOW_NANOS = 500_000_000L;

    /// The window of later samples.
    static final long WINDOW_NANOS = 150_000_000L;

    /// The scale of the sample uncertainty.
    private static final double UNCERTAINTY_SCALE = 10;

    /// The process noise added to the estimate variance per sample.
    private static final double VARIANCE_INCREASE = 5;

    private long windowStartNanos;
    private boolean windowStarted;
    private long windowBytes;
    private double estimateKbps;
    private double varianceKbps;
    private boolean estimated;

    /// Creates an estimator with no estimate.
    AcknowledgedBitrateEstimator() {
        this.varianceKbps = 50;
    }

    /// Feeds one acknowledged packet, in arrival order.
    ///
    /// @param arrivalNanos the arrival time on the receiver's clock
    /// @param sizeBytes    the packet size
    void onPacket(long arrivalNanos, int sizeBytes) {
        if (!windowStarted || arrivalNanos < windowStartNanos) {
            windowStarted = true;
            windowStartNanos = arrivalNanos;
            windowBytes = 0;
        }
        var window = estimated ? WINDOW_NANOS : INITIAL_WINDOW_NANOS;
        var elapsed = arrivalNanos - windowStartNanos;
        if (elapsed > window) {
            var sampleKbps = windowBytes * 8.0 / (elapsed / 1e6);
            update(sampleKbps);
            windowStartNanos = arrivalNanos;
            windowBytes = 0;
        }
        windowBytes += sizeBytes;
    }

    /// {@return the estimated acknowledged throughput, in bits per second, if enough data was acknowledged}
    OptionalLong estimate() {
        return estimated ? OptionalLong.of((long) (estimateKbps * 1000)) : OptionalLong.empty();
    }

    /// Forgets the window under construction, as when the sender leaves application-limited mode and the old
    /// window would understate the link.
    void resetWindow() {
        windowStarted = false;
    }

    private void update(double sampleKbps) {
        if (!estimated) {
            estimateKbps = sampleKbps;
            estimated = true;
            return;
        }
        var uncertainty = UNCERTAINTY_SCALE * Math.abs(estimateKbps - sampleKbps) / Math.max(estimateKbps, 1e-3);
        var sampleVariance = uncertainty * uncertainty;
        var predictedVariance = varianceKbps + VARIANCE_INCREASE;
        var total = sampleVariance + predictedVariance;
        if (total == 0) {
            estimateKbps = sampleKbps;
            return;
        }
        estimateKbps = (sampleVariance * estimateKbps + predictedVariance * sampleKbps) / total;
        varianceKbps = sampleVariance * predictedVariance / total;
    }
}
