package com.github.auties00.parley.cc;

import java.util.OptionalDouble;

/// The delay-gradient filter of GCC: accumulates the inter-group delay variation, smooths it exponentially, and
/// estimates its slope over the last [#WINDOW_SIZE] samples by least-squares linear regression. The slope, scaled by
/// the number of samples and [#THRESHOLD_GAIN], feeds an [OveruseDetector].
///
/// @implNote This implementation uses the trendline (linear regression) filter that replaced the Kalman filter of
/// draft-ietf-rmcat-gcc-02 section 5.3 in the deployed algorithm; it reacts to the same gradient with less tuning.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
final class TrendlineEstimator {
    /// The number of samples the regression spans.
    static final int WINDOW_SIZE = 20;

    /// The exponential smoothing coefficient of the accumulated delay.
    static final double SMOOTHING = 0.9;

    /// The gain applied to the slope before it is compared with the threshold.
    static final double THRESHOLD_GAIN = 4.0;

    /// The sample count after which the slope is no longer scaled up further.
    private static final int MAX_DELTAS = 60;

    private final double[] times;
    private final double[] delays;
    private final OveruseDetector detector;
    private int count;
    private int next;
    private long firstArrivalNanos;
    private double accumulatedDelayMs;
    private double smoothedDelayMs;
    private int numDeltas;
    private double trend;

    /// Creates an empty estimator.
    TrendlineEstimator() {
        this.times = new double[WINDOW_SIZE];
        this.delays = new double[WINDOW_SIZE];
        this.detector = new OveruseDetector();
        this.firstArrivalNanos = Long.MIN_VALUE;
    }

    /// Feeds one pair of group deltas.
    ///
    /// @param deltas the inter-group deltas
    /// @return the detector state after the sample
    BandwidthUsage update(InterArrival.Deltas deltas) {
        var arrivalNanos = deltas.arrivalNanos();
        if (firstArrivalNanos == Long.MIN_VALUE) {
            firstArrivalNanos = arrivalNanos;
        }
        var deltaMs = deltas.delayVariationNanos() / 1e6;
        numDeltas = Math.min(numDeltas + 1, 1000);
        accumulatedDelayMs += deltaMs;
        smoothedDelayMs = SMOOTHING * smoothedDelayMs + (1 - SMOOTHING) * accumulatedDelayMs;
        times[next] = (arrivalNanos - firstArrivalNanos) / 1e6;
        delays[next] = smoothedDelayMs;
        next = (next + 1) % WINDOW_SIZE;
        if (count < WINDOW_SIZE) {
            count++;
        }
        if (count == WINDOW_SIZE) {
            trend = slope().orElse(trend);
        }
        var modifiedTrend = Math.min(numDeltas, MAX_DELTAS) * trend * THRESHOLD_GAIN;
        return detector.detect(modifiedTrend, trend, deltas.sendDeltaNanos() / 1e6, arrivalNanos);
    }

    /// {@return the current detector state}
    BandwidthUsage state() {
        return detector.state();
    }

    /// {@return the last estimated slope of the smoothed delay, in milliseconds per millisecond}
    double trend() {
        return trend;
    }

    /// {@return the detector's adaptive threshold, in milliseconds}
    double thresholdMs() {
        return detector.thresholdMs();
    }

    private OptionalDouble slope() {
        double sumX = 0;
        double sumY = 0;
        for (var index = 0; index < count; index++) {
            sumX += times[index];
            sumY += delays[index];
        }
        var meanX = sumX / count;
        var meanY = sumY / count;
        double numerator = 0;
        double denominator = 0;
        for (var index = 0; index < count; index++) {
            var dx = times[index] - meanX;
            numerator += dx * (delays[index] - meanY);
            denominator += dx * dx;
        }
        if (denominator == 0) {
            return OptionalDouble.empty();
        }
        return OptionalDouble.of(numerator / denominator);
    }
}
