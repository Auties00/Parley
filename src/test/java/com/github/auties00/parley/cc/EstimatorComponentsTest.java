package com.github.auties00.parley.cc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.OptionalLong;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the building blocks of the GCC estimator one by one, with synthetic packet timings.
@DisplayName("GCC estimator components")
class EstimatorComponentsTest {
    private static final long MS = 1_000_000L;

    @Nested
    @DisplayName("SequenceUnwrapper")
    class Unwrapper {
        @Test
        @DisplayName("unwraps forward and backward across the 16-bit boundary")
        void wraps() {
            var unwrapper = new SequenceUnwrapper(16);
            assertEquals(65534, unwrapper.unwrap(65534));
            assertEquals(65537, unwrapper.unwrap(1));
            assertEquals(65535, unwrapper.unwrap(65535));
            assertEquals(65536 + 100, unwrapper.unwrap(100));
            assertEquals(65536 + 100 - 1, unwrapper.peek(99));
        }

        @ParameterizedTest
        @ValueSource(ints = {8, 16, 24, 32})
        @DisplayName("recovers a random walk with steps under half the range")
        void randomWalk(int bits) {
            var random = new Random(bits);
            var unwrapper = new SequenceUnwrapper(bits);
            var modulus = 1L << bits;
            long truth = random.nextLong(modulus);
            assertEquals(truth, unwrapper.unwrap(truth));
            for (var step = 0; step < 50_000; step++) {
                truth += random.nextLong(-(modulus / 2) + 1, modulus / 2);
                assertEquals(truth - Math.floorDiv(truth, modulus) * modulus, Math.floorMod(truth, modulus));
                var unwrapped = unwrapper.unwrap(Math.floorMod(truth, modulus));
                assertEquals(truth, unwrapped);
            }
        }
    }

    @Nested
    @DisplayName("InterArrival")
    class Groups {
        @Test
        @DisplayName("produces deltas between consecutive 5 ms send groups")
        void groups() {
            var interArrival = new InterArrival();
            assertTrue(interArrival.onPacket(0, 100 * MS, 1000).isEmpty());
            assertTrue(interArrival.onPacket(MS, 101 * MS, 1000).isEmpty());
            assertTrue(interArrival.onPacket(10 * MS, 112 * MS, 500).isEmpty(), "the first group completes, no previous");
            var deltas = interArrival.onPacket(20 * MS, 125 * MS, 500).orElseThrow();
            assertEquals(9 * MS, deltas.sendDeltaNanos());
            assertEquals(11 * MS, deltas.arrivalDeltaNanos());
            assertEquals(-1500, deltas.sizeDeltaBytes());
            assertEquals(2 * MS, deltas.delayVariationNanos());
        }

        @Test
        @DisplayName("keeps packets that arrive in a burst in the same group")
        void burst() {
            var interArrival = new InterArrival();
            interArrival.onPacket(0, 100 * MS, 100);
            interArrival.onPacket(10 * MS, 150 * MS, 100);
            assertTrue(interArrival.onPacket(20 * MS, 151 * MS, 100).isEmpty(), "arrived within 5 ms with negative propagation delta");
            var deltas = interArrival.onPacket(40 * MS, 170 * MS, 100).orElseThrow();
            assertEquals(20 * MS, deltas.sendDeltaNanos());
        }

        @Test
        @DisplayName("ignores packets sent before the current group and resets on a clock jump")
        void outOfOrderAndJumps() {
            var interArrival = new InterArrival();
            interArrival.onPacket(100 * MS, 0, 100);
            assertTrue(interArrival.onPacket(50 * MS, MS, 100).isEmpty());
            interArrival.onPacket(110 * MS, 10 * MS, 100);
            assertTrue(interArrival.onPacket(120 * MS, 10_000 * MS, 100).isPresent());
            assertTrue(interArrival.onPacket(130 * MS, 10_010 * MS, 100).isEmpty(), "a 10 s arrival jump resets");
            assertTrue(interArrival.onPacket(140 * MS, 10_020 * MS, 100).isEmpty(), "the history starts over");
            assertTrue(interArrival.onPacket(150 * MS, 10_030 * MS, 100).isPresent());
        }
    }

    @Nested
    @DisplayName("Trendline and over-use detector")
    class Trendline {
        private BandwidthUsage feed(double delayGrowthMsPerGroup, int groups) {
            var trendline = new TrendlineEstimator();
            var usage = BandwidthUsage.NORMAL;
            for (var group = 1; group <= groups; group++) {
                var arrival = group * 10 * MS;
                usage = trendline.update(new InterArrival.Deltas(10 * MS,
                        10 * MS + (long) (delayGrowthMsPerGroup * MS), 0, arrival + (long) (group * delayGrowthMsPerGroup * MS)));
            }
            return usage;
        }

        @Test
        @DisplayName("signals over-use when the one-way delay keeps growing")
        void overuse() {
            assertEquals(BandwidthUsage.OVERUSING, feed(2, 60));
        }

        @Test
        @DisplayName("signals under-use when the delay keeps shrinking")
        void underuse() {
            assertEquals(BandwidthUsage.UNDERUSING, feed(-2, 60));
        }

        @Test
        @DisplayName("stays normal on a flat delay")
        void normal() {
            assertEquals(BandwidthUsage.NORMAL, feed(0, 100));
        }

        @RepeatedTest(5)
        @DisplayName("keeps the adaptive threshold within its clamps on random input")
        void thresholdBounds(RepetitionInfo repetition) {
            var random = new Random(repetition.getCurrentRepetition());
            var trendline = new TrendlineEstimator();
            var arrival = 0L;
            for (var sample = 0; sample < 5_000; sample++) {
                arrival += random.nextInt(1, 50) * MS;
                trendline.update(new InterArrival.Deltas(10 * MS, (long) ((10 + random.nextGaussian() * 30) * MS), 0, arrival));
                assertTrue(trendline.thresholdMs() >= OveruseDetector.MIN_THRESHOLD_MS);
                assertTrue(trendline.thresholdMs() <= OveruseDetector.MAX_THRESHOLD_MS);
            }
        }
    }

    @Nested
    @DisplayName("AimdRateController")
    class Aimd {
        @Test
        @DisplayName("increases about 8% per second far from capacity")
        void multiplicative() {
            var aimd = new AimdRateController(10_000, 1_000_000, 100_000_000);
            aimd.update(BandwidthUsage.NORMAL, OptionalLong.empty(), 100 * MS, 0);
            for (var step = 1; step <= 10; step++) {
                aimd.update(BandwidthUsage.NORMAL, OptionalLong.empty(), 100 * MS, step * 100 * MS);
            }
            assertEquals(1_080_000, aimd.estimate(), 2_000);
        }

        @Test
        @DisplayName("decreases to 85% of the acknowledged rate on over-use and learns the link capacity")
        void decrease() {
            var aimd = new AimdRateController(10_000, 2_000_000, 100_000_000);
            aimd.update(BandwidthUsage.OVERUSING, OptionalLong.of(1_000_000), 100 * MS, 0);
            assertEquals(850_000, aimd.estimate());
            assertEquals(1_000_000, aimd.linkCapacity().orElseThrow());
            assertFalse(aimd.multiplicativeRegime());
        }

        @Test
        @DisplayName("holds on under-use and increases additively near capacity")
        void holdAndAdditive() {
            var aimd = new AimdRateController(10_000, 2_000_000, 100_000_000);
            aimd.update(BandwidthUsage.OVERUSING, OptionalLong.of(1_000_000), 100 * MS, 0);
            aimd.update(BandwidthUsage.UNDERUSING, OptionalLong.of(1_000_000), 100 * MS, 100 * MS);
            assertEquals(850_000, aimd.estimate());
            aimd.update(BandwidthUsage.NORMAL, OptionalLong.of(900_000), 100 * MS, 200 * MS);
            aimd.update(BandwidthUsage.NORMAL, OptionalLong.of(900_000), 100 * MS, 1200 * MS);
            var increase = aimd.estimate() - 850_000;
            var multiplicative = (long) (850_000 * (Math.pow(1.08, 1.2) - 1));
            assertTrue(increase > 0 && increase < multiplicative, "additive step: " + increase);
        }

        @Test
        @DisplayName("never increases beyond 1.5 times the acknowledged rate")
        void throughputCap() {
            var aimd = new AimdRateController(10_000, 1_000_000, 100_000_000);
            aimd.update(BandwidthUsage.NORMAL, OptionalLong.of(100_000), 100 * MS, 0);
            for (var step = 1; step <= 100; step++) {
                aimd.update(BandwidthUsage.NORMAL, OptionalLong.of(100_000), 100 * MS, step * 100 * MS);
            }
            assertEquals(1_000_000, aimd.estimate(), "an estimate already above the cap is kept, not raised");
        }
    }

    @Nested
    @DisplayName("LossBasedController")
    class Loss {
        @Test
        @DisplayName("increases on low loss, decreases on high loss, holds in between")
        void regimes() {
            var loss = new LossBasedController(10_000, 1_000_000, 10_000_000);
            loss.onLoss(100, 1, 100 * MS, 0);
            assertEquals(1_051_000, loss.estimate());
            loss.onLoss(100, 5, 100 * MS, 1_000 * MS);
            assertEquals(1_051_000, loss.estimate());
            loss.onLoss(100, 20, 100 * MS, 2_000 * MS);
            assertEquals((long) (1_051_000 * 0.9), loss.estimate());
            assertEquals(0.2, loss.lossRatio(), 1e-9);
        }

        @Test
        @DisplayName("waits for twenty packets before evaluating a sample")
        void aggregation() {
            var loss = new LossBasedController(10_000, 1_000_000, 10_000_000);
            assertFalse(loss.onLoss(10, 5, 100 * MS, 0));
            assertEquals(1_000_000, loss.estimate());
            assertTrue(loss.onLoss(10, 0, 100 * MS, MS));
            assertEquals(0.25, loss.lossRatio(), 1e-9);
            assertTrue(loss.estimate() < 1_000_000);
        }

        @Test
        @DisplayName("decreases at most once per 300 ms plus the round-trip time")
        void decreaseSpacing() {
            var loss = new LossBasedController(10_000, 1_000_000, 10_000_000);
            loss.onLoss(100, 50, 100 * MS, 0);
            var once = loss.estimate();
            loss.onLoss(100, 50, 100 * MS, 200 * MS);
            assertEquals(once, loss.estimate());
            loss.onLoss(100, 50, 100 * MS, 400 * MS);
            assertTrue(loss.estimate() < once);
        }
    }

    @Nested
    @DisplayName("AcknowledgedBitrateEstimator")
    class Acknowledged {
        @Test
        @DisplayName("converges on a constant receive rate")
        void constantRate() {
            var estimator = new AcknowledgedBitrateEstimator();
            assertTrue(estimator.estimate().isEmpty());
            for (var packet = 0; packet < 2_000; packet++) {
                estimator.onPacket(packet * MS, 125);
            }
            assertEquals(1_000_000, estimator.estimate().orElseThrow(), 30_000);
        }

        @Test
        @DisplayName("follows a rate change within a few windows")
        void rateChange() {
            var estimator = new AcknowledgedBitrateEstimator();
            var time = 0L;
            for (var packet = 0; packet < 2_000; packet++) {
                estimator.onPacket(time += MS, 125);
            }
            for (var packet = 0; packet < 3_000; packet++) {
                estimator.onPacket(time += MS, 250);
            }
            assertEquals(2_000_000, estimator.estimate().orElseThrow(), 200_000);
        }
    }

    @Nested
    @DisplayName("ProbeBitrateEstimator")
    class ProbeEstimation {
        @Test
        @DisplayName("reports the probe rate when the link carried it unchanged")
        void unsaturated() {
            var estimator = new ProbeBitrateEstimator();
            var cluster = new ProbeCluster(1, 2_000_000, 5, 3_750, 0);
            OptionalLong result = OptionalLong.empty();
            for (var packet = 0; packet < 6; packet++) {
                result = estimator.onProbePacket(cluster, packet * 4 * MS, 50 * MS + packet * 4 * MS, 1000, 100 * MS);
            }
            assertEquals(2_000_000, result.orElseThrow(), 1);
        }

        @Test
        @DisplayName("reports 95% of the receive rate when the link spread the probe out")
        void saturated() {
            var estimator = new ProbeBitrateEstimator();
            var cluster = new ProbeCluster(2, 2_000_000, 5, 3_750, 0);
            OptionalLong result = OptionalLong.empty();
            for (var packet = 0; packet < 6; packet++) {
                result = estimator.onProbePacket(cluster, packet * 4 * MS, 50 * MS + packet * 8 * MS, 1000, 100 * MS);
            }
            assertEquals((long) (0.95 * 1_000_000), result.orElseThrow(), 1);
        }

        @Test
        @DisplayName("waits for enough of the cluster and drops implausible measurements")
        void invalid() {
            var estimator = new ProbeBitrateEstimator();
            var cluster = new ProbeCluster(3, 2_000_000, 5, 3_750, 0);
            assertTrue(estimator.onProbePacket(cluster, 0, 50 * MS, 1000, 0).isEmpty());
            assertTrue(estimator.onProbePacket(cluster, 4 * MS, 50 * MS + 100_000, 1000, 0).isEmpty());
            assertTrue(estimator.onProbePacket(cluster, 8 * MS, 50 * MS + 200_000, 1000, 0).isEmpty());
            assertTrue(estimator.onProbePacket(cluster, 12 * MS, 50 * MS + 300_000, 1000, 0).isEmpty(),
                    "receive rate far above send rate is a broken measurement");
        }
    }

    @Nested
    @DisplayName("ProbeController")
    class Probing {
        @Test
        @DisplayName("starts with probes at three and six times the start rate")
        void initial() {
            var controller = new ProbeController(10_000_000);
            var clusters = controller.onStart(300_000, 0);
            assertEquals(2, clusters.size());
            assertEquals(900_000, clusters.get(0).bitrateBps());
            assertEquals(1_800_000, clusters.get(1).bitrateBps());
            assertTrue(clusters.get(0).minBytes() >= 1);
            assertTrue(controller.exponentialProbing());
        }

        @Test
        @DisplayName("keeps probing at twice the estimate while results reach 70% of the last probe")
        void exponential() {
            var controller = new ProbeController(10_000_000);
            controller.onStart(300_000, 0);
            assertTrue(controller.onEstimate(1_000_000, 10 * MS).isEmpty());
            var next = controller.onEstimate(1_700_000, 20 * MS);
            assertEquals(3_400_000, next.getFirst().bitrateBps());
            assertTrue(controller.onEstimate(1_800_000, 2_000 * MS).isEmpty());
            assertFalse(controller.exponentialProbing());
        }

        @Test
        @DisplayName("caps probes at the maximum and probes a raised maximum")
        void maximum() {
            var controller = new ProbeController(1_000_000);
            var clusters = controller.onStart(300_000, 0);
            assertEquals(1_000_000, clusters.get(1).bitrateBps());
            controller.onEstimate(1_000_000, 10 * MS);
            var raised = controller.onMaxBitrate(2_000_000, 20 * MS);
            assertEquals(2_000_000, raised.getFirst().bitrateBps());
        }

        @Test
        @DisplayName("probes every five seconds while application-limited")
        void alr() {
            var controller = new ProbeController(10_000_000);
            controller.onStart(300_000, 0);
            controller.onEstimate(500_000, 10 * MS);
            assertTrue(controller.onProcess(OptionalLong.empty(), 2_000 * MS).isEmpty());
            assertTrue(controller.onProcess(OptionalLong.of(2_000 * MS), 3_000 * MS).isEmpty());
            var due = controller.onProcess(OptionalLong.of(2_000 * MS), 7_100 * MS);
            assertEquals(1_000_000, due.getFirst().bitrateBps());
            assertTrue(controller.onProcess(OptionalLong.of(2_000 * MS), 8_000 * MS).isEmpty());
        }
    }

    @Test
    @DisplayName("detects an application-limited region and its end")
    void alrDetector() {
        var detector = new AlrDetector(1_000_000);
        var time = 0L;
        for (var step = 0; step < 100; step++) {
            detector.onBytesSent(10, time += 10 * MS);
        }
        assertTrue(detector.alrStartNanos().isPresent());
        for (var step = 0; step < 100; step++) {
            detector.onBytesSent(1_250 * 10, time += 10 * MS);
        }
        assertTrue(detector.alrStartNanos().isEmpty());
    }
}
