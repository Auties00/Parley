package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Exercises the whole controller: closed-loop runs through a simulated bottleneck ([CongestionSimulation]) for
/// ramp-up, probing, delay-based backoff and loss-based backoff, and direct feedback for REMB and receiver reports.
@DisplayName("Google congestion control")
class GoogleCongestionControllerTest {
    private static final long MS = 1_000_000L;

    private static CongestionConfig config(long start, long max) {
        return CongestionConfig.defaults().withBitrates(30_000, start, max);
    }

    @Nested
    @DisplayName("through a simulated bottleneck")
    class Simulated {
        @Test
        @DisplayName("ramps up to the link capacity without building a standing queue")
        void rampUp() {
            var simulation = new CongestionSimulation(config(300_000, 5_000_000), 2_500_000);
            simulation.run(20_000);
            var target = simulation.target();
            assertTrue(target >= 1_500_000 && target <= 3_000_000, "target " + target);
            assertTrue(simulation.lastQueueDelayMillis() < 300, "queue " + simulation.lastQueueDelayMillis() + " ms");
        }

        @Test
        @DisplayName("probes to a high capacity within two seconds, far faster than the 8% per second increase")
        void probing() {
            var simulation = new CongestionSimulation(config(300_000, 10_000_000), 4_000_000);
            simulation.run(2_000);
            var target = simulation.target();
            assertTrue(target >= 1_000_000, "target after 2 s " + target);
            assertTrue(target <= 4_500_000, "target after 2 s " + target);
        }

        @Test
        @DisplayName("backs off when the bottleneck capacity drops, then drains the queue")
        void delayBackoff() {
            var simulation = new CongestionSimulation(config(300_000, 5_000_000), 2_000_000);
            simulation.run(15_000);
            var before = simulation.target();
            assertTrue(before >= 1_200_000, "target before the drop " + before);
            simulation.setCapacity(600_000);
            simulation.run(10_000);
            var after = simulation.target();
            assertTrue(after <= 800_000, "target after the drop " + after);
            assertTrue(after >= 200_000, "target after the drop " + after);
            assertTrue(simulation.lastQueueDelayMillis() < 500, "queue " + simulation.lastQueueDelayMillis() + " ms");
        }

        @Test
        @DisplayName("backs off on heavy random loss even without queueing delay")
        void lossBackoff() {
            var simulation = new CongestionSimulation(config(1_000_000, 5_000_000), 50_000_000);
            simulation.setLossRate(0.2);
            simulation.run(15_000);
            assertTrue(simulation.target() <= 300_000, "target " + simulation.target());
            assertTrue(simulation.controller.currentTarget().lossRatio() > 0.1);
        }

        @Test
        @DisplayName("keeps growing on light random loss")
        void lightLoss() {
            var simulation = new CongestionSimulation(config(300_000, 3_000_000), 50_000_000);
            simulation.setLossRate(0.01);
            simulation.run(15_000);
            assertTrue(simulation.target() >= 1_500_000, "target " + simulation.target());
        }

        @Test
        @DisplayName("probes periodically while the encoder is application-limited")
        void alrProbing() {
            var simulation = new CongestionSimulation(config(300_000, 5_000_000), 3_000_000);
            simulation.setEncoderCap(200_000);
            simulation.run(15_000);
            var target = simulation.target();
            assertTrue(target >= 1_000_000, "target " + target + " should be raised by probes, not media");
            assertTrue(simulation.pacer.alrStartNanos().isPresent());
        }

        @Test
        @DisplayName("reports every target change to the listener in order")
        void listener() {
            var simulation = new CongestionSimulation(config(300_000, 5_000_000), 2_000_000);
            simulation.run(5_000);
            assertTrue(simulation.targets.size() > 5);
            for (var index = 1; index < simulation.targets.size(); index++) {
                assertTrue(simulation.targets.get(index)[0] >= simulation.targets.get(index - 1)[0]);
                assertTrue(simulation.targets.get(index)[1] != simulation.targets.get(index - 1)[1]);
            }
            assertEquals(simulation.target(), simulation.targets.getLast()[1]);
        }
    }

    @Nested
    @DisplayName("with direct feedback")
    class Direct {
        private final FakeClock clock = new FakeClock(0);
        private final GoogleCongestionController controller =
                new GoogleCongestionController(config(300_000, 5_000_000).withClock(clock), false);

        @Test
        @DisplayName("starts at the start rate and paces at the pacing factor")
        void initial() {
            var target = controller.currentTarget();
            assertEquals(300_000, target.bitsPerSecond());
            assertEquals(Duration.ofMillis(200), target.rtt());
            assertEquals(750_000, controller.pacer().pacingRate());
        }

        @Test
        @DisplayName("follows the receiver's REMB and receiver-report loss when there is no transport feedback")
        void rembOnly() {
            controller.onRemb(new Remb(1, 700_000, List.of(5L)), 0);
            long sequence = 0;
            for (var second = 1; second <= 40; second++) {
                sequence += 100;
                controller.onReceptionReports(List.of(new ReceptionReport(5, 0, 0, sequence, 0, 0, 0)),
                        50 * MS, second * 1_000 * MS);
            }
            assertEquals(700_000, controller.currentTarget().bitsPerSecond());
            assertEquals(Duration.ofMillis(50), controller.currentTarget().rtt());
            controller.onRemb(new Remb(1, 400_000, List.of(5L)), 41_000 * MS);
            assertEquals(400_000, controller.currentTarget().bitsPerSecond());
            for (var second = 42; second <= 60; second++) {
                sequence += 100;
                controller.onReceptionReports(List.of(new ReceptionReport(5, 64, (int) (sequence / 4), sequence, 0, 0, 0)),
                        50 * MS, second * 1_000 * MS);
            }
            assertTrue(controller.currentTarget().bitsPerSecond() < 100_000, "25% loss in receiver reports");
        }

        @Test
        @DisplayName("lowers the target with the maximum bitrate and rejects one below the minimum")
        void maxBitrate() {
            controller.setMaxBitrate(100_000);
            assertEquals(100_000, controller.currentTarget().bitsPerSecond());
            assertThrows(IllegalArgumentException.class, () -> controller.setMaxBitrate(10_000));
        }

        @Test
        @DisplayName("matches feedback to sent packets and ignores unknown sequence numbers")
        void feedbackMatching() {
            for (var sequence = 0; sequence < 50; sequence++) {
                controller.onPacketSent(sequence, 1000, sequence * 10 * MS, Priority.VIDEO, false);
            }
            var results = new ArrayList<TransportFeedback.PacketResult>();
            for (var sequence = 0; sequence < 50; sequence++) {
                results.add(new TransportFeedback.PacketResult(sequence, sequence % 2 == 0 && sequence > 0
                        ? OptionalLong.of(10_000) : sequence == 0 ? OptionalLong.of(0) : OptionalLong.empty()));
            }
            controller.onTransportFeedback(new TransportFeedback(1, 2, 0, 100, 0, results), 600 * MS);
            assertEquals(0.48, controller.currentTarget().lossRatio(), 0.03);
            controller.onTransportFeedback(new TransportFeedback(1, 2, 40_000, 200, 1,
                    List.of(new TransportFeedback.PacketResult(40_000, OptionalLong.of(0)))), 700 * MS);
        }

        @Test
        @DisplayName("delivers targets on the calling thread, never concurrently")
        void serialListener() throws Exception {
            var active = new java.util.concurrent.atomic.AtomicInteger();
            var overlaps = new java.util.concurrent.atomic.AtomicInteger();
            var seen = new CopyOnWriteArrayList<Long>();
            controller.setTargetListener(target -> {
                if (active.incrementAndGet() > 1) {
                    overlaps.incrementAndGet();
                }
                seen.add(target.bitsPerSecond());
                active.decrementAndGet();
            });
            var threads = new ArrayList<Thread>();
            for (var thread = 0; thread < 8; thread++) {
                var rate = 100_000 + thread * 50_000L;
                threads.add(Thread.ofVirtual().start(() -> {
                    for (var round = 0; round < 50; round++) {
                        controller.onRemb(new Remb(1, rate + round, List.of()), 0);
                    }
                }));
            }
            for (var thread : threads) {
                thread.join();
            }
            assertEquals(0, overlaps.get());
            assertTrue(!seen.isEmpty());
        }
    }

    @Test
    @Timeout(10)
    @DisplayName("runs its pacer thread when created through the factory and stops it at close")
    void factory() throws Exception {
        var controller = CongestionController.gcc(CongestionConfig.defaults());
        try {
            var sent = new java.util.concurrent.CountDownLatch(1);
            controller.pacer().schedule(ByteBuffer.allocate(100), Priority.AUDIO, 1, _ -> sent.countDown());
            assertTrue(sent.await(5, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            controller.close();
        }
        assertThrows(IllegalArgumentException.class, () -> CongestionConfig.defaults().withBitrates(10, 5, 20));
        assertThrows(IllegalArgumentException.class, () -> CongestionConfig.defaults().withPacingFactor(0.5));
        assertThrows(IllegalArgumentException.class, () -> new TargetBitrate(10, 20, 0, Duration.ZERO, 0));
    }
}
