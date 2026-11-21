package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.rtcp.CongestionControlFeedback;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority;
import com.github.auties00.parley.rtp.session.SentPacket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the failure isolation and queue bound of the pacer, the congestion window and RFC 8888 feedback of the
/// controller, the feedback generators' schedules, and the allocator's per-sender ceilings.
@DisplayName("congestion control robustness")
class CongestionRobustnessTest {
    private static final long MS = 1_000_000L;

    @Nested
    @DisplayName("pacer")
    class PacerRobustness {
        @Test
        @Timeout(10)
        @DisplayName("skips a failing step and goes on sending (concurrency-M4)")
        void isolation() throws Exception {
            var failures = new AtomicInteger(0);
            MonotonicClock clock = () -> {
                if (Thread.currentThread().getName().startsWith("faulty-pacer") && failures.getAndDecrement() > 0) {
                    throw new IllegalStateException("clock fault");
                }
                return System.nanoTime();
            };
            var reported = new CompletableFuture<Throwable>();
            var pacer = new Pacer(clock, 8_000_000, Duration.ofSeconds(2).toNanos(), false,
                    Thread.ofVirtual().name("faulty-pacer").factory(), reported::complete);
            try {
                failures.set(3);
                var latch = new CountDownLatch(5);
                for (var i = 0; i < 5; i++) {
                    pacer.schedule(ByteBuffer.allocate(100), Priority.VIDEO, 1, _ -> latch.countDown());
                }
                assertTrue(latch.await(5, TimeUnit.SECONDS));
                assertFalse(reported.isDone());
                assertFalse(pacer.isClosed());
            } finally {
                pacer.close();
            }
        }

        @Test
        @Timeout(10)
        @DisplayName("reports a pacer that keeps failing to its failure listener and closes")
        void failure() throws Exception {
            var broken = new java.util.concurrent.atomic.AtomicBoolean();
            MonotonicClock clock = () -> {
                if (broken.get() && Thread.currentThread().getName().startsWith("faulty-pacer")) {
                    throw new IllegalStateException("clock fault");
                }
                return System.nanoTime();
            };
            var reported = new CompletableFuture<Throwable>();
            var pacer = new Pacer(clock, 8_000_000, Duration.ofSeconds(2).toNanos(), false,
                    Thread.ofVirtual().name("faulty-pacer").factory(), reported::complete);
            broken.set(true);
            pacer.setPacingRate(1_000_000);
            var cause = reported.get(5, TimeUnit.SECONDS);
            assertInstanceOf(IllegalStateException.class, cause);
            assertTrue(pacer.isClosed());
            assertTrue(pacer.failures() >= Pacer.MAX_CONSECUTIVE_FAILURES - 1);
        }

        @Test
        @DisplayName("drops the oldest retransmissions and video once packets waited twice the queue bound")
        void queueBound() {
            var clock = new FakeClock(0);
            var pacer = new Pacer(clock, 8_000, Duration.ofMillis(100).toNanos(), false, null, _ -> {
            });
            var sent = new ArrayList<Priority>();
            pacer.schedule(ByteBuffer.allocate(10_000), Priority.VIDEO, 1, _ -> sent.add(Priority.VIDEO));
            pacer.process(0);
            for (var i = 0; i < 5; i++) {
                pacer.schedule(ByteBuffer.allocate(1000), Priority.VIDEO, 1, _ -> sent.add(Priority.VIDEO));
                pacer.schedule(ByteBuffer.allocate(1000), Priority.RETRANSMISSION, 1,
                        _ -> sent.add(Priority.RETRANSMISSION));
            }
            clock.advanceMillis(150);
            pacer.schedule(ByteBuffer.allocate(100), Priority.AUDIO, 1, _ -> sent.add(Priority.AUDIO));
            clock.advanceMillis(100);
            pacer.process(clock.nanos());
            assertEquals(10, pacer.droppedPackets());
            assertTrue(sent.contains(Priority.AUDIO), "audio is never dropped");
            assertEquals(0, pacer.queuedPackets());
        }

        @Test
        @DisplayName("sends only audio while the congestion window is full")
        void congested() {
            var clock = new FakeClock(0);
            var pacer = new Pacer(clock, 8_000_000, Duration.ofSeconds(2).toNanos(), false, null, _ -> {
            });
            var sent = new ArrayList<Priority>();
            pacer.setCongested(true);
            pacer.schedule(ByteBuffer.allocate(100), Priority.VIDEO, 1, _ -> sent.add(Priority.VIDEO));
            pacer.schedule(ByteBuffer.allocate(100), Priority.AUDIO, 1, _ -> sent.add(Priority.AUDIO));
            pacer.process(0);
            assertEquals(List.of(Priority.AUDIO), sent);
            pacer.setCongested(false);
            pacer.process(MS);
            assertEquals(List.of(Priority.AUDIO, Priority.VIDEO), sent);
        }
    }

    @Nested
    @DisplayName("controller")
    class Controller {
        private final FakeClock clock = new FakeClock(1_000 * MS);
        private final List<TargetBitrate> targets = new ArrayList<>();

        private GoogleCongestionController controller() {
            return new GoogleCongestionController(CongestionConfig.defaults().withClock(clock)
                    .withTargetListener(targets::add), false);
        }

        @Test
        @DisplayName("fills the congestion window when feedback stops, then drains it with feedback, lost feedback "
                + "included")
        void congestionWindow() {
            var controller = controller();
            for (var sequence = 0; sequence < 10; sequence++) {
                controller.onPacketSent(new SentPacket(sequence, 1000, clock.nanos(), Priority.VIDEO, false, 1,
                        sequence));
            }
            var results = new ArrayList<TransportFeedback.PacketResult>();
            for (var sequence = 0; sequence < 10; sequence++) {
                results.add(TransportFeedback.PacketResult.received(sequence, sequence == 0 ? 0 : 1000));
            }
            controller.onTransportFeedback(new TransportFeedback(2, 1, 0, 16, 0, results), clock.nanos());
            assertEquals(0, controller.bytesInFlight());
            assertFalse(controller.pacer().isCongested());
            for (var sequence = 10; sequence < 200; sequence++) {
                controller.onPacketSent(new SentPacket(sequence, 1200, clock.nanos(), Priority.VIDEO, false, 1,
                        sequence));
            }
            assertTrue(controller.pacer().isCongested(), "in flight: " + controller.bytesInFlight());
            var drained = new ArrayList<TransportFeedback.PacketResult>();
            for (var sequence = 100; sequence < 200; sequence++) {
                drained.add(TransportFeedback.PacketResult.received(sequence, 250));
            }
            clock.advanceMillis(100);
            controller.onTransportFeedback(new TransportFeedback(2, 1, 100, 18, 1, drained), clock.nanos());
            assertEquals(0, controller.bytesInFlight());
            assertFalse(controller.pacer().isCongested());
        }

        @Test
        @DisplayName("matches RFC 8888 feedback by SSRC and sequence number and lowers the target on loss")
        void ccfb() {
            var controller = controller();
            var start = controller.currentTarget().bitsPerSecond();
            for (var round = 0; round < 10; round++) {
                for (var i = 0; i < 50; i++) {
                    var sequence = round * 50 + i;
                    controller.onPacketSent(new SentPacket(-1, 1000, clock.nanos(), Priority.VIDEO, false, 7,
                            sequence));
                }
                clock.advanceMillis(400);
                var metrics = new ArrayList<CongestionControlFeedback.Metric>();
                for (var i = 0; i < 50; i++) {
                    metrics.add(i % 2 == 0 ? CongestionControlFeedback.Metric.lost()
                            : new CongestionControlFeedback.Metric(true, 0, 50 - i));
                }
                var report = new CongestionControlFeedback.StreamReport(7, round * 50, metrics);
                controller.onCongestionControlFeedback(new CongestionControlFeedback(2, List.of(report),
                        round * 65_536L), clock.nanos());
            }
            assertTrue(controller.currentTarget().bitsPerSecond() < start);
            assertTrue(controller.currentTarget().lossRatio() > 0.3);
            assertEquals(0, controller.bytesInFlight());
        }

        @Test
        @DisplayName("bounds the receiver report state to the reported local SSRCs")
        void reportState() {
            var controller = controller();
            for (var ssrc = 0; ssrc < 1000; ssrc++) {
                controller.onReceptionReports(List.of(new com.github.auties00.parley.rtp.rtcp.ReceptionReport(ssrc, 0,
                        0, 10, 0, 0, 0)), -1, clock.nanos());
            }
            assertEquals(GoogleCongestionController.MAX_REPORTED_SSRCS, controller.reportedSsrcs());
        }
    }

    @Nested
    @DisplayName("feedback generators")
    class Generators {
        @Test
        @DisplayName("adapt the transport-wide feedback interval to about 5% of the incoming rate, 50 to 250 ms")
        void adaptiveInterval() {
            assertEquals(250 * MS, TransportFeedbackGenerator.adaptiveInterval(0));
            assertEquals(250 * MS, TransportFeedbackGenerator.adaptiveInterval(10_000));
            assertEquals(108_800_000, TransportFeedbackGenerator.adaptiveInterval(100_000), MS);
            assertEquals(50 * MS, TransportFeedbackGenerator.adaptiveInterval(10_000_000));
            var clock = new FakeClock(0);
            var generator = TransportFeedbackGenerator.create(1, clock, _ -> {
            });
            for (var i = 0; i < 200; i++) {
                generator.onPacketReceived(i, 2, 1250, clock.nanos());
                clock.advanceMillis(10);
            }
            assertEquals(Duration.ofNanos(TransportFeedbackGenerator.adaptiveInterval(1_000_000)),
                    generator.interval());
            generator.setInterval(Duration.ofMillis(70));
            generator.onPacketReceived(200, 2, 1250, clock.nanos());
            assertEquals(Duration.ofMillis(70), generator.interval());
        }

        @Test
        @DisplayName("schedule the next feedback one interval after the previous deadline, not after sending")
        void drift() {
            assertEquals(200, TransportFeedbackGenerator.nextDeadline(100, 100, 130));
            assertEquals(200, TransportFeedbackGenerator.nextDeadline(100, 100, 199));
            assertEquals(1100, TransportFeedbackGenerator.nextDeadline(100, 100, 1000));
        }

        @Test
        @DisplayName("report RFC 8888 feedback per SSRC with losses and arrival offsets, for a bounded set of SSRCs")
        void ccfb() {
            var clock = new FakeClock(5_000 * MS);
            var sent = new ArrayList<RtcpPacket>();
            var generator = CongestionControlFeedbackGenerator.create(9, clock, sent::add);
            generator.onPacketReceived(100, 10, clock.nanos());
            generator.onPacketReceived(100, 12, clock.nanos());
            clock.advanceMillis(50);
            generator.sendFeedback();
            var feedback = (CongestionControlFeedback) sent.getFirst();
            var report = feedback.reports().getFirst();
            assertEquals(100, report.ssrc());
            assertEquals(10, report.beginSequence());
            assertEquals(3, report.metrics().size());
            assertFalse(report.metrics().get(1).received());
            assertEquals(51, report.metrics().getFirst().arrivalTimeOffset(), 1);
            for (var ssrc = 1000; ssrc < 1200; ssrc++) {
                generator.onPacketReceived(ssrc, 1, clock.nanos());
            }
            sent.clear();
            generator.sendFeedback();
            var reported = sent.stream().mapToInt(packet -> ((CongestionControlFeedback) packet).reports().size())
                    .sum();
            assertEquals(CongestionControlFeedbackGenerator.MAX_SSRCS, reported);
        }
    }

    @Nested
    @DisplayName("allocator")
    class Allocator {
        @Test
        @DisplayName("keeps a sender's simulcast encodings within its ceiling together (gaps-M10)")
        void ceiling() {
            var allocator = new BitrateAllocator();
            var low = new EncodingDemand(AllocationKey.of("v", "l"), true, 50_000, 200_000, 1, 4);
            var high = new EncodingDemand(AllocationKey.of("v", "h"), true, 200_000, 2_000_000, 1, 1);
            var result = allocator.allocate(3_000_000, List.of(low, high), Map.of("v", 300_000L));
            assertTrue(result.get(low.key()) + result.get(high.key()) <= 300_000, result.toString());
            assertEquals(200_000, result.get(low.key()));
        }

        @Test
        @DisplayName("lowers the floor to a ceiling below it rather than suspend the sender")
        void ceilingBelowFloor() {
            var allocator = new BitrateAllocator();
            var video = new EncodingDemand(AllocationKey.of("v"), true, 30_000, 2_000_000, 1, 1);
            assertEquals(20_000, allocator.allocate(1_000_000, List.of(video), Map.of("v", 20_000L))
                    .get(video.key()));
            assertEquals(30_000, allocator.allocate(30_000, List.of(video)).get(video.key()));
        }
    }
}
