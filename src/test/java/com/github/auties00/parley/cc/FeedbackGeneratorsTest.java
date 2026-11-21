package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the receive-side feedback generators: the transport-wide feedback layout (reference time, 250 us deltas,
/// losses, splitting) and the REMB estimator.
@DisplayName("Feedback generators")
class FeedbackGeneratorsTest {
    private static final long MS = 1_000_000L;

    private static List<TransportFeedback> feedback(List<RtcpPacket> packets) {
        return packets.stream().map(TransportFeedback.class::cast).toList();
    }

    /// Rebuilds the arrival time in microseconds of every reported packet, keyed by 16-bit sequence number; lost
    /// packets map to -1.
    private static Map<Integer, Long> decode(List<TransportFeedback> messages) {
        var result = new HashMap<Integer, Long>();
        for (var message : messages) {
            var time = message.referenceTime64ms() * 64_000;
            for (var packet : message.results()) {
                if (packet.receiveDeltaMicros().isPresent()) {
                    time += packet.receiveDeltaMicros().getAsLong();
                    assertEquals(0, packet.receiveDeltaMicros().getAsLong() % 250);
                    assertTrue(result.put(packet.transportSequence(), time) == null, "reported twice");
                } else {
                    result.putIfAbsent(packet.transportSequence(), -1L);
                }
            }
        }
        return result;
    }

    @Nested
    @DisplayName("TransportFeedbackGenerator")
    class Twcc {
        private final FakeClock clock = new FakeClock(5_000 * MS);
        private final List<RtcpPacket> out = new ArrayList<>();
        private final TransportFeedbackGenerator generator = TransportFeedbackGenerator.create(0x1234, clock, out::add);

        @Test
        @DisplayName("reports arrivals relative to the reference time and marks the gaps lost")
        void layout() {
            generator.onPacketReceived(10, 0xAAAA, clock.nanos());
            generator.onPacketReceived(11, 0xAAAA, clock.nanos() + MS);
            generator.onPacketReceived(13, 0xBBBB, clock.nanos() + 3 * MS + 300_000);
            generator.sendFeedback();
            var message = feedback(out).getFirst();
            assertEquals(0x1234, message.senderSsrc());
            assertEquals(0xAAAA, message.mediaSsrc());
            assertEquals(10, message.baseSequence());
            assertEquals(0, message.feedbackCount());
            assertEquals(List.of(
                    new TransportFeedback.PacketResult(10, OptionalLong.of(0)),
                    new TransportFeedback.PacketResult(11, OptionalLong.of(1000)),
                    new TransportFeedback.PacketResult(12, OptionalLong.empty()),
                    new TransportFeedback.PacketResult(13, OptionalLong.of(2250))), message.results());
        }

        @Test
        @DisplayName("sends nothing without news, numbers its messages, and reports each packet once")
        void incremental() {
            generator.sendFeedback();
            assertTrue(out.isEmpty());
            generator.onPacketReceived(1, 1, clock.nanos());
            generator.sendFeedback();
            generator.sendFeedback();
            assertEquals(1, out.size());
            generator.onPacketReceived(2, 1, clock.nanos() + MS);
            generator.onPacketReceived(1, 1, clock.nanos() + 2 * MS);
            generator.sendFeedback();
            assertEquals(2, out.size());
            var second = feedback(out).get(1);
            assertEquals(1, second.feedbackCount());
            assertEquals(2, second.baseSequence());
            assertEquals(1, second.results().size(), "the duplicate of an already reported packet is ignored");
        }

        @Test
        @DisplayName("keeps trailing gaps open until a later packet closes them")
        void trailingGap() {
            generator.onPacketReceived(1, 1, clock.nanos());
            generator.onPacketReceived(3, 1, clock.nanos() + MS);
            generator.sendFeedback();
            assertEquals(3, feedback(out).getFirst().results().size());
            generator.onPacketReceived(5, 1, clock.nanos() + 2 * MS);
            generator.sendFeedback();
            var second = feedback(out).get(1);
            assertEquals(4, second.baseSequence());
            assertTrue(second.results().getFirst().receiveDeltaMicros().isEmpty());
        }

        @Test
        @DisplayName("splits a feedback when a delta overflows 16 bits or the packet limit is reached")
        void splitting() {
            generator.onPacketReceived(1, 1, clock.nanos());
            generator.onPacketReceived(2, 1, clock.nanos() + 9_000 * MS);
            generator.sendFeedback();
            assertEquals(2, out.size());
            assertEquals(2, feedback(out).get(1).baseSequence());
            out.clear();
            for (var sequence = 3; sequence < 3 + 1_000; sequence++) {
                generator.onPacketReceived(sequence, 1, clock.nanos() + 10_000 * MS + sequence * 100_000L);
            }
            generator.sendFeedback();
            assertEquals(3, out.size());
            assertEquals(1_000, feedback(out).stream().mapToInt(message -> message.results().size()).sum());
            assertTrue(feedback(out).stream().allMatch(message -> message.results().size()
                    <= TransportFeedbackGenerator.MAX_PACKETS_PER_FEEDBACK));
        }

        @Test
        @DisplayName("continues across the 16-bit sequence wrap")
        void sequenceWrap() {
            generator.onPacketReceived(65534, 1, clock.nanos());
            generator.onPacketReceived(65535, 1, clock.nanos() + MS);
            generator.onPacketReceived(1, 1, clock.nanos() + 2 * MS);
            generator.sendFeedback();
            var results = feedback(out).getFirst().results();
            assertEquals(List.of(65534, 65535, 0, 1), results.stream().map(TransportFeedback.PacketResult::transportSequence).toList());
            assertTrue(results.get(2).receiveDeltaMicros().isEmpty());
        }

        @Test
        @DisplayName("sends on process only once the interval elapsed")
        void interval() {
            generator.onPacketReceived(1, 1, clock.nanos());
            generator.process();
            assertTrue(out.isEmpty());
            clock.advanceMillis(100);
            generator.process();
            assertEquals(1, out.size());
            generator.setInterval(Duration.ofMillis(10));
            generator.onPacketReceived(2, 1, clock.nanos());
            clock.advanceMillis(10);
            generator.process();
            assertEquals(2, out.size());
            assertThrows(IllegalArgumentException.class, () -> generator.setInterval(Duration.ZERO));
            assertThrows(IllegalArgumentException.class, () -> generator.onPacketReceived(1, -1, 0));
        }

        @RepeatedTest(10)
        @DisplayName("lets the sender rebuild every arrival time within one 250 us tick")
        void reconstruction(RepetitionInfo repetition) {
            var random = new Random(repetition.getCurrentRepetition());
            var arrivals = new HashMap<Integer, Long>();
            var time = clock.nanos();
            var start = random.nextInt(65536);
            var feedbackMessages = new ArrayList<RtcpPacket>();
            var local = TransportFeedbackGenerator.create(1, clock, feedbackMessages::add);
            var epoch = Long.MIN_VALUE;
            for (var index = 0; index < 3_000; index++) {
                time += random.nextInt(0, 3_000_000);
                var sequence = (start + index) & 0xFFFF;
                if (random.nextInt(10) == 0) {
                    continue;
                }
                if (epoch == Long.MIN_VALUE) {
                    epoch = time;
                }
                local.onPacketReceived(sequence, 7, time);
                arrivals.put(sequence, time);
                if (random.nextInt(50) == 0) {
                    local.sendFeedback();
                }
            }
            local.sendFeedback();
            var decoded = decode(feedback(feedbackMessages));
            Long offset = null;
            for (var entry : arrivals.entrySet()) {
                var micros = decoded.get(entry.getKey());
                assertTrue(micros != null && micros >= 0, "sequence " + entry.getKey() + " reported received");
                var trueMicros = (entry.getValue() - epoch) / 1_000;
                if (offset == null) {
                    offset = micros - trueMicros;
                }
                assertEquals(trueMicros + offset, micros, 250, "sequence " + entry.getKey());
            }
            assertTrue(decoded.values().stream().filter(value -> value < 0).count() > 0);
        }
    }

    @Nested
    @DisplayName("RembGenerator")
    class RembEstimation {
        private final FakeClock clock = new FakeClock(0);
        private final List<RtcpPacket> out = new ArrayList<>();
        private final RembGenerator generator = RembGenerator.create(0x99, clock, out::add);

        private static int absSendTime(long nanos) {
            return (int) (((nanos << 18) / 1_000_000_000L) & 0xFFFFFF);
        }

        private long stream(long fromNanos, long durationNanos, long rateBps, double queueGrowth) {
            var packetBytes = 1200;
            var interval = packetBytes * 8 * 1_000_000_000L / rateBps;
            var time = fromNanos;
            var delay = 20 * MS;
            for (; time < fromNanos + durationNanos; time += interval) {
                delay += (long) (interval * queueGrowth);
                clock.set(time + delay);
                generator.onPacketReceived(0x10 + (time / interval) % 2, absSendTime(time), packetBytes, time + delay);
                generator.process();
            }
            return time;
        }

        @Test
        @DisplayName("estimates near the incoming rate on a clean path and reports every second")
        void steady() {
            stream(0, 10_000 * MS, 1_000_000, 0);
            var estimate = generator.currentEstimate().orElseThrow();
            assertTrue(estimate >= 900_000, "estimate " + estimate);
            var rembs = out.stream().map(Remb.class::cast).toList();
            assertTrue(rembs.size() >= 8 && rembs.size() <= 12, rembs.size() + " reports");
            assertEquals(List.of(0x10L, 0x11L), rembs.getLast().ssrcs());
            assertEquals(0x99, rembs.getLast().senderSsrc());
        }

        @Test
        @DisplayName("lowers the estimate and reports at once when the queue keeps growing")
        void overuse() {
            var end = stream(0, 5_000 * MS, 1_000_000, 0);
            var before = generator.currentEstimate().orElseThrow();
            var reportsBefore = out.size();
            stream(end, 1_000 * MS, 1_000_000, 0.2);
            var after = generator.currentEstimate().orElseThrow();
            assertTrue(after < before * 0.97, before + " -> " + after);
            assertTrue(out.size() > reportsBefore);
            assertTrue(((Remb) out.getLast()).bitrateBps() < before);
        }

        @Test
        @DisplayName("has no estimate before half a second of data")
        void warmUp() {
            generator.onPacketReceived(1, 0, 1200, 0);
            assertTrue(generator.currentEstimate().isEmpty());
            generator.process();
            assertTrue(out.isEmpty());
            assertThrows(IllegalArgumentException.class, () -> generator.onPacketReceived(1, 0, -1, 0));
            assertThrows(IllegalArgumentException.class, () -> generator.setRtt(Duration.ZERO));
        }
    }

    @Test
    @Timeout(10)
    @DisplayName("runs the periodic threads and stops them at close")
    void threads() throws Exception {
        var twccOut = new CopyOnWriteArrayList<RtcpPacket>();
        var twcc = TransportFeedbackGenerator.create(1, System::nanoTime, twccOut::add);
        twcc.setInterval(Duration.ofMillis(20));
        twcc.start(Thread.ofVirtual().factory());
        assertThrows(IllegalStateException.class, () -> twcc.start(Thread.ofVirtual().factory()));
        twcc.onPacketReceived(1, 1, System.nanoTime());
        var deadline = System.nanoTime() + 5_000 * MS;
        while (twccOut.isEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        assertFalse(twccOut.isEmpty());
        twcc.close();
        var remb = RembGenerator.create(1, System::nanoTime, _ -> {
        });
        remb.start(Thread.ofVirtual().factory());
        remb.close();
        assertThrows(IllegalStateException.class, () -> remb.start(Thread.ofVirtual().factory()));
    }
}
