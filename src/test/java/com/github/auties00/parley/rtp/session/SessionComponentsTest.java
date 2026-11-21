package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.rtp.extension.Mid;
import com.github.auties00.parley.rtp.extension.RepairedRtpStreamId;
import com.github.auties00.parley.rtp.extension.RtpStreamId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SplittableRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the session's building blocks in isolation: RFC 3550 reception statistics and RTCP interval math, the NACK
/// tracker, the BUNDLE demultiplexer and the SFU stream rewriter.
@DisplayName("RTP session components")
class SessionComponentsTest {
    static final HeaderExtensionMap EXTENSIONS = HeaderExtensionMap.of(Map.of(1, HeaderExtensionUris.MID,
            2, HeaderExtensionUris.RTP_STREAM_ID, 3, HeaderExtensionUris.REPAIRED_RTP_STREAM_ID));

    static RtpPacket packet(long ssrc, int payloadType, int sequence, long timestamp, Optional<String> mid,
                            Optional<String> rid, Optional<String> repairedRid) throws RtpFormatException {
        var writer = RtpPacketWriter.into(ByteBuffer.allocate(128)).ssrc(ssrc).payloadType(payloadType)
                .sequence(sequence).timestamp(timestamp).payload(ByteBuffer.wrap(new byte[]{1}));
        mid.ifPresent(value -> writer.extension(1, new Mid(value).encode()));
        rid.ifPresent(value -> writer.extension(2, new RtpStreamId(value).encode()));
        repairedRid.ifPresent(value -> writer.extension(3, new RepairedRtpStreamId(value).encode()));
        return RtpPacket.parse(writer.finish());
    }

    @Nested
    @DisplayName("reception statistics (RFC 3550 appendix A)")
    class Statistics {
        @Test
        @DisplayName("counts loss and computes the fraction lost per interval")
        void loss() {
            var statistics = new ReceptionStatistics();
            for (var sequence = 0; sequence < 10; sequence++) {
                if (sequence != 3 && sequence != 7) {
                    statistics.update(sequence, 0, 0, 90_000);
                }
            }
            var report = statistics.report(5, 0, 0, 0);
            assertEquals(2, report.cumulativeLost());
            assertEquals(2 * 256 / 10, report.fractionLost());
            assertEquals(9, report.extendedHighestSequence());
            statistics.update(10, 0, 0, 90_000);
            assertEquals(0, statistics.report(5, 0, 0, 0).fractionLost());
        }

        @Test
        @DisplayName("extends the highest sequence number across wraps")
        void cycles() {
            var statistics = new ReceptionStatistics();
            for (var i = 0; i < 20; i++) {
                statistics.update((65530 + i) & 0xFFFF, 0, 0, 8000);
            }
            assertEquals(65536 + 13, statistics.extendedHighestSequence());
            assertEquals(0, statistics.cumulativeLost());
        }

        @Test
        @DisplayName("treats a large jump as a restart only when it repeats")
        void restart() {
            var statistics = new ReceptionStatistics();
            statistics.update(100, 0, 0, 8000);
            statistics.update(101, 0, 0, 8000);
            assertTrue(!statistics.update(30_000, 0, 0, 8000));
            assertTrue(statistics.update(30_001, 0, 0, 8000));
            assertEquals(30_001, statistics.extendedHighestSequence());
            assertEquals(1, statistics.received());
        }

        @Test
        @DisplayName("follows the A.8 jitter estimator")
        void jitter() {
            var statistics = new ReceptionStatistics();
            var arrival = 0L;
            for (var i = 0; i < 10; i++) {
                statistics.update(i, 160L * i, arrival, 8000);
                arrival += 20_000_000L;
            }
            assertEquals(0, statistics.jitter());
            statistics.update(10, 1600, arrival + 10_000_000L, 8000);
            assertEquals(5, statistics.jitter());
            statistics.update(11, 1760, arrival + 20_000_000L, 8000);
            assertEquals(9, statistics.jitter());
        }
    }

    @Nested
    @DisplayName("RTCP interval (RFC 3550 section 6.3)")
    class Interval {
        @Test
        @DisplayName("computes the deterministic interval with the sender share")
        void deterministic() {
            assertEquals(1.0, RtcpScheduler.deterministicInterval(2, 1, 12_500, true, 100, 1.0), 1e-9);
            assertEquals(990 * 100 / (0.75 * 12_500),
                    RtcpScheduler.deterministicInterval(1000, 10, 12_500, false, 100, 1.0), 1e-9);
            assertEquals(10 * 100 / (0.25 * 12_500),
                    RtcpScheduler.deterministicInterval(1000, 10, 12_500, true, 100, 0.01), 1e-9);
        }

        @Test
        @DisplayName("randomizes between 0.5 and 1.5 times the interval over e - 3/2")
        void randomized() {
            var config = new RtcpConfig(true, false, false, Duration.ofSeconds(5), Duration.ZERO, 2_000_000);
            var scheduler = new RtcpScheduler(config, new SplittableRandom(1), 0, 100);
            scheduler.onRegular(0, 100, true, 2, 1, true);
            for (var i = 0; i < 1000; i++) {
                var interval = scheduler.interval(2, 1, true) / 1e9;
                assertTrue(interval >= 0.5 * 5 / RtcpScheduler.COMPENSATION - 1e-9);
                assertTrue(interval <= 1.5 * 5 / RtcpScheduler.COMPENSATION + 1e-9);
            }
        }

        @Test
        @DisplayName("allows one early packet per regular interval under AVPF only")
        void early() {
            var avpf = new RtcpScheduler(new RtcpConfig(true, false, false, Duration.ofSeconds(1), Duration.ZERO,
                    2_000_000), new SplittableRandom(1), 0, 100);
            assertTrue(avpf.tryEarly(0, 2, 1, true));
            assertTrue(!avpf.tryEarly(1, 2, 1, true));
            avpf.onRegular(2_000_000_000L, 100, true, 2, 1, true);
            assertTrue(avpf.tryEarly(2_000_000_001L, 2, 1, true));
            var plain = new RtcpScheduler(RtcpConfig.rfc3550(2_000_000), new SplittableRandom(1), 0, 100);
            assertTrue(!plain.tryEarly(0, 2, 1, true));
        }

        @Test
        @DisplayName("suppresses regular reports closer than trr-int")
        void trrInt() {
            var scheduler = new RtcpScheduler(new RtcpConfig(true, false, false, Duration.ofSeconds(1),
                    Duration.ofSeconds(5), 2_000_000), new SplittableRandom(1), 0, 100);
            scheduler.onRegular(0, 100, true, 2, 1, true);
            assertTrue(!scheduler.trrAllows(1_000_000_000L));
            assertTrue(scheduler.trrAllows(5_000_000_000L));
        }
    }

    @Nested
    @DisplayName("NACK tracker")
    class Nacks {
        @Test
        @DisplayName("NACKs a gap at once and again after a round trip, then gives up")
        void retries() {
            var tracker = new NackTracker(2);
            tracker.onPacket(10, false);
            tracker.onPacket(13, false);
            assertEquals(List.of(11L, 12L), tracker.due(0, 50_000_000L));
            assertTrue(tracker.due(10_000_000L, 50_000_000L).isEmpty());
            tracker.onPacket(11, true);
            assertEquals(List.of(12L), tracker.due(60_000_000L, 50_000_000L));
            assertTrue(tracker.due(120_000_000L, 50_000_000L).isEmpty());
            assertTrue(tracker.takeKeyframeNeeded());
            assertEquals(0, tracker.missingCount());
        }

        @Test
        @DisplayName("asks for a keyframe instead of tracking a huge gap")
        void hugeGap() {
            var tracker = new NackTracker(10);
            tracker.onPacket(0, false);
            tracker.onPacket(NackTracker.MAX_MISSING + 5, false);
            assertEquals(0, tracker.missingCount());
            assertTrue(tracker.takeKeyframeNeeded());
        }
    }

    @Nested
    @DisplayName("BUNDLE demultiplexer (RFC 8843 section 9.2)")
    class Demux {
        private RtpDemuxer<String> demuxer() {
            return RtpDemuxer.create(EXTENSIONS, List.of(
                    new RtpDemuxer.Route<>("audio", Optional.of("a"), Optional.empty(), Set.of(100L), Set.of(111)),
                    new RtpDemuxer.Route<>("high", Optional.of("v"), Optional.of("h"), Set.of(), Set.of(96, 97)),
                    new RtpDemuxer.Route<>("low", Optional.of("v"), Optional.of("l"), Set.of(), Set.of(96, 97))));
        }

        private static String target(RtpDemuxer.Result<String> result) {
            return assertInstanceOf(RtpDemuxer.Result.Matched.class, result).target().toString();
        }

        @Test
        @DisplayName("routes by MID and RID, then by the SSRC binding it learned")
        void midAndRid() throws RtpFormatException {
            var demuxer = demuxer();
            assertEquals("high", target(demuxer.route(packet(1, 96, 0, 0, Optional.of("v"), Optional.of("h"),
                    Optional.empty()))));
            assertEquals("low", target(demuxer.route(packet(2, 96, 0, 0, Optional.of("v"), Optional.of("l"),
                    Optional.empty()))));
            assertEquals("high", target(demuxer.route(packet(1, 96, 1, 0, Optional.empty(), Optional.empty(),
                    Optional.empty()))));
            assertEquals("low", target(demuxer.route(packet(3, 97, 0, 0, Optional.of("v"), Optional.empty(),
                    Optional.of("l")))));
            assertEquals("low", target(demuxer.route(packet(3, 97, 1, 0, Optional.empty(), Optional.empty(),
                    Optional.empty()))));
        }

        @Test
        @DisplayName("routes by signaled SSRC and by a payload type unique to one route")
        void ssrcAndPayloadType() throws RtpFormatException {
            var demuxer = demuxer();
            assertEquals("audio", target(demuxer.route(packet(100, 0, 0, 0, Optional.empty(), Optional.empty(),
                    Optional.empty()))));
            assertEquals("audio", target(demuxer.route(packet(55, 111, 0, 0, Optional.empty(), Optional.empty(),
                    Optional.empty()))));
            var unmatched = assertInstanceOf(RtpDemuxer.Result.Unmatched.class, demuxer.route(packet(56, 96, 0, 0,
                    Optional.empty(), Optional.empty(), Optional.empty())));
            assertEquals(56, unmatched.stream().ssrc());
        }

        @Test
        @DisplayName("treats the MID as authoritative and rebinds the SSRC")
        void midRebinds() throws RtpFormatException {
            var demuxer = demuxer();
            assertEquals("audio", target(demuxer.route(packet(100, 111, 0, 0, Optional.empty(), Optional.empty(),
                    Optional.empty()))));
            assertEquals("high", target(demuxer.route(packet(100, 96, 1, 0, Optional.of("v"), Optional.of("h"),
                    Optional.empty()))));
            assertEquals("high", demuxer.boundTarget(100).orElseThrow());
            var unknown = assertInstanceOf(RtpDemuxer.Result.Unmatched.class, demuxer.route(packet(100, 96, 2, 0,
                    Optional.of("x"), Optional.empty(), Optional.empty())));
            assertEquals(Optional.of("x"), unknown.stream().mid());
        }

        @Test
        @DisplayName("keeps bindings to targets that stay routed")
        void withRoutes() throws RtpFormatException {
            var demuxer = demuxer();
            demuxer.route(packet(9, 96, 0, 0, Optional.of("v"), Optional.of("h"), Optional.empty()));
            var next = demuxer.withRoutes(EXTENSIONS, List.of(
                    new RtpDemuxer.Route<>("high", Optional.of("v"), Optional.of("h"), Set.of(), Set.of(96))));
            assertEquals("high", next.boundTarget(9).orElseThrow());
        }
    }

    @Nested
    @DisplayName("SFU stream rewriter")
    class Rewriter {
        @Test
        @DisplayName("keeps sequence numbers and timestamps continuous across a layer switch")
        void switchLayers() throws RtpFormatException {
            var rewriter = RtpStreamRewriter.create(77, 90_000);
            rewriter.switchTo(1);
            var empty = Optional.<String>empty();
            var first = rewriter.rewrite(packet(1, 96, 100, 9000, empty, empty, empty), true, 0, 4).orElseThrow();
            var second = rewriter.rewrite(packet(1, 96, 101, 12_000, empty, empty, empty), false, 33_000_000L, 0)
                    .orElseThrow();
            assertEquals(100, RtpPacket.parse(first).sequence());
            assertEquals(77, RtpPacket.parse(second).ssrc());
            assertEquals(4, first.capacity() - first.limit());
            rewriter.switchTo(2);
            assertTrue(rewriter.rewrite(packet(2, 96, 5000, 500, empty, empty, empty), false, 40_000_000L, 0)
                    .isEmpty());
            assertTrue(rewriter.rewrite(packet(1, 96, 102, 15_000, empty, empty, empty), false, 66_000_000L, 0)
                    .isPresent());
            var switched = RtpPacket.parse(rewriter.rewrite(packet(2, 96, 5001, 800, empty, empty, empty), true,
                    99_000_000L, 0).orElseThrow());
            assertEquals(103, switched.sequence());
            assertEquals(15_000 + 33 * 90, switched.timestamp());
            assertTrue(rewriter.rewrite(packet(1, 96, 103, 18_000, empty, empty, empty), false, 100_000_000L, 0)
                    .isEmpty());
            assertTrue(rewriter.rewrite(packet(2, 96, 5000, 500, empty, empty, empty), false, 100_000_000L, 0)
                    .isEmpty());
            assertEquals(new RtpStreamRewriter.SourcePacket(2, 5001), rewriter.sourceOf(103).orElseThrow());
            assertEquals(new RtpStreamRewriter.SourcePacket(1, 101), rewriter.sourceOf(101).orElseThrow());
        }
    }
}
