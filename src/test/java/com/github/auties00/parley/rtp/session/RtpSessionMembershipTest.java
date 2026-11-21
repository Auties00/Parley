package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import com.github.auties00.parley.rtp.extension.Mid;
import com.github.auties00.parley.rtp.rtcp.Bye;
import com.github.auties00.parley.rtp.rtcp.CongestionControlFeedback;
import com.github.auties00.parley.rtp.rtcp.ExtendedReport;
import com.github.auties00.parley.rtp.rtcp.FullIntraRequest;
import com.github.auties00.parley.rtp.rtcp.ReceiverReport;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.SourceDescription;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import static com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority.VIDEO;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.EXTENSIONS;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.Pair;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.VIDEO_SSRC;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.payload;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.send;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.valueOf;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.values;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.video;
import static com.github.auties00.parley.rtp.session.RtpSessionTest.videoReceiver;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers what a session does with peer-chosen SSRCs: the bounded member table, SSRC collisions and loops, leaving
/// with BYE, feedback plausibility, forwarding, FEC schemes and the stream statistics, driven over [TestNetwork] by
/// packets injected as the remote side.
@DisplayName("RTP session membership and forwarding")
class RtpSessionMembershipTest {
    static ByteBuffer rtp(long ssrc, int sequence) {
        return RtpPacketWriter.into(ByteBuffer.allocate(64)).payloadType(96).sequence(sequence & 0xFFFF)
                .timestamp(sequence * 3000L).ssrc(ssrc).payload(ByteBuffer.wrap(new byte[]{1, 2, 3})).finish();
    }

    static ByteBuffer rtcp(RtcpPacket... packets) {
        return RtcpPacket.encodeCompound(List.of(packets), 0);
    }

    static void injectRtp(TestNetwork net, ByteBuffer packet) {
        net.left.rtpReceiver.receive(packet, net.clock.nanos());
    }

    static void injectRtcp(TestNetwork net, RtcpPacket... packets) {
        net.left.rtcpReceiver.receive(rtcp(packets), net.clock.nanos());
    }

    static <T> List<T> lastCompoundOf(TestNetwork.Endpoint endpoint, Class<T> type) {
        var compound = endpoint.sentRtcp.getLast();
        return compound.stream().filter(type::isInstance).map(type::cast).toList();
    }

    @Nested
    @DisplayName("member table")
    class Members {
        @Test
        @DisplayName("stays bounded under 20,000 packets from random SSRCs (correctness-M1 probe)")
        void bounded() {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            var random = new Random(31);
            for (var i = 0; i < 20_000; i++) {
                var chunks = new ArrayList<SourceDescription.Chunk>();
                for (var c = 0; c < 10; c++) {
                    chunks.add(SourceDescription.ofCname(random.nextInt() & 0xFFFFFFFFL, "x").chunks().getFirst());
                }
                injectRtcp(net, new ReceiverReport(random.nextInt() & 0xFFFFFFFFL, List.of()),
                        new SourceDescription(chunks), new ExtendedReport(random.nextInt() & 0xFFFFFFFFL,
                                List.of(new ExtendedReport.ReceiverReferenceTime(random.nextLong()))));
                injectRtp(net, rtp(random.nextInt() & 0xFFFFFFFFL, i));
                if (i % 1000 == 0) {
                    net.clock.advanceMillis(100);
                }
            }
            assertTrue(session.memberTableSize() <= MemberTable.CAPACITY, "members: " + session.memberTableSize());
            session.close();
        }

        @Test
        @DisplayName("records a CNAME only for a member heard in RTP, and keeps the first one of a contested SSRC")
        void cnames() {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            injectRtcp(net, new ReceiverReport(500, List.of()), SourceDescription.ofCname(500, "only-rtcp"));
            assertTrue(session.remoteCname(500).isEmpty());
            injectRtp(net, rtp(77, 1));
            injectRtcp(net, new ReceiverReport(500, List.of()), SourceDescription.ofCname(77, "first"));
            injectRtcp(net, new ReceiverReport(500, List.of()), SourceDescription.ofCname(77, "second"));
            assertEquals("first", session.remoteCname(77).orElseThrow());
            assertEquals(1, session.thirdPartyCollisionCount());
        }

        @Test
        @DisplayName("forgets members after the member timeout")
        void expiry() {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            for (var ssrc = 1; ssrc <= 100; ssrc++) {
                injectRtp(net, rtp(1000 + ssrc, ssrc));
            }
            assertEquals(100, session.memberTableSize());
            net.clock.advanceMillis(RtpSession.MEMBER_TIMEOUT_NANOS / 1_000_000 + 1);
            session.tick();
            assertEquals(0, session.memberTableSize());
        }

        @Test
        @DisplayName("answers at most 31 receiver reference times per report")
        void referenceTimes() {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            for (var ssrc = 1; ssrc <= 100; ssrc++) {
                injectRtcp(net, new ReceiverReport(ssrc, List.of()), new ExtendedReport(ssrc,
                        List.of(new ExtendedReport.ReceiverReferenceTime(ssrc * 1000L))));
            }
            net.clock.advanceMillis(5_000);
            session.tick();
            var dlrr = net.left.sentRtcpOf(ExtendedReport.class).stream()
                    .flatMap(report -> report.blocks().stream())
                    .filter(block -> block instanceof ExtendedReport.Dlrr)
                    .map(block -> ((ExtendedReport.Dlrr) block).entries().size())
                    .toList();
            assertEquals(List.of(RtpSession.MAX_DLRR_ENTRIES), dlrr);
        }

        @Test
        @DisplayName("bounds the FIR sequence numbers it remembers per requester")
        void firRequesters() {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            var stream = session.createSendStream(video().feedback(Set.of(FeedbackMechanism.FIR)).build());
            for (var requester = 1; requester <= 500; requester++) {
                injectRtcp(net, new ReceiverReport(requester, List.of()),
                        new FullIntraRequest(requester, List.of(new FullIntraRequest.Entry(VIDEO_SSRC, 1))));
            }
            assertTrue(stream.firRequesters() <= RtpSendStream.MAX_FIR_REQUESTERS);
            assertEquals(500, stream.statistics().firCount());
        }
    }

    @Nested
    @DisplayName("SSRC collisions")
    class Collisions {
        @Test
        @DisplayName("moves a stream whose SSRC a remote packet carries, announcing the old one in RR, SDES and BYE")
        void rtpCollision() {
            var net = new TestNetwork();
            var changes = new ArrayList<SsrcChange>();
            var session = net.session(net.left, 10).ssrcChangedListener(changes::add).build();
            var stream = session.createSendStream(video().build());
            injectRtp(net, rtp(VIDEO_SSRC, 1));
            assertEquals(1, changes.size());
            assertEquals(VIDEO_SSRC, changes.getFirst().oldSsrc());
            assertEquals(changes.getFirst().newSsrc(), stream.config().ssrc());
            assertEquals(1, lastCompoundOf(net.left, ReceiverReport.class).size());
            assertEquals(1, lastCompoundOf(net.left, SourceDescription.class).size());
            assertEquals(List.of(VIDEO_SSRC), lastCompoundOf(net.left, Bye.class).getFirst().ssrcs());

            injectRtp(net, rtp(stream.config().ssrc(), 2));
            assertEquals(1, changes.size(), "a second collision inside the hold-off is ignored");
            assertEquals(1, session.ignoredCollisionCount());
            net.clock.advanceMillis(RtpSession.COLLISION_HOLDOFF_NANOS / 1_000_000 + 1);
            injectRtp(net, rtp(stream.config().ssrc(), 3));
            assertEquals(2, changes.size());
            assertEquals(2, session.collisionCount());
        }

        @Test
        @DisplayName("treats its own CNAME on a local SSRC as a loop, and drops looped RTP afterwards")
        void loop() {
            var net = new TestNetwork();
            var changes = new ArrayList<SsrcChange>();
            var session = net.session(net.left, 10).ssrcChangedListener(changes::add).build();
            session.createSendStream(video().build());
            injectRtcp(net, new ReceiverReport(VIDEO_SSRC, List.of()), SourceDescription.ofCname(VIDEO_SSRC, "left"));
            injectRtp(net, rtp(VIDEO_SSRC, 1));
            assertTrue(changes.isEmpty());
            assertEquals(2, session.loopedPacketCount());
        }

        @Test
        @DisplayName("moves the feedback SSRC of a session without send streams")
        void localSsrc() {
            var net = new TestNetwork();
            var changes = new ArrayList<SsrcChange>();
            var session = net.session(net.left, 10).ssrcChangedListener(changes::add).build();
            injectRtcp(net, new ReceiverReport(10, List.of()), SourceDescription.ofCname(10, "someone-else"));
            assertEquals(List.of(new SsrcChange(10, session.localSsrc())), changes);
        }

        @Test
        @DisplayName("changes SSRC on request, refusing an SSRC another local stream uses")
        void changeSsrc() throws Exception {
            var net = new TestNetwork();
            var changes = new ArrayList<SsrcChange>();
            var session = net.session(net.left, 10).ssrcChangedListener(changes::add).build();
            var stream = session.createSendStream(video().build());
            session.createSendStream(SendStreamConfig.builder("a", 4242, 111, 48_000).build());
            send(stream, List.of(payload(1)), 0, true, Map.of(), VIDEO);
            stream.changeSsrc(9999);
            assertEquals(List.of(new SsrcChange(VIDEO_SSRC, 9999)), changes);
            assertEquals(List.of(VIDEO_SSRC), lastCompoundOf(net.left, Bye.class).getFirst().ssrcs());
            assertEquals(0, stream.statistics().packetsSent());
            send(stream, List.of(payload(2)), 3000, true, Map.of(), VIDEO);
            assertEquals(9999, net.left.sentRtp.getLast().ssrc());
            assertThrows(IllegalArgumentException.class, () -> stream.changeSsrc(4242));
        }
    }

    @Nested
    @DisplayName("leaving")
    class Leaving {
        @Test
        @DisplayName("announces a removed stream's media, RTX and FlexFEC SSRCs with RR and CNAME, then drops its sends")
        void removal() throws Exception {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            var stream = session.createSendStream(video().rtx(2222, 97)
                    .fec(new FecConfig.Flexfec(98, 3333, false, 50)).build());
            session.removeSendStream(stream);
            var compound = net.left.sentRtcp.getLast();
            assertTrue(compound.getFirst() instanceof ReceiverReport);
            assertTrue(compound.get(1) instanceof SourceDescription description
                    && description.chunks().getFirst().find(SourceDescription.Item.CNAME).orElseThrow().equals("left"));
            assertEquals(List.of(VIDEO_SSRC, 2222L, 3333L), ((Bye) compound.get(2)).ssrcs());
            var before = net.left.sentRtp.size();
            send(stream, List.of(payload(1)), 0, true, Map.of(), VIDEO);
            assertEquals(before, net.left.sentRtp.size());
            assertEquals(1, stream.droppedPackets());
        }

        @Test
        @DisplayName("splits the closing BYE into packets of at most 31 sources")
        void byeSplit() {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            for (var i = 0; i < 12; i++) {
                session.createSendStream(SendStreamConfig.builder("m" + i, 100 + i * 3, 96, 90_000)
                        .rtx(101 + i * 3, 97).fec(new FecConfig.Flexfec(98, 102 + i * 3, false, 50)).build());
            }
            session.close();
            var byes = net.left.sentRtcp.stream().flatMap(List::stream).filter(Bye.class::isInstance)
                    .map(packet -> ((Bye) packet).ssrcs().size()).toList();
            assertEquals(List.of(31, 5), byes);
        }

        @Test
        @DisplayName("delays the BYE by the reconsideration timer in a session of more than 50 members")
        void reconsideration() throws Exception {
            var net = new TestNetwork();
            var session = net.session(net.left, 10).build();
            var stream = session.createSendStream(video().build());
            for (var ssrc = 1; ssrc <= 60; ssrc++) {
                injectRtp(net, rtp(5000 + ssrc, ssrc));
            }
            var before = net.left.sentRtcp.size();
            session.removeSendStream(stream);
            assertEquals(before, net.left.sentRtcp.size());
            assertEquals(1, session.pendingByeCount());
            net.clock.advanceMillis(10_000);
            session.tick();
            assertEquals(0, session.pendingByeCount());
            assertTrue(net.left.sentRtcpOf(Bye.class).stream().anyMatch(bye -> bye.ssrcs().contains(VIDEO_SSRC)));
        }
    }

    @Nested
    @DisplayName("feedback")
    class Feedback {
        @Test
        @DisplayName("hands RFC 8888 feedback to the observer and drops transport-wide feedback far from what was sent")
        void plausibility() throws Exception {
            var net = new TestNetwork();
            var ccfb = new ArrayList<CongestionControlFeedback>();
            var twcc = new ArrayList<TransportFeedback>();
            var observer = new TransportFeedbackObserver() {
                @Override
                public void onPacketSent(SentPacket packet) {
                }

                @Override
                public void onTransportFeedback(TransportFeedback feedback, long arrivalNanos) {
                    twcc.add(feedback);
                }

                @Override
                public void onRemb(Remb remb, long arrivalNanos) {
                }

                @Override
                public void onReceptionReports(List<ReceptionReport> reports, long rttNanos, long arrivalNanos) {
                }

                @Override
                public void onCongestionControlFeedback(CongestionControlFeedback feedback, long arrivalNanos) {
                    ccfb.add(feedback);
                }
            };
            var session = net.session(net.left, 10).extensions(EXTENSIONS).feedbackObserver(observer).build();
            assertTrue(session.roundTripTime().isEmpty());
            var stream = session.createSendStream(video().build());
            for (var i = 0; i < 3; i++) {
                send(stream, List.of(payload(i)), 3000L * i, true, Map.of(), VIDEO);
            }
            injectRtcp(net, new ReceiverReport(20, List.of()), new TransportFeedback(20, 1, 0x100, 0, 0,
                    List.of(TransportFeedback.PacketResult.lost(0x100))));
            injectRtcp(net, new ReceiverReport(20, List.of()), new TransportFeedback(20, 1, 1, 0, 0,
                    List.of(TransportFeedback.PacketResult.received(1, 0))));
            injectRtcp(net, new ReceiverReport(20, List.of()), new CongestionControlFeedback(20, List.of(), 0));
            assertEquals(1, twcc.size());
            assertEquals(1, twcc.getFirst().baseSequence());
            assertEquals(1, session.droppedFeedbackCount());
            assertEquals(1, ccfb.size());
        }
    }

    @Nested
    @DisplayName("forwarding")
    class Forwarding {
        static RtpPacket source(long ssrc, int sequence, long timestamp, boolean marker, int value) throws Exception {
            return RtpPacket.parse(RtpPacketWriter.into(ByteBuffer.allocate(64)).payloadType(100).sequence(sequence)
                    .timestamp(timestamp).ssrc(ssrc).marker(marker).payload(payload(value)).finish());
        }

        @Test
        @DisplayName("sends forwarded payloads unchanged on its own SSRC, MID and continuous sequence across a switch")
        void forward() throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().build());
            pair.receive(videoReceiver().build());
            var now = pair.net.clock.nanos();
            stream.forward(source(500, 100, 1000, false, 1), 96, Map.of(), true, now);
            stream.forward(source(500, 101, 1000, true, 2), 96, Map.of(), false, now);
            stream.forward(source(500, 103, 4000, true, 3), 96, Map.of(), false, now + 33_000_000);
            stream.forward(source(600, 9000, 77_000, false, 4), 96, Map.of(), false, now + 40_000_000);
            stream.forward(source(500, 104, 7000, true, 5), 96, Map.of(), false, now + 50_000_000);
            stream.forward(source(600, 9001, 80_000, true, 6), 96, Map.of(), true, now + 66_000_000);
            stream.forward(source(500, 105, 10_000, true, 7), 96, Map.of(), false, now + 70_000_000);
            var sent = pair.net.left.sentRtp;
            assertEquals(List.of(1, 2, 3, 5, 6), values(sent));
            for (var packet : sent) {
                assertEquals(VIDEO_SSRC, packet.ssrc());
                assertEquals(96, packet.payloadType());
                assertEquals("v", Mid.parse(packet.extension(1).orElseThrow()).value());
            }
            var sequences = sent.stream().map(RtpPacket::sequence).toList();
            assertEquals((sequences.get(0) + 1) & 0xFFFF, sequences.get(1));
            assertEquals((sequences.get(1) + 2) & 0xFFFF, sequences.get(2), "upstream loss is kept as a gap");
            assertEquals((sequences.get(3) + 1) & 0xFFFF, sequences.get(4), "the switch continues the sequence");
            assertTrue(((sent.get(4).timestamp() - sent.get(3).timestamp()) & 0xFFFFFFFFL) > 0);
            assertEquals(2, stream.droppedPackets());
            var statistics = stream.statistics();
            assertEquals(4, statistics.framesSent());
            assertEquals(2, statistics.keyFramesSent());
            pair.net.deliver();
            assertEquals(List.of(1, 2, 3, 5, 6), values(pair.received));
        }

        @Test
        @DisplayName("serves NACKs of forwarded packets from its history as RTX")
        void forwardedNack() throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().rtx(2222, 97).feedback(Set.of(FeedbackMechanism.NACK))
                    .build());
            pair.receive(videoReceiver().rtxPayloadType(97, 96).feedback(Set.of(FeedbackMechanism.NACK)).build());
            pair.net.left.dropRtp = packet -> packet.ssrc() == VIDEO_SSRC && valueOf(packet) == 2;
            var now = pair.net.clock.nanos();
            for (var i = 1; i <= 4; i++) {
                stream.forward(source(500, 100 + i, 1000L * i, true, i), 96, Map.of(), i == 1, now);
                pair.net.deliver();
            }
            assertEquals(new TreeSet<>(List.of(1, 2, 3, 4)), new TreeSet<>(values(pair.received)));
            assertEquals(1, stream.statistics().retransmittedPacketsSent());
        }
    }

    @Nested
    @DisplayName("statistics")
    class Statistics {
        @Test
        @DisplayName("counts frames, key frames, the picture size, the frame rate and the pacer queue time per SSRC")
        void sendStatistics() throws Exception {
            var net = new TestNetwork();
            var queued = new ArrayList<Map.Entry<ByteBuffer, OutgoingPacketScheduler.PacketSink>>();
            OutgoingPacketScheduler scheduler = (packet, priority, ssrc, sink) -> queued.add(Map.entry(packet, sink));
            var session = net.session(net.left, 10).scheduler(scheduler).build();
            var stream = session.createSendStream(video().build());
            for (var frame = 0; frame < 40; frame++) {
                var info = frame == 0 ? RtpSendStream.FrameInfo.keyFrame(640, 360) : RtpSendStream.FrameInfo.DELTA;
                stream.send(List.of(new RtpSendStream.Payload(payload(frame), true, Map.of())), 3000L * frame,
                        VIDEO, info);
                net.clock.advanceMillis(5);
                for (var entry : queued) {
                    entry.getValue().send(entry.getKey());
                }
                queued.clear();
                net.clock.advanceMillis(28);
            }
            var statistics = stream.statistics();
            assertEquals(40, statistics.framesSent());
            assertEquals(1, statistics.keyFramesSent());
            assertEquals(OptionalInt.of(640), statistics.frameWidth());
            assertEquals(OptionalInt.of(360), statistics.frameHeight());
            assertEquals(30, statistics.framesPerSecond().orElseThrow(), 1.5);
            assertEquals(Duration.ofMillis(200), statistics.totalPacketSendDelay());
        }

        @Test
        @DisplayName("reports the FlexFEC SSRC and the FEC bytes received")
        void fecStatistics() throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().fec(new FecConfig.Flexfec(98, 3333, false, 50)).build());
            var rx = pair.receive(videoReceiver().fec(new FecConfig.Flexfec(98, 3333, false, 0)).build());
            send(stream, List.of(payload(1), payload(2)), 0, true, Map.of(), VIDEO);
            pair.net.deliver();
            var statistics = rx.statistics();
            assertEquals(3333, statistics.fecSsrc().orElseThrow());
            assertTrue(statistics.fecBytesReceived() > 0);
            assertTrue(statistics.fecPacketsReceived() > 0);
        }
    }

    @Nested
    @DisplayName("FlexFEC schemes")
    class FlexfecSchemes {
        void run(FecConfig.FlexfecScheme scheme, java.util.function.IntPredicate lost, int frames, int perFrame)
                throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().fec(new FecConfig.Flexfec(98, 3333, false, 100, scheme))
                    .build());
            var rx = pair.receive(videoReceiver().fec(new FecConfig.Flexfec(98, 3333, false, 0)).build());
            pair.net.left.dropRtp = packet -> packet.ssrc() == VIDEO_SSRC && lost.test(valueOf(packet));
            for (var frame = 0; frame < frames; frame++) {
                var payloads = new ArrayList<ByteBuffer>();
                for (var i = 0; i < perFrame; i++) {
                    payloads.add(payload(frame * perFrame + i));
                }
                send(stream, payloads, 3000L * frame, true, Map.of(), VIDEO);
                pair.net.deliver();
            }
            assertEquals(frames * perFrame, new TreeSet<>(values(pair.received)).size());
            assertTrue(rx.statistics().packetsRecovered() > 0);
        }

        @Test
        @DisplayName("recovers one loss per row with 1-D row FEC (F=1, D=0)")
        void rows() throws Exception {
            run(new FecConfig.FlexfecScheme.RowColumn(4, 0, true), value -> value % 4 == 2, 3, 4);
        }

        @Test
        @DisplayName("recovers a burst inside one row with 2-D row and column FEC")
        void columns() throws Exception {
            run(new FecConfig.FlexfecScheme.RowColumn(4, 3, true), value -> value == 5 || value == 6, 3, 4);
        }

        @Test
        @DisplayName("recovers lost packets from FlexFEC retransmissions (R=1)")
        void retransmission() throws Exception {
            run(new FecConfig.FlexfecScheme.Retransmission(), value -> value % 2 == 0, 3, 4);
        }

        @Test
        @DisplayName("refuses schemes other than masks for flexfec-03")
        void draft03() {
            assertThrows(IllegalArgumentException.class, () -> new FecConfig.Flexfec(98, 3333, true, 50,
                    new FecConfig.FlexfecScheme.Retransmission()));
            assertThrows(IllegalArgumentException.class, () -> new FecConfig.FlexfecScheme.RowColumn(4, 1, true));
            assertFalse(new FecConfig.Flexfec(98, 3333, false, 50).scheme()
                    instanceof FecConfig.FlexfecScheme.RowColumn);
        }
    }
}
