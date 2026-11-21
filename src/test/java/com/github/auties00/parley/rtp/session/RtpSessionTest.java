package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.rtp.extension.Mid;
import com.github.auties00.parley.rtp.rtcp.Bye;
import com.github.auties00.parley.rtp.rtcp.ExtendedReport;
import com.github.auties00.parley.rtp.rtcp.FullIntraRequest;
import com.github.auties00.parley.rtp.rtcp.Nack;
import com.github.auties00.parley.rtp.rtcp.PictureLossIndication;
import com.github.auties00.parley.rtp.rtcp.ReceiverReport;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.SenderReport;
import com.github.auties00.parley.rtp.rtcp.SourceDescription;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import static com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority.AUDIO;
import static com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority.VIDEO;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Drives two sessions against each other over the in-memory [TestNetwork] with a manual clock: the send path and
/// its stamping, NACK and RTX loops, RED and FEC recovery under loss, RTCP reports and round-trip times, keyframe
/// requests, simulcast demultiplexing and the scheduler and observer hooks.
@DisplayName("RTP session")
class RtpSessionTest {
    static final HeaderExtensionMap EXTENSIONS = HeaderExtensionMap.of(Map.of(1, HeaderExtensionUris.MID,
            2, HeaderExtensionUris.RTP_STREAM_ID, 3, HeaderExtensionUris.REPAIRED_RTP_STREAM_ID,
            4, HeaderExtensionUris.TRANSPORT_WIDE_CC, 5, HeaderExtensionUris.ABS_SEND_TIME));
    static final long VIDEO_SSRC = 1111;
    static final long RTX_SSRC = 2222;

    static SendStreamConfig.Builder video() {
        return SendStreamConfig.builder("v", VIDEO_SSRC, 96, 90_000).extensions(EXTENSIONS);
    }

    static ReceiveStreamConfig.Builder videoReceiver() {
        return ReceiveStreamConfig.builder(96, 90_000).mid("v").extensions(EXTENSIONS);
    }

    static ByteBuffer payload(int value) {
        return ByteBuffer.wrap(new byte[]{(byte) value, (byte) (value >> 8), 42});
    }

    /// Sends payloads as one frame, the marker on the last one.
    static void send(RtpSendStream stream, List<ByteBuffer> payloads, long timestamp, boolean marker,
                     Map<java.net.URI, ByteBuffer> extensions, OutgoingPacketScheduler.Priority priority)
            throws java.io.IOException {
        var list = new ArrayList<RtpSendStream.Payload>();
        for (var i = 0; i < payloads.size(); i++) {
            list.add(new RtpSendStream.Payload(payloads.get(i), marker && i == payloads.size() - 1, extensions));
        }
        stream.send(list, timestamp, priority);
    }

    static int valueOf(RtpPacket packet) {
        var payload = packet.payload();
        return (payload.get(0) & 0xFF) | (payload.get(1) & 0xFF) << 8;
    }

    static List<Integer> values(List<RtpPacket> packets) {
        var out = new ArrayList<Integer>();
        for (var packet : packets) {
            out.add(valueOf(packet));
        }
        return out;
    }

    /// Two connected sessions, the left one sending and the right one receiving.
    static final class Pair {
        final TestNetwork net = new TestNetwork();
        final RtpSession left;
        final RtpSession right;
        final List<RtpPacket> received = new ArrayList<>();

        Pair(RtcpConfig rtcp) {
            left = net.session(net.left, 10).extensions(EXTENSIONS).rtcp(rtcp).build();
            right = net.session(net.right, 20).extensions(EXTENSIONS).rtcp(rtcp).build();
        }

        Pair() {
            this(RtcpConfig.webrtc());
        }

        RtpReceiveStream receive(ReceiveStreamConfig config) {
            var stream = right.createReceiveStream(config);
            stream.setPacketReceiver(packet -> received.add(packet.copy()));
            return stream;
        }
    }

    @Nested
    @DisplayName("send path")
    class SendPath {
        @Test
        @DisplayName("writes MID, RID and stamped transport-wide sequence numbers and send times")
        void extensions() throws Exception {
            var pair = new Pair();
            var sent = new ArrayList<int[]>();
            var observed = new TestObserver();
            var left = pair.net.session(pair.net.left, 10).extensions(EXTENSIONS).feedbackObserver(observed).build();
            var stream = left.createSendStream(video().rid("h").build());
            pair.net.clock.advanceMillis(500);
            send(stream, List.of(payload(1), payload(2)), 90_000, true, Map.of(), VIDEO);
            for (var packet : pair.net.left.sentRtp) {
                assertEquals("v", Mid.parse(packet.extension(1).orElseThrow()).value());
                assertEquals("h", new String(TestBytes.of(packet.extension(2).orElseThrow())));
                sent.add(new int[]{packet.extension(4).orElseThrow().getShort(0) & 0xFFFF, packet.sequence()});
                assertEquals(com.github.auties00.parley.rtp.extension.AbsSendTime.ofNanos(pair.net.clock.nanos())
                        .value(), com.github.auties00.parley.rtp.extension.AbsSendTime.parse(
                        packet.extension(5).orElseThrow()).value());
            }
            assertEquals(0, sent.get(0)[0]);
            assertEquals(1, sent.get(1)[0]);
            assertEquals((sent.get(0)[1] + 1) & 0xFFFF, sent.get(1)[1]);
            assertFalse(pair.net.left.sentRtp.get(0).marker());
            assertTrue(pair.net.left.sentRtp.get(1).marker());
            assertEquals(List.of(0, 1), observed.sequences);
            var statistics = stream.statistics();
            assertEquals(2, statistics.packetsSent());
            assertEquals(6, statistics.bytesSent());
        }

        @Test
        @DisplayName("stamps transport-wide sequence numbers in the order a pacer releases packets")
        void pacedOrder() throws Exception {
            var net = new TestNetwork();
            var queued = new ArrayList<Map.Entry<ByteBuffer, OutgoingPacketScheduler.PacketSink>>();
            OutgoingPacketScheduler pacer = (packet, priority, ssrc, sink) -> queued.add(Map.entry(packet, sink));
            var session = net.session(net.left, 10).extensions(EXTENSIONS).scheduler(pacer).build();
            var audio = session.createSendStream(SendStreamConfig.builder("a", 5, 111, 48_000)
                    .extensions(EXTENSIONS).build());
            var video = session.createSendStream(video().build());
            send(video, List.of(payload(1)), 0, true, Map.of(), VIDEO);
            send(audio, List.of(payload(2)), 0, false, Map.of(), AUDIO);
            assertTrue(net.left.sentRtp.isEmpty());
            for (var i = queued.size() - 1; i >= 0; i--) {
                queued.get(i).getValue().send(queued.get(i).getKey());
            }
            assertEquals(5, net.left.sentRtp.get(0).ssrc());
            assertEquals(0, net.left.sentRtp.get(0).extension(4).orElseThrow().getShort(0));
            assertEquals(1, net.left.sentRtp.get(1).extension(4).orElseThrow().getShort(0));
        }

        @Test
        @DisplayName("sends payloads with their own markers and extension values")
        void ownMarkers() throws Exception {
            var pair = new Pair();
            var withLevel = EXTENSIONS.entries().entrySet().stream()
                    .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            withLevel.put(6, HeaderExtensionUris.AUDIO_LEVEL);
            var stream = pair.left.createSendStream(video().extensions(HeaderExtensionMap.of(withLevel)).build());
            stream.send(List.of(new RtpSendStream.Payload(payload(1), true,
                            Map.of(HeaderExtensionUris.AUDIO_LEVEL, ByteBuffer.wrap(new byte[]{9}),
                                    HeaderExtensionUris.PLAYOUT_DELAY, ByteBuffer.wrap(new byte[3]))),
                    new RtpSendStream.Payload(payload(2), false, Map.of())), 0, VIDEO);
            assertTrue(pair.net.left.sentRtp.get(0).marker());
            assertEquals(9, pair.net.left.sentRtp.get(0).extension(6).orElseThrow().get(0));
            assertFalse(pair.net.left.sentRtp.get(1).marker());
            assertTrue(pair.net.left.sentRtp.get(1).extension(6).isEmpty());
        }

        @Test
        @DisplayName("refuses to reuse a local SSRC and to send after close")
        void misuse() throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().rtx(RTX_SSRC, 97).build());
            assertThrows(IllegalArgumentException.class,
                    () -> pair.left.createSendStream(SendStreamConfig.builder("x", RTX_SSRC, 96, 90_000).build()));
            pair.left.close();
            assertThrows(IllegalStateException.class,
                    () -> send(stream, List.of(payload(1)), 0, true, Map.of(), VIDEO));
            assertFalse(pair.net.left.sentRtcpOf(Bye.class).isEmpty());
        }
    }

    @Nested
    @DisplayName("NACK and retransmission")
    class Retransmission {
        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        @DisplayName("recovers lost packets through NACK and RTX, or plain resends without RTX")
        void nackLoop(boolean rtx) throws Exception {
            var pair = new Pair();
            var config = video().feedback(Set.of(FeedbackMechanism.NACK, FeedbackMechanism.PLI));
            var receiver = videoReceiver().feedback(Set.of(FeedbackMechanism.NACK, FeedbackMechanism.PLI));
            if (rtx) {
                config.rtx(RTX_SSRC, 97);
                receiver.rtxPayloadType(97, 96);
            }
            var stream = pair.left.createSendStream(config.build());
            var rx = pair.receive(receiver.build());
            var dropped = new HashSet<Integer>();
            pair.net.left.dropRtp = packet -> packet.ssrc() == VIDEO_SSRC && (valueOf(packet) == 5
                    || valueOf(packet) == 6) && dropped.add(valueOf(packet));
            for (var i = 0; i < 20; i++) {
                send(stream, List.of(payload(i)), 3000L * i, true, Map.of(), VIDEO);
                pair.net.deliver();
            }
            assertEquals(new TreeSet<>(java.util.stream.IntStream.range(0, 20).boxed().toList()),
                    new TreeSet<>(values(pair.received)));
            assertEquals(List.of(0, 1, 2, 3, 4, 7, 5, 6), values(pair.received).subList(0, 8));
            assertEquals(1, pair.net.right.sentRtcpOf(Nack.class).size());
            var sendStatistics = stream.statistics();
            assertEquals(2, sendStatistics.retransmittedPacketsSent());
            assertEquals(1, sendStatistics.nackCount());
            var receiveStatistics = rx.statistics();
            assertEquals(2, receiveStatistics.retransmittedPacketsReceived());
            assertEquals(1, receiveStatistics.nackCount());
            assertEquals(rtx, receiveStatistics.rtxSsrc().isPresent());
            if (rtx) {
                assertTrue(pair.net.left.sentRtp.stream().anyMatch(packet -> packet.ssrc() == RTX_SSRC
                        && packet.extension(4).isPresent()));
            }
        }

        @Test
        @DisplayName("retries NACKs after each round trip and falls back to a PLI when retries run out")
        void retriesThenKeyframe() throws Exception {
            var pair = new Pair();
            var requests = new ArrayList<KeyframeRequest>();
            var stream = pair.left.createSendStream(video().rtx(RTX_SSRC, 97)
                    .feedback(Set.of(FeedbackMechanism.NACK, FeedbackMechanism.PLI))
                    .keyframeRequestListener(requests::add).build());
            pair.receive(videoReceiver().rtxPayloadType(97, 96).nackMaxRetries(3)
                    .feedback(Set.of(FeedbackMechanism.NACK, FeedbackMechanism.PLI)).build());
            pair.net.left.dropRtp = packet -> packet.ssrc() == RTX_SSRC || valueOf(packet) == 1;
            for (var i = 0; i < 3; i++) {
                send(stream, List.of(payload(i)), 3000L * i, true, Map.of(), VIDEO);
                pair.net.deliver();
            }
            assertEquals(1, pair.net.right.sentRtcpOf(Nack.class).size());
            for (var round = 0; round < 3; round++) {
                pair.net.clock.advanceMillis(150);
                pair.right.tick();
                pair.net.deliver();
            }
            assertEquals(3, pair.net.right.sentRtcpOf(Nack.class).size());
            assertEquals(1, pair.net.right.sentRtcpOf(PictureLossIndication.class).size());
            assertEquals(1, requests.size());
            assertEquals(KeyframeMethod.PLI, requests.getFirst().method());
            assertEquals(VIDEO_SSRC, requests.getFirst().mediaSsrc());
        }

        @Test
        @DisplayName("queues feedback for the next regular report when early feedback is not allowed")
        void compoundFeedback() throws Exception {
            var pair = new Pair(RtcpConfig.rfc3550(2_000_000));
            var stream = pair.left.createSendStream(video().feedback(Set.of(FeedbackMechanism.NACK)).build());
            pair.receive(videoReceiver().feedback(Set.of(FeedbackMechanism.NACK)).build());
            pair.net.left.dropRtp = packet -> valueOf(packet) == 1;
            for (var i = 0; i < 3; i++) {
                send(stream, List.of(payload(i)), 3000L * i, true, Map.of(), VIDEO);
                pair.net.deliver();
            }
            assertTrue(pair.net.right.sentRtcpOf(Nack.class).isEmpty());
            pair.net.clock.advanceMillis(10_000);
            pair.right.tick();
            var compound = pair.net.right.sentRtcp.getLast();
            assertTrue(compound.getFirst() instanceof ReceiverReport);
            assertTrue(compound.stream().anyMatch(packet -> packet instanceof SourceDescription));
            assertTrue(compound.stream().anyMatch(packet -> packet instanceof Nack));
        }

        @Test
        @DisplayName("drops duplicates and keeps sequence order with a reorder delay")
        void reorder() throws Exception {
            var net = new TestNetwork();
            var session = net.session(net.right, 20).extensions(EXTENSIONS).build();
            var stream = session.createReceiveStream(videoReceiver().reorderDelay(Duration.ofMillis(100)).build());
            var received = new ArrayList<Integer>();
            stream.setPacketReceiver(packet -> received.add(packet.sequence()));
            for (var sequence : List.of(10, 12, 11, 11, 13, 15)) {
                net.right.rtpReceiver.receive(raw(sequence), net.clock.nanos());
            }
            assertEquals(List.of(10, 11, 12, 13), received);
            net.clock.advanceMillis(100);
            session.tick();
            assertEquals(List.of(10, 11, 12, 13, 15), received);
            assertEquals(1, stream.statistics().packetsDuplicated());
        }
    }

    static ByteBuffer raw(int sequence) {
        return RtpPacketWriter.into(ByteBuffer.allocate(64)).ssrc(VIDEO_SSRC).payloadType(96).sequence(sequence)
                .timestamp(3000L * sequence).extension(1, new Mid("v").encode())
                .payload(ByteBuffer.wrap(new byte[]{1})).finish();
    }

    @Nested
    @DisplayName("redundancy and FEC")
    class Redundancy {
        @Test
        @DisplayName("recovers a lost audio packet from the RED redundancy of the next one")
        void red() throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(SendStreamConfig.builder("v", 7, 111, 48_000)
                    .extensions(EXTENSIONS).red(new RedConfig(63, 2)).build());
            var rx = pair.receive(ReceiveStreamConfig.builder(111, 48_000).mid("v").redPayloadType(63)
                    .extensions(EXTENSIONS).build());
            var count = new int[1];
            pair.net.left.dropRtp = packet -> ++count[0] == 4;
            for (var i = 0; i < 8; i++) {
                send(stream, List.of(payload(i)), 960L * i, false, Map.of(), AUDIO);
                pair.net.deliver();
            }
            assertEquals(List.of(0, 1, 2, 3, 4, 5, 6, 7), values(pair.received));
            assertTrue(pair.received.stream().allMatch(packet -> packet.payloadType() == 111));
            assertEquals(960L * 3, pair.received.get(3).timestamp());
            assertEquals(1, rx.statistics().packetsRecovered());
        }

        @Test
        @DisplayName("recovers lost video packets from ULPFEC carried in RED")
        void ulpfec() throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().fec(new FecConfig.Ulpfec(100, 101, 50)).build());
            var rx = pair.receive(videoReceiver().fec(new FecConfig.Ulpfec(100, 101, 0)).build());
            pair.net.left.dropRtp = packet -> {
                var blocks = packet.payloadType() == 100 && packet.payload().get(0) == 96;
                return blocks && packet.payload().get(1) == 2;
            };
            for (var frame = 0; frame < 3; frame++) {
                var payloads = new ArrayList<ByteBuffer>();
                for (var i = 0; i < 4; i++) {
                    payloads.add(payload(frame * 4 + i).position(0));
                }
                send(stream, payloads, 3000L * frame, true, Map.of(), VIDEO);
                pair.net.deliver();
            }
            var values = new TreeSet<>(values(pair.received));
            assertEquals(12, values.size());
            assertTrue(rx.statistics().packetsRecovered() >= 1);
            assertTrue(rx.statistics().fecPacketsReceived() >= 3);
            assertEquals(6, stream.statistics().fecPacketsSent());
            assertTrue(pair.received.stream().allMatch(packet -> packet.payloadType() == 96));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        @DisplayName("recovers lost video packets from FlexFEC on its own SSRC")
        void flexfec(boolean draft03) throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().fec(new FecConfig.Flexfec(98, 3333, draft03, 50))
                    .build());
            var rx = pair.receive(videoReceiver().fec(new FecConfig.Flexfec(98, 3333, draft03, 0)).build());
            pair.net.left.dropRtp = packet -> packet.ssrc() == VIDEO_SSRC && valueOf(packet) % 4 == 1;
            for (var frame = 0; frame < 3; frame++) {
                var payloads = new ArrayList<ByteBuffer>();
                for (var i = 0; i < 4; i++) {
                    payloads.add(payload(frame * 4 + i));
                }
                send(stream, payloads, 3000L * frame, true, Map.of(), VIDEO);
                pair.net.deliver();
            }
            assertEquals(12, new TreeSet<>(values(pair.received)).size());
            assertEquals(3, rx.statistics().packetsRecovered());
            assertTrue(pair.net.left.sentRtp.stream().anyMatch(packet -> packet.ssrc() == 3333));
        }
    }

    @Nested
    @DisplayName("RTCP")
    class Rtcp {
        @Test
        @DisplayName("reports loss, measures the round trip from LSR and DLSR, and maps the sender clock")
        void reportsAndRtt() throws Exception {
            var pair = new Pair();
            var observer = new TestObserver();
            var left = pair.net.session(pair.net.left, 10).extensions(EXTENSIONS).feedbackObserver(observer).build();
            var stream = left.createSendStream(video().build());
            var rx = pair.receive(videoReceiver().build());
            var count = new int[1];
            pair.net.left.dropRtp = packet -> ++count[0] == 4 || count[0] == 8;
            for (var i = 0; i < 10; i++) {
                send(stream, List.of(payload(i)), 3000L * i, true, Map.of(), VIDEO);
            }
            pair.net.deliver();
            pair.net.clock.advanceMillis(1100);
            left.tick();
            assertTrue(pair.net.left.sentRtcp.getLast().getFirst() instanceof SenderReport);
            pair.net.clock.advanceMillis(50);
            pair.net.deliver();
            var mapping = rx.senderClock().orElseThrow();
            assertEquals(3000L * 9 + 90_000L * 1100 / 1000, mapping.rtpTimestamp());
            pair.net.clock.advanceMillis(200);
            pair.right.tick();
            var compound = pair.net.right.sentRtcp.getLast();
            var report = (ReceiverReport) compound.getFirst();
            var block = report.reports().getFirst();
            assertEquals(VIDEO_SSRC, block.ssrc());
            assertEquals(2, block.cumulativeLost());
            assertEquals(2 * 256 / 10, block.fractionLost());
            assertTrue(compound.stream().anyMatch(packet -> packet instanceof ExtendedReport));
            pair.net.clock.advanceMillis(50);
            pair.net.deliver();
            var remote = stream.statistics().remote().orElseThrow();
            assertEquals(2, remote.packetsLost());
            assertEquals(100, remote.roundTripTime().orElseThrow().toMillis(), 1);
            assertEquals(1, observer.reports.size());
            assertEquals(100, observer.rtts.getFirst() / 1_000_000L, 1);
            assertEquals(2, rx.statistics().packetsLost());
            assertEquals(1, rx.statistics().remoteSender().orElseThrow().reportsReceived());
            assertEquals(10, rx.statistics().remoteSender().orElseThrow().packetsSent());
            pair.net.clock.advanceMillis(2000);
            left.tick();
            assertTrue(pair.net.left.sentRtcp.getLast().stream().anyMatch(packet -> packet instanceof ExtendedReport
                    xr && xr.blocks().stream().anyMatch(b -> b instanceof ExtendedReport.Dlrr)));
            pair.net.clock.advanceMillis(50);
            pair.net.deliver();
            var receiverRtt = rx.statistics().roundTripTime().orElseThrow();
            assertTrue(Math.abs(receiverRtt.toMillis() - 100) <= 1, receiverRtt.toString());
            assertEquals("left", pair.right.remoteCname(VIDEO_SSRC).orElseThrow());
        }

        @Test
        @DisplayName("forwards keyframe requests, deduplicating FIR retransmissions")
        void keyframes() throws Exception {
            var pair = new Pair();
            var requests = new ArrayList<KeyframeRequest>();
            var stream = pair.left.createSendStream(video().feedback(Set.of(FeedbackMechanism.FIR))
                    .keyframeRequestListener(requests::add).build());
            var rx = pair.receive(videoReceiver().ssrc(VIDEO_SSRC).feedback(Set.of(FeedbackMechanism.FIR)).build());
            rx.requestKeyframe(KeyframeMethod.FIR);
            rx.requestKeyframe(KeyframeMethod.PLI);
            pair.net.deliver();
            pair.right.sendRtcp(new FullIntraRequest(20, List.of(new FullIntraRequest.Entry(VIDEO_SSRC, 0))));
            pair.net.deliver();
            assertEquals(List.of(KeyframeMethod.FIR, KeyframeMethod.PLI),
                    requests.stream().map(KeyframeRequest::method).toList());
            assertEquals(1, stream.statistics().firCount());
            assertEquals(1, stream.statistics().pliCount());
            assertEquals(1, rx.statistics().firCount());
        }

        @Test
        @DisplayName("requests retransmissions explicitly and refuses without a known SSRC")
        void explicitNack() throws Exception {
            var pair = new Pair();
            var unknown = pair.right.createReceiveStream(videoReceiver().build());
            assertThrows(IllegalStateException.class, () -> unknown.requestRetransmission(List.of(1)));
            assertThrows(IllegalStateException.class, () -> unknown.requestKeyframe(KeyframeMethod.PLI));
            var known = pair.right.createReceiveStream(ReceiveStreamConfig.builder(100, 90_000).ssrc(5).build());
            known.requestRetransmission(List.of(1, 2));
            assertEquals(List.of(1, 2), pair.net.right.sentRtcpOf(Nack.class).getFirst().sequences());
        }

        @Test
        @DisplayName("hands congestion feedback to the observer and the rest to the RTCP listener")
        void observer() throws Exception {
            var pair = new Pair();
            var observer = new TestObserver();
            var forwarded = new ArrayList<RtcpPacket>();
            var left = pair.net.session(pair.net.left, 10).extensions(EXTENSIONS).feedbackObserver(observer)
                    .rtcpListener(forwarded::add).build();
            var feedback = new TransportFeedback(20, 1, 0, 0, 0, List.of(TransportFeedback.PacketResult.lost(0)));
            pair.right.sendRtcp(feedback);
            pair.net.deliver();
            assertEquals(List.of(), observer.feedback, "feedback before any packet left names nothing sent");
            assertEquals(1, left.droppedFeedbackCount());
            send(left.createSendStream(video().build()), List.of(payload(1)), 0, true, Map.of(), VIDEO);
            pair.right.sendRtcp(feedback, new Remb(20, 500_000, List.of(1L)),
                    new com.github.auties00.parley.rtp.rtcp.App(1, 20, "TEST", ByteBuffer.allocate(4)));
            pair.net.deliver();
            assertEquals(List.of(feedback), observer.feedback);
            assertEquals(500_000, observer.rembs.getFirst().bitrateBps());
            assertEquals(1, forwarded.size());
            pair.right.close();
            pair.net.deliver();
            assertTrue(forwarded.getLast() instanceof Bye);
        }
    }

    @Nested
    @DisplayName("simulcast and unsignaled streams")
    class Simulcast {
        @Test
        @DisplayName("lets the unhandled-stream listener create one receive stream per RID")
        void sfu() throws Exception {
            var pair = new Pair();
            var high = pair.left.createSendStream(video().rid("h").rtx(RTX_SSRC, 97)
                    .feedback(Set.of(FeedbackMechanism.NACK)).build());
            var low = pair.left.createSendStream(SendStreamConfig.builder("v", 4444, 96, 90_000).rid("l")
                    .rtx(5555, 97).extensions(EXTENSIONS).feedback(Set.of(FeedbackMechanism.NACK)).build());
            var byRid = new java.util.HashMap<String, List<Integer>>();
            var reported = new ArrayList<UnsignaledStream>();
            var right = new RtpSession[1];
            right[0] = pair.net.session(pair.net.right, 30).extensions(EXTENSIONS).unsignaledStreamListener(stream -> {
                reported.add(stream);
                var rid = stream.rid().orElseThrow();
                var rx = right[0].createReceiveStream(videoReceiver().rid(rid).rtxPayloadType(97, 96)
                        .feedback(Set.of(FeedbackMechanism.NACK)).build());
                var list = new ArrayList<Integer>();
                byRid.put(rid, list);
                rx.setPacketReceiver(packet -> list.add(valueOf(packet)));
            }).build();
            var dropped = new HashSet<Integer>();
            pair.net.left.dropRtp = packet -> packet.ssrc() == 4444 && valueOf(packet) == 102
                    && dropped.add(valueOf(packet));
            for (var i = 0; i < 5; i++) {
                send(high, List.of(payload(i)), 3000L * i, true, Map.of(), VIDEO);
                send(low, List.of(payload(100 + i)), 3000L * i, true, Map.of(), VIDEO);
                pair.net.deliver();
            }
            assertEquals(2, reported.size());
            assertEquals(List.of(0, 1, 2, 3, 4), byRid.get("h"));
            assertEquals(new TreeSet<>(List.of(100, 101, 102, 103, 104)), new TreeSet<>(byRid.get("l")));
            assertEquals(1, low.statistics().retransmittedPacketsSent());
        }

        @Test
        @DisplayName("updates routes after renegotiation and stops routing removed streams")
        void routes() throws Exception {
            var pair = new Pair();
            var stream = pair.left.createSendStream(video().build());
            var rx = pair.receive(videoReceiver().build());
            send(stream, List.of(payload(1)), 0, true, Map.of(), VIDEO);
            pair.net.deliver();
            pair.right.updateRoutes(RtpRoutingTable.of(EXTENSIONS, List.of()));
            send(stream, List.of(payload(2)), 3000, true, Map.of(), VIDEO);
            pair.net.deliver();
            assertEquals(List.of(1), values(pair.received));
            pair.right.updateRoutes(RtpRoutingTable.of(EXTENSIONS, List.of(rx)));
            pair.right.removeReceiveStream(rx);
            send(stream, List.of(payload(3)), 6000, true, Map.of(), VIDEO);
            pair.net.deliver();
            assertEquals(List.of(1), values(pair.received));
        }
    }

    @Nested
    @DisplayName("padding")
    class Padding {
        @Test
        @DisplayName("pads with RTX copies of recent packets, or padding-only packets without RTX")
        void padding() throws Exception {
            for (var rtx : List.of(true, false)) {
                var net = new TestNetwork();
                var sources = new ArrayList<OutgoingPacketScheduler.PaddingSource>();
                var observer = new TestObserver();
                var scheduler = new OutgoingPacketScheduler() {
                    @Override
                    public void schedule(ByteBuffer packet, Priority priority, long ssrc, PacketSink sink) {
                        try {
                            sink.send(packet);
                        } catch (java.io.IOException exception) {
                            throw new AssertionError(exception);
                        }
                    }

                    @Override
                    public void setPaddingSource(PaddingSource source) {
                        sources.add(source);
                    }
                };
                var session = net.session(net.left, 10).extensions(EXTENSIONS).scheduler(scheduler)
                        .feedbackObserver(observer).build();
                var receiver = net.session(net.right, 20).extensions(EXTENSIONS).build();
                var config = video().feedback(Set.of(FeedbackMechanism.NACK));
                var receiveConfig = videoReceiver();
                if (rtx) {
                    config.rtx(RTX_SSRC, 97);
                    receiveConfig.rtxPayloadType(97, 96);
                }
                var stream = session.createSendStream(config.build());
                var delivered = new ArrayList<Integer>();
                receiver.createReceiveStream(receiveConfig.build())
                        .setPacketReceiver(packet -> delivered.add(valueOf(packet)));
                assertEquals(0, sources.getFirst().sendPadding(1000, true));
                send(stream, List.of(payload(1)), 0, true, Map.of(), VIDEO);
                var before = net.left.sentRtp.size();
                var sent = sources.getFirst().sendPadding(500, true);
                assertTrue(sent >= 500 || rtx);
                assertTrue(net.left.sentRtp.size() > before);
                assertTrue(observer.probes > 0);
                net.deliver();
                assertEquals(List.of(1), delivered);
                if (!rtx) {
                    assertTrue(net.left.sentRtp.getLast().paddingLength() > 0);
                    assertTrue(stream.statistics().paddingPacketsSent() >= 2);
                }
            }
        }
    }

    /// Records what a congestion controller would see.
    static final class TestObserver implements TransportFeedbackObserver {
        final List<Integer> sequences = new ArrayList<>();
        final List<TransportFeedback> feedback = new ArrayList<>();
        final List<Remb> rembs = new ArrayList<>();
        final List<List<ReceptionReport>> reports = new ArrayList<>();
        final List<Long> rtts = new ArrayList<>();
        int probes;

        @Override
        public void onPacketSent(SentPacket packet) {
            sequences.add(packet.transportSequence());
            if (packet.priority() == OutgoingPacketScheduler.Priority.PADDING) {
                probes++;
            }
        }

        @Override
        public void onTransportFeedback(TransportFeedback feedback, long arrivalNanos) {
            this.feedback.add(feedback);
        }

        @Override
        public void onRemb(Remb remb, long arrivalNanos) {
            rembs.add(remb);
        }

        @Override
        public void onReceptionReports(List<ReceptionReport> reports, long rttNanos, long arrivalNanos) {
            this.reports.add(reports);
            rtts.add(rttNanos);
        }
    }

    /// Copies a buffer's remaining bytes.
    static final class TestBytes {
        static byte[] of(ByteBuffer buffer) {
            var out = new byte[buffer.remaining()];
            buffer.duplicate().get(out);
            return out;
        }
    }

    @Test
    @DisplayName("runs its RTCP timer on its own thread and stops it on close")
    void timerThread() throws Exception {
        var net = new TestNetwork();
        var threads = new ArrayList<Thread>();
        var session = RtpSession.builder(net.left).clock(System::nanoTime)
                .rtcp(new RtcpConfig(true, true, false, Duration.ofMillis(100), Duration.ZERO, 2_000_000))
                .threadFactory(runnable -> {
                    var thread = Thread.ofVirtual().unstarted(runnable);
                    threads.add(thread);
                    return thread;
                }).build();
        var deadline = System.nanoTime() + 5_000_000_000L;
        while (net.left.sentRtcp.isEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertFalse(net.left.sentRtcp.isEmpty());
        session.close();
        threads.getFirst().join(5_000);
        assertFalse(threads.getFirst().isAlive());
    }

    @Test
    @DisplayName("parses only RtpFormatException-free packets and counts malformed ones")
    void malformed() throws RtpFormatException {
        var net = new TestNetwork();
        var session = net.session(net.right, 20).build();
        net.right.rtpReceiver.receive(ByteBuffer.wrap(new byte[]{1, 2, 3}), 0);
        net.right.rtcpReceiver.receive(ByteBuffer.wrap(new byte[]{(byte) 0x80, (byte) 201, 0, 5}), 0);
        assertEquals(1, session.malformedRtpCount());
        assertEquals(1, session.malformedRtcpCount());
        assertTrue(RtpPacket.parse(raw(1)).extension(1).isPresent());
        assertEquals(Optional.empty(), session.remoteCname(1));
    }
}
