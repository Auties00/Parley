package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.rtp.extension.Mid;
import com.github.auties00.parley.rtp.extension.RepairedRtpStreamId;
import com.github.auties00.parley.rtp.extension.RtpStreamId;
import com.github.auties00.parley.rtp.fec.FecEncoder;
import com.github.auties00.parley.rtp.fec.FecFormat;
import com.github.auties00.parley.rtp.fec.Red;
import com.github.auties00.parley.rtp.fec.RedEncoder;
import com.github.auties00.parley.rtp.fec.Rtx;
import com.github.auties00.parley.rtp.rtcp.Nack;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.SenderReport;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Consumer;

/// One outgoing RTP stream of a session: a sequence number space, an SSRC, its retransmission history and its
/// repair streams (RTX, RED, ULPFEC or FlexFEC), as negotiated in its [SendStreamConfig].
///
/// [#send(List, long, boolean, Map, OutgoingPacketScheduler.Priority)] turns already packetized payloads into RTP
/// packets: it assigns sequence numbers, writes the MID, RID and caller-supplied header extensions, reserves the
/// transport-wide sequence number and absolute send time the session stamps at send time, wraps them in RED when
/// configured, stores them for retransmission, generates FEC at the end of each frame, and hands everything to the
/// session's [OutgoingPacketScheduler].
///
/// NACKs from the peer are served from the history without involving the application: as RTX when negotiated,
/// otherwise by resending the original packet; a packet already resent within the last round trip is not resent
/// again. PLI and FIR requests reach the [#setKeyframeRequestListener(Consumer)] listener.
///
/// # Threading
///
/// Every method is thread-safe. The keyframe listener is called on the transport's RTCP reader thread and must not
/// block.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc2198.html RFC 2198: RTP Payload for Redundant Audio Data
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
public final class RtpSendStream {
    /// The most padding bytes one padding-only packet carries.
    static final int MAX_PADDING = 255;

    private final RtpSession session;
    private final SendStreamConfig config;
    private final OptionalInt midId;
    private final OptionalInt ridId;
    private final OptionalInt repairedRidId;
    private final OptionalInt transportSequenceId;
    private final OptionalInt absSendTimeId;
    private final PacketHistory history;
    private final RedEncoder redEncoder;
    private final FecEncoder fecEncoder;
    private int sequence;
    private int rtxSequence;
    private int flexfecSequence;
    private long lastRtpTimestamp;
    private long lastCaptureNanos = Long.MIN_VALUE;
    private long lastSentNanos = Long.MIN_VALUE;
    private final Map<Long, Integer> lastFirSequence = new HashMap<>();
    private volatile Consumer<KeyframeRequest> keyframeListener = request -> {
    };

    private long packetsSent;
    private long bytesSent;
    private long headerBytesSent;
    private long retransmittedPacketsSent;
    private long retransmittedBytesSent;
    private long fecPacketsSent;
    private long paddingPacketsSent;
    private long nackCount;
    private long pliCount;
    private long firCount;
    private ReceptionReport lastReport;
    private long reportsReceived;
    private long lastRttNanos = -1;
    private long totalRttNanos;
    private long rttMeasurements;

    RtpSendStream(RtpSession session, SendStreamConfig config, int initialSequence) {
        this.session = session;
        this.config = config;
        var extensions = config.extensions();
        this.midId = extensions.idOf(HeaderExtensionUris.MID);
        this.ridId = config.rid().isPresent() ? extensions.idOf(HeaderExtensionUris.RTP_STREAM_ID)
                : OptionalInt.empty();
        this.repairedRidId = config.rid().isPresent() ? extensions.idOf(HeaderExtensionUris.REPAIRED_RTP_STREAM_ID)
                : OptionalInt.empty();
        this.transportSequenceId = extensions.idOf(HeaderExtensionUris.TRANSPORT_WIDE_CC);
        this.absSendTimeId = extensions.idOf(HeaderExtensionUris.ABS_SEND_TIME);
        this.history = config.feedback().contains(FeedbackMechanism.NACK)
                ? new PacketHistory(config.historyLength().toNanos()) : null;
        this.redEncoder = config.red().map(red -> new RedEncoder(red.distance())).orElse(null);
        this.fecEncoder = config.fec().map(fec -> switch (fec) {
            case FecConfig.Ulpfec ulpfec -> new FecEncoder(FecFormat.ULPFEC, config.ssrc(), ulpfec.protectionPercent());
            case FecConfig.Flexfec flexfec -> new FecEncoder(flexfec.draft03() ? FecFormat.FLEXFEC_03
                    : FecFormat.FLEXFEC, config.ssrc(), flexfec.protectionPercent());
        }).orElse(null);
        this.sequence = initialSequence & 0xFFFF;
        this.rtxSequence = (initialSequence * 7 + 1) & 0xFFFF;
        this.flexfecSequence = (initialSequence * 13 + 3) & 0xFFFF;
    }

    /// One payload to send, with its own marker bit and header extension values.
    ///
    /// @param payload    the payload; its bytes are copied into the packet
    /// @param marker     the marker bit
    /// @param extensions header extension values by URI; values whose URI was not negotiated are not written
    public record Payload(ByteBuffer payload, boolean marker, Map<URI, ByteBuffer> extensions) {
        /// Checks the fields and copies `extensions`.
        public Payload {
            Objects.requireNonNull(payload, "payload cannot be null");
            extensions = Map.copyOf(extensions);
        }
    }

    /// {@return the configuration}
    public SendStreamConfig config() {
        return config;
    }

    /// Sends the payloads of one frame (or one audio packet) with a shared timestamp and header extensions.
    ///
    /// @param payloads         the payloads, in order, at least one; their bytes are copied
    /// @param rtpTimestamp     the RTP timestamp of the frame, an unsigned 32-bit value
    /// @param endOfFrameMarker whether the last payload carries the marker bit
    /// @param extensionValues  header extension values written on every packet, by URI; values whose URI was not
    ///                         negotiated are not written
    /// @param priority         the scheduling priority
    /// @throws IOException             if the scheduler sends at once and the transport fails before any packet left
    /// @throws IllegalArgumentException if `payloads` is empty or `rtpTimestamp` is out of range
    /// @throws IllegalStateException   if the session is closed
    public void send(List<ByteBuffer> payloads, long rtpTimestamp, boolean endOfFrameMarker,
                     Map<URI, ByteBuffer> extensionValues, OutgoingPacketScheduler.Priority priority)
            throws IOException {
        Objects.requireNonNull(payloads, "payloads cannot be null");
        Objects.requireNonNull(extensionValues, "extensionValues cannot be null");
        var list = new ArrayList<Payload>(payloads.size());
        for (var i = 0; i < payloads.size(); i++) {
            list.add(new Payload(payloads.get(i), endOfFrameMarker && i == payloads.size() - 1, extensionValues));
        }
        send(list, rtpTimestamp, priority);
    }

    /// Sends payloads that carry their own marker bits and header extension values, as a packetizer produces them.
    ///
    /// FEC is generated after a payload whose marker bit is set, the end of a frame.
    ///
    /// @param payloads     the payloads, in order, at least one
    /// @param rtpTimestamp the RTP timestamp, an unsigned 32-bit value
    /// @param priority     the scheduling priority
    /// @throws IOException             if the scheduler sends at once and the transport fails
    /// @throws IllegalArgumentException if `payloads` is empty or `rtpTimestamp` is out of range
    /// @throws IllegalStateException   if the session is closed
    public void send(List<Payload> payloads, long rtpTimestamp, OutgoingPacketScheduler.Priority priority)
            throws IOException {
        Objects.requireNonNull(payloads, "payloads cannot be null");
        Objects.requireNonNull(priority, "priority cannot be null");
        if (payloads.isEmpty()) {
            throw new IllegalArgumentException("payloads cannot be empty");
        }
        if (rtpTimestamp < 0 || rtpTimestamp > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("rtpTimestamp must be an unsigned 32-bit value: " + rtpTimestamp);
        }
        var outgoing = new ArrayList<RtpSession.Outgoing>(payloads.size() + 2);
        var lock = session.lock();
        lock.lock();
        try {
            session.checkOpen();
            var now = session.now();
            lastRtpTimestamp = rtpTimestamp;
            lastCaptureNanos = now;
            for (var payload : payloads) {
                buildMedia(payload, rtpTimestamp, priority, now, outgoing);
                if (payload.marker() && fecEncoder != null) {
                    buildFec(rtpTimestamp, now, outgoing);
                }
            }
        } finally {
            lock.unlock();
        }
        session.dispatch(outgoing);
    }

    private void buildMedia(Payload payload, long timestamp, OutgoingPacketScheduler.Priority priority, long now,
                            List<RtpSession.Outgoing> out) {
        var mediaPayload = payload.payload();
        var payloadType = config.payloadType();
        if (redEncoder != null) {
            mediaPayload = redEncoder.encode(payloadType, timestamp, mediaPayload);
            payloadType = config.red().orElseThrow().payloadType();
        }
        var seq = sequence;
        sequence = (sequence + 1) & 0xFFFF;
        var media = writePacket(config.ssrc(), payloadType, seq, timestamp, payload.marker(), payload.extensions(),
                mediaPayload, ridId);
        var sent = media;
        if (fecEncoder != null) {
            fecEncoder.add(view(media));
            if (config.fec().orElseThrow() instanceof FecConfig.Ulpfec ulpfec) {
                var red = Red.encode(List.of(), payloadType, mediaPayload);
                sent = writePacket(config.ssrc(), ulpfec.redPayloadType(), seq, timestamp, payload.marker(),
                        payload.extensions(), red, ridId);
            }
        }
        if (history != null) {
            history.store(view(sent).copy(), now, priority);
        }
        out.add(new RtpSession.Outgoing(sent, priority, config.ssrc(), RtpSession.PacketKind.MEDIA, this));
    }

    private void buildFec(long timestamp, long now, List<RtpSession.Outgoing> out) {
        for (var fecPayload : fecEncoder.flush()) {
            switch (config.fec().orElseThrow()) {
                case FecConfig.Ulpfec ulpfec -> {
                    var red = Red.encode(List.of(), ulpfec.ulpfecPayloadType(), fecPayload);
                    var seq = sequence;
                    sequence = (sequence + 1) & 0xFFFF;
                    var packet = writePacket(config.ssrc(), ulpfec.redPayloadType(), seq, timestamp, false, Map.of(),
                            red, ridId);
                    out.add(new RtpSession.Outgoing(packet, OutgoingPacketScheduler.Priority.FEC, config.ssrc(),
                            RtpSession.PacketKind.FEC, this));
                }
                case FecConfig.Flexfec flexfec -> {
                    var seq = flexfecSequence;
                    flexfecSequence = (flexfecSequence + 1) & 0xFFFF;
                    var packet = writePacket(flexfec.ssrc(), flexfec.payloadType(), seq, timestamp, false, Map.of(),
                            fecPayload, OptionalInt.empty());
                    out.add(new RtpSession.Outgoing(packet, OutgoingPacketScheduler.Priority.FEC, flexfec.ssrc(),
                            RtpSession.PacketKind.FEC, this));
                }
            }
        }
    }

    /// Writes a packet with the session's reserved extensions into a new buffer with SRTP tailroom.
    private ByteBuffer writePacket(long ssrc, int payloadType, int seq, long timestamp, boolean marker,
                                   Map<URI, ByteBuffer> values, ByteBuffer payload, OptionalInt ridSlot) {
        var extensions = new ArrayList<Map.Entry<Integer, ByteBuffer>>(6);
        midId.ifPresent(id -> extensions.add(Map.entry(id, new Mid(config.mid()).encode())));
        if (ridSlot.isPresent()) {
            extensions.add(Map.entry(ridSlot.getAsInt(), (ridSlot.equals(ridId)
                    ? new RtpStreamId(config.rid().orElseThrow()).encode()
                    : new RepairedRtpStreamId(config.rid().orElseThrow()).encode())));
        }
        transportSequenceId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(2))));
        absSendTimeId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(3))));
        for (var entry : values.entrySet()) {
            var id = config.extensions().idOf(entry.getKey());
            if (id.isPresent() && extensions.stream().noneMatch(e -> e.getKey() == id.getAsInt())) {
                extensions.add(Map.entry(id.getAsInt(), entry.getValue()));
            }
        }
        return write(ssrc, payloadType, seq, timestamp, marker, List.of(), extensions, payload, 0);
    }

    private ByteBuffer write(long ssrc, int payloadType, int seq, long timestamp, boolean marker, List<Long> csrcs,
                             List<Map.Entry<Integer, ByteBuffer>> extensions, ByteBuffer payload, int padding) {
        var extensionBytes = 0;
        for (var entry : extensions) {
            extensionBytes += 2 + entry.getValue().remaining();
        }
        var capacity = RtpPacket.FIXED_HEADER_LENGTH + 4 * csrcs.size() + 4 + extensionBytes + 3
                + payload.remaining() + padding + session.tailroom();
        var writer = RtpPacketWriter.into(ByteBuffer.allocate(capacity)).ssrc(ssrc).payloadType(payloadType)
                .sequence(seq).timestamp(timestamp).marker(marker).csrcs(csrcs).payload(payload).padding(padding);
        for (var entry : extensions) {
            writer.extension(entry.getKey(), entry.getValue());
        }
        return writer.finish();
    }

    private static RtpPacket view(ByteBuffer packet) {
        try {
            return RtpPacket.parse(packet);
        } catch (RtpFormatException exception) {
            throw new IllegalStateException("the writer produced an unparsable packet", exception);
        }
    }

    /// Sets the listener told of PLI and FIR requests from the peer; a FIR retransmitted with an unchanged command
    /// sequence number is reported once.
    ///
    /// @param listener the listener, called on the transport's RTCP reader thread
    public void setKeyframeRequestListener(Consumer<KeyframeRequest> listener) {
        this.keyframeListener = Objects.requireNonNull(listener, "listener cannot be null");
    }

    /// {@return a snapshot of the stream's counters}
    public SendStreamStatistics statistics() {
        var lock = session.lock();
        lock.lock();
        try {
            Optional<SendStreamStatistics.RemoteReception> remote = Optional.empty();
            if (lastReport != null) {
                var jitter = Duration.ofNanos(lastReport.jitter() * 1_000_000_000L / config.clockRate());
                remote = Optional.of(new SendStreamStatistics.RemoteReception(lastReport.fractionLost(),
                        lastReport.cumulativeLost(), lastReport.extendedHighestSequence(), jitter,
                        lastRttNanos < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(lastRttNanos)),
                        Duration.ofNanos(totalRttNanos), rttMeasurements, reportsReceived));
            }
            return new SendStreamStatistics(config.ssrc(), config.rtxSsrc(), config.rid(), packetsSent, bytesSent,
                    headerBytesSent, retransmittedPacketsSent, retransmittedBytesSent, fecPacketsSent,
                    paddingPacketsSent, nackCount, pliCount, firCount, remote);
        } finally {
            lock.unlock();
        }
    }

    long ssrc() {
        return config.ssrc();
    }

    boolean ownsSsrc(long ssrc) {
        return ssrc == config.ssrc() || (config.rtxSsrc().isPresent() && config.rtxSsrc().getAsLong() == ssrc)
                || config.fec().filter(fec -> fec instanceof FecConfig.Flexfec flexfec && flexfec.ssrc() == ssrc)
                .isPresent();
    }

    OptionalInt transportSequenceId() {
        return transportSequenceId;
    }

    OptionalInt absSendTimeId() {
        return absSendTimeId;
    }

    /// Called under the session lock once a packet actually left.
    void onSent(RtpSession.PacketKind kind, int payloadBytes, int headerBytes, long nowNanos) {
        lastSentNanos = nowNanos;
        switch (kind) {
            case MEDIA -> {
                packetsSent++;
                bytesSent += payloadBytes;
                headerBytesSent += headerBytes;
            }
            case RETRANSMISSION -> {
                retransmittedPacketsSent++;
                retransmittedBytesSent += payloadBytes;
            }
            case FEC -> fecPacketsSent++;
            case PADDING -> paddingPacketsSent++;
        }
    }

    /// {@return whether the stream sent media since `sinceNanos`}
    boolean sentSince(long sinceNanos) {
        return lastSentNanos != Long.MIN_VALUE && lastSentNanos >= sinceNanos;
    }

    /// Builds the sender report of the stream, or empty before its first packet. Called under the session lock.
    Optional<SenderReport> senderReport(long ntp, long nowNanos, List<ReceptionReport> blocks) {
        if (lastCaptureNanos == Long.MIN_VALUE) {
            return Optional.empty();
        }
        var elapsed = nowNanos - lastCaptureNanos;
        var ticks = (elapsed / 1_000_000_000L) * config.clockRate()
                + (elapsed % 1_000_000_000L) * config.clockRate() / 1_000_000_000L;
        var rtp = (lastRtpTimestamp + ticks) & 0xFFFFFFFFL;
        return Optional.of(new SenderReport(config.ssrc(), ntp, rtp, packetsSent & 0xFFFFFFFFL,
                bytesSent & 0xFFFFFFFFL, blocks));
    }

    /// Serves a NACK from the history. Called under the session lock.
    void onNack(Nack nack, long nowNanos, long rttNanos, List<RtpSession.Outgoing> out) {
        nackCount++;
        if (history == null) {
            return;
        }
        var minimumInterval = Math.max(rttNanos < 0 ? 0 : rttNanos, 5_000_000L);
        for (var seq : nack.sequences()) {
            var found = history.find(seq, nowNanos);
            if (found.isEmpty()) {
                continue;
            }
            var entry = found.get();
            if (entry.lastResentNanos != Long.MIN_VALUE && nowNanos - entry.lastResentNanos < minimumInterval) {
                continue;
            }
            entry.lastResentNanos = nowNanos;
            entry.resends++;
            out.add(retransmission(entry.packet, OutgoingPacketScheduler.Priority.RETRANSMISSION,
                    RtpSession.PacketKind.RETRANSMISSION));
        }
    }

    private RtpSession.Outgoing retransmission(RtpPacket original, OutgoingPacketScheduler.Priority priority,
                                               RtpSession.PacketKind kind) {
        if (config.rtxSsrc().isEmpty()) {
            var copy = ByteBuffer.allocate(original.length() + session.tailroom());
            copy.put(original.buffer()).flip();
            return new RtpSession.Outgoing(copy, priority, config.ssrc(), kind, this);
        }
        var extensions = new ArrayList<Map.Entry<Integer, ByteBuffer>>();
        for (var id : original.extensionIds()) {
            var value = original.extension(id).orElseThrow();
            if (ridId.isPresent() && id == ridId.getAsInt()) {
                repairedRidId.ifPresent(rrid -> extensions.add(Map.entry(rrid,
                        new RepairedRtpStreamId(config.rid().orElseThrow()).encode())));
            } else if (transportSequenceId.isPresent() && id == transportSequenceId.getAsInt()) {
                extensions.add(Map.entry(id, ByteBuffer.allocate(2)));
            } else if (absSendTimeId.isPresent() && id == absSendTimeId.getAsInt()) {
                extensions.add(Map.entry(id, ByteBuffer.allocate(3)));
            } else {
                extensions.add(Map.entry(id, value));
            }
        }
        var seq = rtxSequence;
        rtxSequence = (rtxSequence + 1) & 0xFFFF;
        var packet = write(config.rtxSsrc().getAsLong(), config.rtxPayloadType().getAsInt(), seq,
                original.timestamp(), original.marker(), original.csrcs(), extensions, Rtx.payloadOf(original), 0);
        return new RtpSession.Outgoing(packet, priority, config.rtxSsrc().getAsLong(), kind, this);
    }

    /// Builds padding for a probe: RTX copies of the newest packets when RTX and history are available, otherwise
    /// padding-only packets. Called under the session lock.
    int padding(int targetBytes, List<RtpSession.Outgoing> out) {
        var produced = 0;
        if (config.rtxSsrc().isPresent() && history != null && history.size() > 0) {
            for (var entry : history.newest(64)) {
                if (produced >= targetBytes) {
                    break;
                }
                var packet = retransmission(entry.packet, OutgoingPacketScheduler.Priority.PADDING,
                        RtpSession.PacketKind.PADDING);
                produced += packet.buffer().remaining();
                out.add(packet);
            }
            if (produced > 0) {
                return produced;
            }
        }
        while (produced < targetBytes) {
            long ssrc;
            int payloadType;
            int seq;
            if (config.rtxSsrc().isPresent()) {
                ssrc = config.rtxSsrc().getAsLong();
                payloadType = config.rtxPayloadType().getAsInt();
                seq = rtxSequence;
                rtxSequence = (rtxSequence + 1) & 0xFFFF;
            } else {
                ssrc = config.ssrc();
                payloadType = config.payloadType();
                seq = sequence;
                sequence = (sequence + 1) & 0xFFFF;
            }
            var extensions = new ArrayList<Map.Entry<Integer, ByteBuffer>>(3);
            midId.ifPresent(id -> extensions.add(Map.entry(id, new Mid(config.mid()).encode())));
            transportSequenceId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(2))));
            absSendTimeId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(3))));
            var packet = write(ssrc, payloadType, seq, lastRtpTimestamp, false, List.of(), extensions,
                    ByteBuffer.allocate(0), MAX_PADDING);
            produced += packet.remaining();
            out.add(new RtpSession.Outgoing(packet, OutgoingPacketScheduler.Priority.PADDING, ssrc,
                    RtpSession.PacketKind.PADDING, this));
        }
        return produced;
    }

    /// Records a PLI or a FIR entry for this stream. Called under the session lock.
    Optional<KeyframeRequest> onKeyframeRequest(KeyframeMethod method, long requesterSsrc, int firSequence,
                                                long nowNanos) {
        if (method == KeyframeMethod.FIR) {
            var previous = lastFirSequence.put(requesterSsrc, firSequence);
            if (previous != null && previous == firSequence) {
                return Optional.empty();
            }
            firCount++;
        } else {
            pliCount++;
        }
        return Optional.of(new KeyframeRequest(method, config.ssrc(), requesterSsrc, nowNanos));
    }

    Consumer<KeyframeRequest> keyframeListener() {
        return keyframeListener;
    }

    /// Records a reception report about this stream. Called under the session lock.
    void onReceptionReport(ReceptionReport report, long rttNanos) {
        lastReport = report;
        reportsReceived++;
        if (rttNanos >= 0) {
            lastRttNanos = rttNanos;
            totalRttNanos += rttNanos;
            rttMeasurements++;
        }
    }

    @Override
    public String toString() {
        return "RtpSendStream[mid=" + config.mid() + config.rid().map(rid -> ", rid=" + rid).orElse("") + ", ssrc="
                + config.ssrc() + "]";
    }
}
