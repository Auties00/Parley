package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.SequenceNumbers;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.RtpPacketWriter;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.rtp.extension.Mid;
import com.github.auties00.parley.rtp.extension.RepairedRtpStreamId;
import com.github.auties00.parley.rtp.extension.RtpStreamId;
import com.github.auties00.parley.rtp.fec.FecEncoder;
import com.github.auties00.parley.rtp.fec.FecFormat;
import com.github.auties00.parley.rtp.fec.FecMaskType;
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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.function.Consumer;

/// One outgoing RTP stream of a session: a sequence number space, an SSRC, its retransmission history and its
/// repair streams (RTX, RED, ULPFEC or FlexFEC), as negotiated in its [SendStreamConfig].
///
/// [#send(List, long, OutgoingPacketScheduler.Priority)] turns already packetized payloads into RTP packets: it
/// assigns sequence numbers, writes the MID, RID and caller-supplied header extensions, reserves the transport-wide
/// sequence number and absolute send time the session stamps at send time, wraps them in RED when configured, stores
/// them for retransmission, generates FEC at the end of each frame, and hands everything to the session's
/// [OutgoingPacketScheduler]. [#forward(RtpPacket, int, Map, boolean, long)] does the same for packets an SFU
/// forwards without decoding them.
///
/// NACKs from the peer are served from the history without involving the application: as RTX when negotiated, as
/// FlexFEC retransmissions when that scheme was chosen, otherwise by resending the original packet; a packet already
/// resent within the last round trip is not resent again. PLI and FIR requests reach the configuration's
/// [SendStreamConfig#keyframeRequestListener()].
///
/// # Lifecycle
///
/// [RtpSession#removeSendStream(RtpSendStream)] removes the stream under the session's lock; from then on every send
/// is dropped (and counted in [#droppedPackets()]), so no packet follows the BYE that announced its departure. An
/// SSRC collision (RFC 3550 section 8.2) or [#changeSsrc(long)] moves the stream to a new SSRC: the old one is
/// announced in a BYE, the counters the sender reports restart, and the history is cleared.
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
/// @spec https://www.rfc-editor.org/rfc/rfc7667.html RFC 7667: RTP Topologies
public final class RtpSendStream {
    /// The most padding bytes one padding-only packet carries.
    static final int MAX_PADDING = 255;

    /// The window the frame rate is measured over.
    static final long FRAME_RATE_WINDOW_NANOS = 1_000_000_000L;

    /// The requesters whose last FIR sequence number is remembered; the SSRCs are the peer's to choose.
    static final int MAX_FIR_REQUESTERS = 64;

    /// The mean run length of NACKed sequence numbers above which losses count as bursty.
    static final double BURSTY_RUN_LENGTH = 1.5;

    /// The clock rate of video payload types, whose forwarded packets are paced as video.
    private static final int VIDEO_CLOCK_RATE = 90_000;

    private final RtpSession session;
    private volatile SendStreamConfig config;
    private final OptionalInt midId;
    private final OptionalInt ridId;
    private final OptionalInt repairedRidId;
    private final OptionalInt transportSequenceId;
    private final OptionalInt absSendTimeId;
    private final PacketHistory history;
    private final RedEncoder redEncoder;
    private FecEncoder fecEncoder;
    private int sequence;
    private int rtxSequence;
    private int flexfecSequence;
    private long lastRtpTimestamp;
    private long lastCaptureNanos = Long.MIN_VALUE;
    private long lastSentNanos = Long.MIN_VALUE;
    private boolean removed;
    private final Map<Long, Integer> lastFirSequence = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, Integer> eldest) {
            return size() > MAX_FIR_REQUESTERS;
        }
    };
    private volatile Consumer<? super KeyframeRequest> keyframeListener;
    private RtpStreamRewriter rewriter;
    private boolean forwardingKeyFrame;
    private double nackRunLength = 1;

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
    private long droppedPackets;
    private long framesSent;
    private long keyFramesSent;
    private OptionalInt frameWidth = OptionalInt.empty();
    private OptionalInt frameHeight = OptionalInt.empty();
    private final ArrayDeque<Long> frameTimes = new ArrayDeque<>();
    private long firstFrameNanos = Long.MIN_VALUE;
    private long totalPacketSendDelayNanos;
    private ReceptionReport lastReport;
    private long reportsReceived;
    private long lastRttNanos = -1;
    private long totalRttNanos;
    private long rttMeasurements;

    RtpSendStream(RtpSession session, SendStreamConfig config, int initialSequence) {
        this.session = session;
        this.config = config;
        this.keyframeListener = config.keyframeRequestListener();
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
        this.fecEncoder = createFecEncoder(config);
        this.sequence = initialSequence & 0xFFFF;
        this.rtxSequence = (initialSequence * 7 + 1) & 0xFFFF;
        this.flexfecSequence = (initialSequence * 13 + 3) & 0xFFFF;
    }

    private static FecEncoder createFecEncoder(SendStreamConfig config) {
        return config.fec().map(fec -> switch (fec) {
            case FecConfig.Ulpfec ulpfec -> FecEncoder.create(FecFormat.ULPFEC, config.ssrc(),
                    ulpfec.protectionPercent());
            case FecConfig.Flexfec flexfec -> switch (flexfec.scheme()) {
                case FecConfig.FlexfecScheme.Mask _ -> FecEncoder.create(flexfec.draft03() ? FecFormat.FLEXFEC_03
                        : FecFormat.FLEXFEC, config.ssrc(), flexfec.protectionPercent());
                case FecConfig.FlexfecScheme.RowColumn(var columns, var rows, var rowParity) ->
                        FecEncoder.rowColumn(config.ssrc(), columns, rows, rowParity);
                case FecConfig.FlexfecScheme.Retransmission _ ->
                        FecEncoder.retransmission(config.ssrc(), flexfec.protectionPercent());
            };
        }).orElse(null);
    }

    /// One payload to send, with its own marker bit and header extension values.
    ///
    /// @param payload    the payload; its bytes are copied
    /// @param marker     the marker bit
    /// @param extensions header extension values by URI; values whose URI was not negotiated are not written
    public record Payload(ByteBuffer payload, boolean marker, Map<URI, ByteBuffer> extensions) {
        /// Checks the fields and copies `extensions`.
        public Payload {
            Objects.requireNonNull(payload, "payload cannot be null");
            extensions = Map.copyOf(extensions);
        }
    }

    /// What the send statistics record of a frame: whether it is a key frame, and its picture size when the encoder
    /// knows it.
    ///
    /// @param keyFrame whether the frame is a key frame
    /// @param width    the picture width in pixels, if known
    /// @param height   the picture height in pixels, if known
    public record FrameInfo(boolean keyFrame, OptionalInt width, OptionalInt height) {
        /// A delta frame of unknown size.
        public static final FrameInfo DELTA = new FrameInfo(false, OptionalInt.empty(), OptionalInt.empty());

        /// Checks the fields.
        ///
        /// @throws IllegalArgumentException if a dimension is not positive
        public FrameInfo {
            Objects.requireNonNull(width, "width cannot be null");
            Objects.requireNonNull(height, "height cannot be null");
            if (width.isPresent() && width.getAsInt() <= 0 || height.isPresent() && height.getAsInt() <= 0) {
                throw new IllegalArgumentException("dimensions must be positive");
            }
        }

        /// {@return a key frame of a known size}
        ///
        /// @param width  the width in pixels
        /// @param height the height in pixels
        public static FrameInfo keyFrame(int width, int height) {
            return new FrameInfo(true, OptionalInt.of(width), OptionalInt.of(height));
        }
    }

    /// {@return the configuration, with the SSRCs the stream uses now}
    public SendStreamConfig config() {
        return config;
    }

    /// Sends payloads that carry their own marker bits and header extension values, as a packetizer produces them,
    /// counted as one delta frame of unknown size.
    ///
    /// FEC is generated after a payload whose marker bit is set, the end of a frame. After the stream was removed
    /// the payloads are dropped.
    ///
    /// @param payloads     the payloads, in order, at least one
    /// @param rtpTimestamp the RTP timestamp, an unsigned 32-bit value
    /// @param priority     the scheduling priority
    /// @throws IOException              if the scheduler sends at once and the transport fails
    /// @throws IllegalArgumentException if `payloads` is empty or `rtpTimestamp` is out of range
    /// @throws IllegalStateException    if the session is closed
    public void send(List<Payload> payloads, long rtpTimestamp, OutgoingPacketScheduler.Priority priority)
            throws IOException {
        send(payloads, rtpTimestamp, priority, FrameInfo.DELTA);
    }

    /// Sends the payloads of one frame, recording it in the frame counters of the statistics.
    ///
    /// FEC is generated after a payload whose marker bit is set, the end of a frame. After the stream was removed
    /// the payloads are dropped.
    ///
    /// @param payloads     the payloads, in order, at least one
    /// @param rtpTimestamp the RTP timestamp, an unsigned 32-bit value
    /// @param priority     the scheduling priority
    /// @param frame        what the statistics record of the frame
    /// @throws IOException              if the scheduler sends at once and the transport fails
    /// @throws IllegalArgumentException if `payloads` is empty or `rtpTimestamp` is out of range
    /// @throws IllegalStateException    if the session is closed
    public void send(List<Payload> payloads, long rtpTimestamp, OutgoingPacketScheduler.Priority priority,
                     FrameInfo frame) throws IOException {
        Objects.requireNonNull(payloads, "payloads cannot be null");
        Objects.requireNonNull(priority, "priority cannot be null");
        Objects.requireNonNull(frame, "frame cannot be null");
        if (payloads.isEmpty()) {
            throw new IllegalArgumentException("payloads cannot be empty");
        }
        checkTimestamp(rtpTimestamp);
        var outgoing = new ArrayList<RtpSession.Outgoing>(payloads.size() + 2);
        var lock = session.lock();
        lock.lock();
        try {
            session.checkOpen();
            if (removed) {
                droppedPackets += payloads.size();
                return;
            }
            var now = session.now();
            lastRtpTimestamp = rtpTimestamp;
            lastCaptureNanos = now;
            for (var payload : payloads) {
                buildMedia(payload, rtpTimestamp, priority, now, outgoing);
                if (payload.marker() && fecEncoder != null) {
                    buildFec(rtpTimestamp, now, outgoing);
                }
            }
            onFrame(frame, now);
        } finally {
            lock.unlock();
        }
        session.dispatch(outgoing);
    }

    /// Sends payloads of another payload type on this stream's source and sequence space, without RED, FEC or the
    /// sender report clock update, as RFC 4733 telephone events need: they share the audio source and its sequence
    /// numbers but have their own payload type and timestamps. After the stream was removed the payloads are
    /// dropped.
    ///
    /// @param payloadType  the payload type of the packets, `0..127`
    /// @param payloads     the payloads, in order, at least one
    /// @param rtpTimestamp the RTP timestamp, an unsigned 32-bit value
    /// @param priority     the scheduling priority
    /// @throws IOException              if the scheduler sends at once and the transport fails
    /// @throws IllegalArgumentException if `payloads` is empty or a value is out of range
    /// @throws IllegalStateException    if the session is closed
    /// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
    public void sendWithPayloadType(int payloadType, List<Payload> payloads, long rtpTimestamp,
                                    OutgoingPacketScheduler.Priority priority) throws IOException {
        Objects.requireNonNull(payloads, "payloads cannot be null");
        Objects.requireNonNull(priority, "priority cannot be null");
        if (payloads.isEmpty()) {
            throw new IllegalArgumentException("payloads cannot be empty");
        }
        SessionChecks.payloadType(payloadType, "payloadType");
        checkTimestamp(rtpTimestamp);
        var outgoing = new ArrayList<RtpSession.Outgoing>(payloads.size());
        var lock = session.lock();
        lock.lock();
        try {
            session.checkOpen();
            if (removed) {
                droppedPackets += payloads.size();
                return;
            }
            var now = session.now();
            var ssrc = config.ssrc();
            for (var payload : payloads) {
                var seq = sequence;
                sequence = (sequence + 1) & 0xFFFF;
                var packet = writePacket(ssrc, payloadType, seq, rtpTimestamp, payload.marker(),
                        payload.extensions(), List.of(), payload.payload(), ridId);
                if (history != null) {
                    history.store(view(packet).copy(), now, priority);
                }
                outgoing.add(new RtpSession.Outgoing(packet, priority, ssrc, RtpSession.PacketKind.MEDIA, this, now));
            }
        } finally {
            lock.unlock();
        }
        session.dispatch(outgoing);
    }

    /// Sends a packet an SFU forwards from another stream, without decoding it.
    ///
    /// The packet's payload, marker bit and CSRCs are sent unchanged; everything else is this stream's: its SSRC,
    /// its MID and RID, `extensions` written with this stream's negotiated ids (values whose URI was not negotiated
    /// are not written), and the transport-wide sequence number and absolute send time stamped at send time. The
    /// sequence numbers and timestamps continue this stream's own spaces: gaps from loss upstream are kept, so the
    /// receiver NACKs them, and a switch to another source (another simulcast layer, another publisher) neither
    /// jumps nor rewinds them. A packet of a new source starts the switch; the switch takes effect at the first
    /// packet of that source with `switchPoint` set (the first packet of a key frame), and until then the packets
    /// of the old source keep flowing and the new source's are dropped. Forwarded packets are stored for
    /// retransmission, served to NACKs as RTX when negotiated, paced as video at the 90 kHz video clock rate and as
    /// audio otherwise, and counted in the statistics (a frame at each marker bit, a key frame when it started with
    /// `switchPoint`).
    ///
    /// @param packet       the packet as received from its source; its bytes are copied
    /// @param payloadType  the payload type this stream negotiated for the packet's codec, `0..127`
    /// @param extensions   the header extension values to write, by URI
    /// @param switchPoint  whether a decoder can start at the packet
    /// @param arrivalNanos when the packet arrived, on the session's clock; it times source switches
    /// @throws IOException              if the scheduler sends at once and the transport fails
    /// @throws IllegalArgumentException if `payloadType` is out of range
    /// @throws IllegalStateException    if the session is closed
    /// @spec https://www.rfc-editor.org/rfc/rfc7667.html RFC 7667: RTP Topologies
    public void forward(RtpPacket packet, int payloadType, Map<URI, ByteBuffer> extensions, boolean switchPoint,
                        long arrivalNanos) throws IOException {
        Objects.requireNonNull(packet, "packet cannot be null");
        Objects.requireNonNull(extensions, "extensions cannot be null");
        SessionChecks.payloadType(payloadType, "payloadType");
        var outgoing = new ArrayList<RtpSession.Outgoing>(1);
        var lock = session.lock();
        lock.lock();
        try {
            session.checkOpen();
            if (removed) {
                droppedPackets++;
                return;
            }
            if (rewriter == null) {
                rewriter = RtpStreamRewriter.create(config.ssrc(), config.clockRate());
                rewriter.startAt(sequence, lastRtpTimestamp);
            }
            var active = rewriter.activeSource();
            if (active.isEmpty() || active.getAsLong() != packet.ssrc()) {
                rewriter.switchTo(packet.ssrc());
            }
            var mapped = rewriter.map(packet, switchPoint, arrivalNanos);
            if (mapped.isEmpty()) {
                droppedPackets++;
                return;
            }
            var seq = mapped.get().sequence();
            var timestamp = mapped.get().timestamp();
            if (SequenceNumbers.isNewer(seq, (sequence - 1) & 0xFFFF)) {
                sequence = (seq + 1) & 0xFFFF;
            }
            var now = session.now();
            lastRtpTimestamp = timestamp;
            lastCaptureNanos = now;
            // TODO: protect forwarded packets with RED and FEC when configured; they are sent without repair.
            var priority = config.clockRate() == VIDEO_CLOCK_RATE ? OutgoingPacketScheduler.Priority.VIDEO
                    : OutgoingPacketScheduler.Priority.AUDIO;
            var ssrc = config.ssrc();
            var built = writePacket(ssrc, payloadType, seq, timestamp, packet.marker(), extensions, packet.csrcs(),
                    packet.payload(), ridId);
            if (history != null) {
                history.store(view(built).copy(), now, priority);
            }
            outgoing.add(new RtpSession.Outgoing(built, priority, ssrc, RtpSession.PacketKind.MEDIA, this, now));
            if (switchPoint) {
                forwardingKeyFrame = true;
            }
            if (packet.marker()) {
                onFrame(forwardingKeyFrame ? new FrameInfo(true, OptionalInt.empty(), OptionalInt.empty())
                        : FrameInfo.DELTA, now);
                forwardingKeyFrame = false;
            }
        } finally {
            lock.unlock();
        }
        session.dispatch(outgoing);
    }

    /// Moves the stream to a new media SSRC, as after an SSRC collision: the old SSRC is announced in an RTCP BYE
    /// (with a receiver report and the CNAME, RFC 3550 section 8.2), the counters the sender reports restart, the
    /// history is cleared, and the session's SSRC change listener is told.
    ///
    /// @param newSsrc the new SSRC, an unsigned 32-bit value no local stream uses
    /// @throws IOException              if sending the BYE fails; the change is made anyway
    /// @throws IllegalArgumentException if `newSsrc` is out of range or used by a local stream
    /// @throws IllegalStateException    if the session is closed or the stream was removed
    /// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
    public void changeSsrc(long newSsrc) throws IOException {
        SessionChecks.ssrc(newSsrc, "newSsrc");
        session.changeSsrc(this, config.ssrc(), newSsrc);
    }

    /// Replaces one of the stream's SSRCs. Called under the session lock.
    void replaceSsrc(long oldSsrc, long newSsrc) {
        var previous = config;
        config = previous.withReplacedSsrc(oldSsrc, newSsrc);
        if (previous.ssrc() == oldSsrc) {
            packetsSent = 0;
            bytesSent = 0;
            headerBytesSent = 0;
            lastReport = null;
            if (history != null) {
                history.clear();
            }
            if (fecEncoder != null) {
                fecEncoder = createFecEncoder(config);
            }
            rewriter = null;
        }
    }

    private static void checkTimestamp(long rtpTimestamp) {
        if (rtpTimestamp < 0 || rtpTimestamp > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("rtpTimestamp must be an unsigned 32-bit value: " + rtpTimestamp);
        }
    }

    /// Records a frame in the counters. Called under the session lock.
    private void onFrame(FrameInfo frame, long nowNanos) {
        framesSent++;
        if (frame.keyFrame()) {
            keyFramesSent++;
        }
        if (frame.width().isPresent() && frame.height().isPresent()) {
            frameWidth = frame.width();
            frameHeight = frame.height();
        }
        if (firstFrameNanos == Long.MIN_VALUE) {
            firstFrameNanos = nowNanos;
        }
        frameTimes.addLast(nowNanos);
        while (!frameTimes.isEmpty() && nowNanos - frameTimes.peekFirst() >= FRAME_RATE_WINDOW_NANOS) {
            frameTimes.pollFirst();
        }
    }

    private void buildMedia(Payload payload, long timestamp, OutgoingPacketScheduler.Priority priority, long now,
                            List<RtpSession.Outgoing> out) {
        var mediaPayload = payload.payload();
        var payloadType = config.payloadType();
        var ssrc = config.ssrc();
        if (redEncoder != null) {
            mediaPayload = redEncoder.encode(payloadType, timestamp, mediaPayload);
            payloadType = config.red().orElseThrow().payloadType();
        }
        var seq = sequence;
        sequence = (sequence + 1) & 0xFFFF;
        var media = writePacket(ssrc, payloadType, seq, timestamp, payload.marker(), payload.extensions(), List.of(),
                mediaPayload, ridId);
        var sent = media;
        if (fecEncoder != null) {
            fecEncoder.add(view(media));
            if (config.fec().orElseThrow() instanceof FecConfig.Ulpfec ulpfec) {
                var red = Red.encode(List.of(), payloadType, mediaPayload);
                sent = writePacket(ssrc, ulpfec.redPayloadType(), seq, timestamp, payload.marker(),
                        payload.extensions(), List.of(), red, ridId);
            }
        }
        if (history != null) {
            history.store(view(sent).copy(), now, priority);
        }
        out.add(new RtpSession.Outgoing(sent, priority, ssrc, RtpSession.PacketKind.MEDIA, this, now));
    }

    private void buildFec(long timestamp, long now, List<RtpSession.Outgoing> out) {
        for (var fecPayload : fecEncoder.flush()) {
            switch (config.fec().orElseThrow()) {
                case FecConfig.Ulpfec ulpfec -> {
                    var red = Red.encode(List.of(), ulpfec.ulpfecPayloadType(), fecPayload);
                    var seq = sequence;
                    sequence = (sequence + 1) & 0xFFFF;
                    var packet = writePacket(config.ssrc(), ulpfec.redPayloadType(), seq, timestamp, false, Map.of(),
                            List.of(), red, ridId);
                    out.add(new RtpSession.Outgoing(packet, OutgoingPacketScheduler.Priority.FEC, config.ssrc(),
                            RtpSession.PacketKind.FEC, this, now));
                }
                case FecConfig.Flexfec flexfec -> out.add(flexfecPacket(flexfec, fecPayload, timestamp,
                        OutgoingPacketScheduler.Priority.FEC, RtpSession.PacketKind.FEC, now));
            }
        }
    }

    /// Wraps a FlexFEC repair payload in a packet of the FlexFEC stream; an RFC 8627 packet lists the protected
    /// SSRC as its CSRC.
    private RtpSession.Outgoing flexfecPacket(FecConfig.Flexfec flexfec, ByteBuffer payload, long timestamp,
                                              OutgoingPacketScheduler.Priority priority, RtpSession.PacketKind kind,
                                              long now) {
        var seq = flexfecSequence;
        flexfecSequence = (flexfecSequence + 1) & 0xFFFF;
        var csrcs = flexfec.draft03() ? List.<Long>of() : List.of(config.ssrc());
        var packet = writePacket(flexfec.ssrc(), flexfec.payloadType(), seq, timestamp, false, Map.of(), csrcs,
                payload, OptionalInt.empty());
        return new RtpSession.Outgoing(packet, priority, flexfec.ssrc(), kind, this, now);
    }

    /// Writes a packet with the session's reserved extensions into a new buffer with SRTP tailroom.
    private ByteBuffer writePacket(long ssrc, int payloadType, int seq, long timestamp, boolean marker,
                                   Map<URI, ByteBuffer> values, List<Long> csrcs, ByteBuffer payload,
                                   OptionalInt ridSlot) {
        var extensions = new ArrayList<Map.Entry<Integer, ByteBuffer>>(6);
        var current = config;
        midId.ifPresent(id -> extensions.add(Map.entry(id, new Mid(current.mid()).encode())));
        if (ridSlot.isPresent()) {
            extensions.add(Map.entry(ridSlot.getAsInt(), (ridSlot.equals(ridId)
                    ? new RtpStreamId(current.rid().orElseThrow()).encode()
                    : new RepairedRtpStreamId(current.rid().orElseThrow()).encode())));
        }
        transportSequenceId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(2))));
        absSendTimeId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(3))));
        for (var entry : values.entrySet()) {
            var id = current.extensions().idOf(entry.getKey());
            if (id.isPresent() && extensions.stream().noneMatch(e -> e.getKey() == id.getAsInt())) {
                extensions.add(Map.entry(id.getAsInt(), entry.getValue()));
            }
        }
        return write(ssrc, payloadType, seq, timestamp, marker, csrcs, extensions, payload, 0);
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

    /// Sets the listener told of PLI and FIR requests from the peer, replacing the configuration's.
    ///
    /// @param listener the listener, called on the transport's RTCP reader thread
    /// @deprecated give the listener to [SendStreamConfig.Builder#keyframeRequestListener(Consumer)]; a listener set
    /// after the stream was created misses the requests that arrived before
    @Deprecated(forRemoval = true)
    public void setKeyframeRequestListener(Consumer<KeyframeRequest> listener) {
        // TODO: remove once peer.TransportBackend passes the listener in its SendStreamConfig (cross-group).
        this.keyframeListener = Objects.requireNonNull(listener, "listener cannot be null");
    }

    /// {@return a snapshot of the stream's counters}
    public SendStreamStatistics statistics() {
        var lock = session.lock();
        lock.lock();
        try {
            var current = config;
            Optional<SendStreamStatistics.RemoteReception> remote = Optional.empty();
            if (lastReport != null) {
                var jitter = Duration.ofNanos(lastReport.jitter() * 1_000_000_000L / current.clockRate());
                remote = Optional.of(new SendStreamStatistics.RemoteReception(lastReport.fractionLost(),
                        lastReport.cumulativeLost(), lastReport.extendedHighestSequence(), jitter,
                        lastRttNanos < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(lastRttNanos)),
                        Duration.ofNanos(totalRttNanos), rttMeasurements, reportsReceived));
            }
            var now = session.now();
            while (!frameTimes.isEmpty() && now - frameTimes.peekFirst() >= FRAME_RATE_WINDOW_NANOS) {
                frameTimes.pollFirst();
            }
            var framesPerSecond = firstFrameNanos == Long.MIN_VALUE
                    || now - firstFrameNanos < FRAME_RATE_WINDOW_NANOS
                    ? OptionalDouble.empty()
                    : OptionalDouble.of(frameTimes.size() * 1e9 / FRAME_RATE_WINDOW_NANOS);
            return new SendStreamStatistics(current.ssrc(), current.rtxSsrc(), current.rid(), packetsSent, bytesSent,
                    headerBytesSent, retransmittedPacketsSent, retransmittedBytesSent, fecPacketsSent,
                    paddingPacketsSent, nackCount, pliCount, firCount, framesSent, keyFramesSent, frameWidth,
                    frameHeight, framesPerSecond, Duration.ofNanos(totalPacketSendDelayNanos), droppedPackets,
                    remote);
        } finally {
            lock.unlock();
        }
    }

    /// {@return the packets dropped because the stream was removed, or because a forwarded source was not switched
    /// to}
    public long droppedPackets() {
        var lock = session.lock();
        lock.lock();
        try {
            return droppedPackets;
        } finally {
            lock.unlock();
        }
    }

    long ssrc() {
        return config.ssrc();
    }

    /// {@return every SSRC the stream sends on: media, RTX and FlexFEC}
    List<Long> ssrcs() {
        var current = config;
        var out = new ArrayList<Long>(3);
        out.add(current.ssrc());
        current.rtxSsrc().ifPresent(out::add);
        current.fec().ifPresent(fec -> {
            if (fec instanceof FecConfig.Flexfec flexfec) {
                out.add(flexfec.ssrc());
            }
        });
        return out;
    }

    boolean ownsSsrc(long ssrc) {
        return ssrcs().contains(ssrc);
    }

    /// Marks the stream removed. Called under the session lock.
    void markRemoved() {
        removed = true;
    }

    boolean isRemoved() {
        return removed;
    }

    OptionalInt transportSequenceId() {
        return transportSequenceId;
    }

    OptionalInt absSendTimeId() {
        return absSendTimeId;
    }

    /// Called under the session lock once a packet actually left.
    void onSent(RtpSession.PacketKind kind, int payloadBytes, int headerBytes, long nowNanos, long queuedNanos) {
        lastSentNanos = nowNanos;
        switch (kind) {
            case MEDIA -> {
                packetsSent++;
                bytesSent += payloadBytes;
                headerBytesSent += headerBytes;
                totalPacketSendDelayNanos += Math.max(0, queuedNanos);
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
        var current = config;
        var elapsed = nowNanos - lastCaptureNanos;
        var ticks = (elapsed / 1_000_000_000L) * current.clockRate()
                + (elapsed % 1_000_000_000L) * current.clockRate() / 1_000_000_000L;
        var rtp = (lastRtpTimestamp + ticks) & 0xFFFFFFFFL;
        return Optional.of(new SenderReport(current.ssrc(), ntp, rtp, packetsSent & 0xFFFFFFFFL,
                bytesSent & 0xFFFFFFFFL, blocks));
    }

    /// Serves a NACK from the history and learns the loss pattern from it. Called under the session lock.
    void onNack(Nack nack, long nowNanos, long rttNanos, List<RtpSession.Outgoing> out) {
        nackCount++;
        learnLossPattern(nack.sequences());
        if (history == null || removed) {
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
                    RtpSession.PacketKind.RETRANSMISSION, nowNanos));
        }
    }

    /// Follows the mean run length of NACKed sequence numbers and switches the ULPFEC or FlexFEC masks to the
    /// burst-resilient kind when losses come in runs.
    private void learnLossPattern(List<Integer> sequences) {
        if (sequences.isEmpty()) {
            return;
        }
        var runs = 1;
        for (var i = 1; i < sequences.size(); i++) {
            if (((sequences.get(i) - sequences.get(i - 1)) & 0xFFFF) != 1) {
                runs++;
            }
        }
        var mean = (double) sequences.size() / runs;
        nackRunLength = 0.8 * nackRunLength + 0.2 * mean;
        if (fecEncoder != null) {
            fecEncoder.setMaskType(nackRunLength > BURSTY_RUN_LENGTH ? FecMaskType.BURSTY : FecMaskType.RANDOM);
        }
    }

    private RtpSession.Outgoing retransmission(RtpPacket original, OutgoingPacketScheduler.Priority priority,
                                               RtpSession.PacketKind kind, long now) {
        var current = config;
        if (current.rtxSsrc().isEmpty()) {
            if (current.fec().orElse(null) instanceof FecConfig.Flexfec flexfec
                    && flexfec.scheme() instanceof FecConfig.FlexfecScheme.Retransmission) {
                return flexfecPacket(flexfec, FecEncoder.retransmissionOf(original), original.timestamp(), priority,
                        kind, now);
            }
            var copy = ByteBuffer.allocate(original.length() + session.tailroom());
            copy.put(original.buffer()).flip();
            return new RtpSession.Outgoing(copy, priority, current.ssrc(), kind, this, now);
        }
        var extensions = new ArrayList<Map.Entry<Integer, ByteBuffer>>();
        for (var id : original.extensionIds()) {
            var value = original.extension(id).orElseThrow();
            if (ridId.isPresent() && id == ridId.getAsInt()) {
                repairedRidId.ifPresent(rrid -> extensions.add(Map.entry(rrid,
                        new RepairedRtpStreamId(current.rid().orElseThrow()).encode())));
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
        var packet = write(current.rtxSsrc().getAsLong(), current.rtxPayloadType().getAsInt(), seq,
                original.timestamp(), original.marker(), original.csrcs(), extensions, Rtx.payloadOf(original), 0);
        return new RtpSession.Outgoing(packet, priority, current.rtxSsrc().getAsLong(), kind, this, now);
    }

    /// Builds padding for a probe: RTX copies of the newest packets when RTX and history are available, otherwise
    /// padding-only packets. Called under the session lock.
    int padding(int targetBytes, List<RtpSession.Outgoing> out) {
        var produced = 0;
        var current = config;
        var now = session.now();
        if (current.rtxSsrc().isPresent() && history != null && history.size() > 0) {
            for (var entry : history.newest(64)) {
                if (produced >= targetBytes) {
                    break;
                }
                var packet = retransmission(entry.packet, OutgoingPacketScheduler.Priority.PADDING,
                        RtpSession.PacketKind.PADDING, now);
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
            if (current.rtxSsrc().isPresent()) {
                ssrc = current.rtxSsrc().getAsLong();
                payloadType = current.rtxPayloadType().getAsInt();
                seq = rtxSequence;
                rtxSequence = (rtxSequence + 1) & 0xFFFF;
            } else {
                ssrc = current.ssrc();
                payloadType = current.payloadType();
                seq = sequence;
                sequence = (sequence + 1) & 0xFFFF;
            }
            var extensions = new ArrayList<Map.Entry<Integer, ByteBuffer>>(3);
            midId.ifPresent(id -> extensions.add(Map.entry(id, new Mid(current.mid()).encode())));
            transportSequenceId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(2))));
            absSendTimeId.ifPresent(id -> extensions.add(Map.entry(id, ByteBuffer.allocate(3))));
            var packet = write(ssrc, payloadType, seq, lastRtpTimestamp, false, List.of(), extensions,
                    ByteBuffer.allocate(0), MAX_PADDING);
            produced += packet.remaining();
            out.add(new RtpSession.Outgoing(packet, OutgoingPacketScheduler.Priority.PADDING, ssrc,
                    RtpSession.PacketKind.PADDING, this, now));
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

    Consumer<? super KeyframeRequest> keyframeListener() {
        return keyframeListener;
    }

    int firRequesters() {
        return lastFirSequence.size();
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
        var current = config;
        return "RtpSendStream[mid=" + current.mid() + current.rid().map(rid -> ", rid=" + rid).orElse("") + ", ssrc="
                + current.ssrc() + "]";
    }
}
