package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.NtpTime;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.SequenceUnwrapper;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.rtp.fec.FecDecoder;
import com.github.auties00.parley.rtp.fec.FecFormat;
import com.github.auties00.parley.rtp.fec.Red;
import com.github.auties00.parley.rtp.fec.Rtx;
import com.github.auties00.parley.rtp.rtcp.FullIntraRequest;
import com.github.auties00.parley.rtp.rtcp.Nack;
import com.github.auties00.parley.rtp.rtcp.PictureLossIndication;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.SenderReport;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/// One incoming RTP stream of a session: the packets the session's demultiplexer routes to it, repaired and ordered
/// as its [ReceiveStreamConfig] negotiated.
///
/// The stream unwraps RTX, decodes RED, recovers lost packets from ULPFEC or FlexFEC, drops duplicates, keeps the
/// RFC 3550 reception statistics its receiver reports carry, sends NACKs for gaps (again after each round trip, up to
/// the retry limit) and falls back to a keyframe request when retransmission gives up. Its packet receiver sees
/// media packets in sequence order; a packet recovered after later ones were delivered is delivered late, and with a
/// non-zero reorder delay packets after a gap are held that long for the missing ones.
///
/// # Threading
///
/// Every method is thread-safe. The packet receiver is called on the transport's reader thread (or the session's
/// timer thread, for packets released by the reorder delay), one call at a time.
///
/// # Ownership
///
/// A packet handed to the receiver may be a view of the transport's receive buffer: it is valid only during the call,
/// and [RtpPacket#copy()] keeps it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc2198.html RFC 2198: RTP Payload for Redundant Audio Data
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
public final class RtpReceiveStream {
    /// The sequence numbers remembered as delivered, to drop duplicates.
    static final int DELIVERED_WINDOW = 2048;
    /// The most packets held by the reorder delay; more release the oldest gap.
    static final int MAX_HELD = 512;
    /// The shortest time between two keyframe requests the stream makes on its own.
    static final long KEYFRAME_REQUEST_INTERVAL_NANOS = 300_000_000L;

    private final RtpSession session;
    private final ReceiveStreamConfig config;
    private final OptionalInt transportSequenceId;
    private final OptionalInt absSendTimeId;
    private final ReentrantLock deliveryLock = new ReentrantLock();
    private volatile Consumer<RtpPacket> receiver = packet -> {
    };

    private long mediaSsrc;
    private long rtxSsrc;
    private final ReceptionStatistics statistics = new ReceptionStatistics();
    private final SequenceUnwrapper unwrapper = SequenceUnwrapper.forSequenceNumbers();
    private final NackTracker nack;
    private FecDecoder fecDecoder;
    private final long[] delivered = new long[DELIVERED_WINDOW];
    private long highestDelivered = Long.MIN_VALUE;
    private final TreeMap<Long, RtpPacket> held = new TreeMap<>();
    private long nextExpected = Long.MIN_VALUE;
    private long heldSinceNanos = Long.MIN_VALUE;
    private int firSequence;
    private long lastKeyframeRequestNanos = Long.MIN_VALUE;

    private NtpRtpMapping senderClock;
    private long lastSenderReport;
    private long lastSenderReportArrival;
    private SenderReport lastSr;
    private long senderReports;

    private long bytesReceived;
    private long headerBytesReceived;
    private long lastPacketNanos = Long.MIN_VALUE;
    private long duplicated;
    private long discarded;
    private long retransmittedPackets;
    private long retransmittedBytes;
    private long fecPackets;
    private long fecBytes;
    private long recovered;
    private long nackCount;
    private long pliCount;
    private long firCount;
    private long receiverRttNanos = -1;

    RtpReceiveStream(RtpSession session, ReceiveStreamConfig config) {
        this.session = session;
        this.config = config;
        this.transportSequenceId = config.extensions().idOf(HeaderExtensionUris.TRANSPORT_WIDE_CC);
        this.absSendTimeId = config.extensions().idOf(HeaderExtensionUris.ABS_SEND_TIME);
        this.mediaSsrc = config.ssrc().orElse(-1);
        this.rtxSsrc = config.rtxSsrc().orElse(-1);
        this.nack = config.feedback().contains(FeedbackMechanism.NACK) ? new NackTracker(config.nackMaxRetries())
                : null;
        if (mediaSsrc >= 0) {
            createFecDecoder();
        }
    }

    /// {@return the configuration}
    public ReceiveStreamConfig config() {
        return config;
    }

    /// Sets the receiver of the stream's media packets, replacing the previous one.
    ///
    /// @param receiver the receiver; see the class documentation for its thread and the lifetime of its argument
    public void setPacketReceiver(Consumer<RtpPacket> receiver) {
        this.receiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    /// Asks the sender for a keyframe now, whatever the stream's own keyframe requests.
    ///
    /// @param method whether to send a PLI or a FIR
    /// @throws IOException          if the transport fails
    /// @throws IllegalStateException if the media SSRC is neither signaled nor learned yet, or the session is closed
    public void requestKeyframe(KeyframeMethod method) throws IOException {
        Objects.requireNonNull(method, "method cannot be null");
        RtcpPacket packet;
        var lock = session.lock();
        lock.lock();
        try {
            session.checkOpen();
            packet = keyframeRequest(method, session.now()).orElseThrow(() ->
                    new IllegalStateException("the media SSRC is not known yet"));
        } finally {
            lock.unlock();
        }
        session.sendFeedbackNow(List.of(packet));
    }

    /// Asks the sender to retransmit packets now, whatever the stream's own NACKs.
    ///
    /// @param sequences the sequence numbers, `0..65535`, at least one
    /// @throws IOException             if the transport fails
    /// @throws IllegalArgumentException if `sequences` is empty or a number is out of range
    /// @throws IllegalStateException   if the media SSRC is neither signaled nor learned yet, or the session is closed
    public void requestRetransmission(List<Integer> sequences) throws IOException {
        Objects.requireNonNull(sequences, "sequences cannot be null");
        Nack packet;
        var lock = session.lock();
        lock.lock();
        try {
            session.checkOpen();
            if (mediaSsrc < 0) {
                throw new IllegalStateException("the media SSRC is not known yet");
            }
            packet = new Nack(session.feedbackSsrc(), mediaSsrc, sequences);
            nackCount++;
        } finally {
            lock.unlock();
        }
        session.sendFeedbackNow(List.of(packet));
    }

    /// {@return the mapping between the sender's wall clock and RTP timestamps from its last sender report}
    public Optional<NtpRtpMapping> senderClock() {
        var lock = session.lock();
        lock.lock();
        try {
            return Optional.ofNullable(senderClock);
        } finally {
            lock.unlock();
        }
    }

    /// {@return a snapshot of the stream's counters}
    public ReceiveStreamStatistics statistics() {
        var lock = session.lock();
        lock.lock();
        try {
            var clockRate = config.defaultClockRate();
            var jitter = Duration.ofNanos(statistics.jitter() * 1_000_000_000L / clockRate);
            Optional<ReceiveStreamStatistics.RemoteSender> remote = lastSr == null ? Optional.empty()
                    : Optional.of(new ReceiveStreamStatistics.RemoteSender(lastSr.packetCount(), lastSr.octetCount(),
                    NtpTime.toInstant(lastSr.ntpTimestamp()), senderReports));
            return new ReceiveStreamStatistics(mediaSsrc < 0 ? OptionalLong.empty() : OptionalLong.of(mediaSsrc),
                    rtxSsrc < 0 ? OptionalLong.empty() : OptionalLong.of(rtxSsrc), config.mid(), config.rid(),
                    statistics.received(), bytesReceived, headerBytesReceived, statistics.cumulativeLost(),
                    statistics.lastFractionLost(), jitter, duplicated, discarded, retransmittedPackets,
                    retransmittedBytes, fecPackets, fecBytes, fecSsrc(), recovered, nackCount, pliCount, firCount,
                    lastPacketNanos == Long.MIN_VALUE ? OptionalLong.empty() : OptionalLong.of(lastPacketNanos),
                    remote, receiverRttNanos < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(receiverRttNanos)));
        } finally {
            lock.unlock();
        }
    }

    long lastPacketNanos() {
        return lastPacketNanos;
    }

    /// {@return the FlexFEC SSRC, when FEC travels on its own SSRC}
    private OptionalLong fecSsrc() {
        return config.fec().filter(fec -> fec instanceof FecConfig.Flexfec)
                .map(fec -> OptionalLong.of(((FecConfig.Flexfec) fec).ssrc())).orElse(OptionalLong.empty());
    }

    OptionalLong mediaSsrc() {
        return mediaSsrc < 0 ? OptionalLong.empty() : OptionalLong.of(mediaSsrc);
    }

    boolean ownsSsrc(long ssrc) {
        return ssrc == mediaSsrc || ssrc == rtxSsrc || config.fec().filter(fec ->
                fec instanceof FecConfig.Flexfec flexfec && flexfec.ssrc() == ssrc).isPresent();
    }

    /// {@return the route the demultiplexer uses for this stream}
    RtpDemuxer.Route<RtpReceiveStream> route() {
        var ssrcs = new java.util.HashSet<Long>();
        config.ssrc().ifPresent(ssrcs::add);
        config.rtxSsrc().ifPresent(ssrcs::add);
        var payloadTypes = new java.util.HashSet<>(config.payloadTypes().keySet());
        payloadTypes.addAll(config.rtxPayloadTypes().keySet());
        config.redPayloadType().ifPresent(payloadTypes::add);
        config.fec().ifPresent(fec -> {
            switch (fec) {
                case FecConfig.Ulpfec ulpfec -> {
                    payloadTypes.add(ulpfec.redPayloadType());
                    payloadTypes.add(ulpfec.ulpfecPayloadType());
                }
                case FecConfig.Flexfec flexfec -> {
                    payloadTypes.add(flexfec.payloadType());
                    ssrcs.add(flexfec.ssrc());
                }
            }
        });
        return new RtpDemuxer.Route<>(this, config.mid(), config.rid(), ssrcs, payloadTypes);
    }

    private void createFecDecoder() {
        config.fec().ifPresent(fec -> fecDecoder = switch (fec) {
            case FecConfig.Ulpfec ignored -> new FecDecoder(FecFormat.ULPFEC, mediaSsrc);
            case FecConfig.Flexfec flexfec -> new FecDecoder(flexfec.draft03() ? FecFormat.FLEXFEC_03
                    : FecFormat.FLEXFEC, mediaSsrc);
        });
    }

    /// What receiving one packet, or one timer tick, produced: packets to deliver in order and feedback to send,
    /// both handled after the session lock is released.
    ///
    /// The common outcome, one in-order packet and no feedback, allocates no list: the first delivery is held in a
    /// field and the lists are created only when needed.
    static final class Work {
        /// The first packet to deliver, or `null`.
        private RtpPacket first;
        /// The packets to deliver after `first`, or `null` before a second one.
        private List<RtpPacket> rest;
        /// The feedback to send, or `null` before the first.
        private List<RtcpPacket> feedback;

        /// Adds a packet to deliver.
        void addDelivery(RtpPacket packet) {
            if (first == null) {
                first = packet;
            } else {
                if (rest == null) {
                    rest = new ArrayList<>(4);
                }
                rest.add(packet);
            }
        }

        /// Adds feedback to send.
        void addFeedback(RtcpPacket packet) {
            if (feedback == null) {
                feedback = new ArrayList<>(2);
            }
            feedback.add(packet);
        }

        /// {@return whether there is nothing to deliver and nothing to send}
        boolean isEmpty() {
            return first == null && feedback == null;
        }

        /// {@return the feedback to send, possibly empty}
        List<RtcpPacket> feedback() {
            return feedback == null ? List.of() : feedback;
        }

        /// {@return the number of packets to deliver}
        int deliveryCount() {
            return first == null ? 0 : 1 + (rest == null ? 0 : rest.size());
        }

        /// {@return the packet to deliver at `index`, in order}
        RtpPacket delivery(int index) {
            return index == 0 ? first : rest.get(index - 1);
        }
    }

    private enum Origin {
        NETWORK, RETRANSMISSION, RECOVERED
    }

    /// Processes a packet routed to the stream. Called under the session lock on the reader thread.
    void receive(RtpPacket packet, long arrivalNanos, Work work) {
        lastPacketNanos = arrivalNanos;
        var payloadType = packet.payloadType();
        var flexfec = config.fec().filter(fec -> fec instanceof FecConfig.Flexfec).map(FecConfig.Flexfec.class::cast);
        if (flexfec.isPresent() && (packet.ssrc() == flexfec.get().ssrc()
                || (payloadType == flexfec.get().payloadType() && packet.ssrc() != mediaSsrc))) {
            fecPackets++;
            fecBytes += packet.payloadLength();
            if (fecDecoder != null) {
                try {
                    for (var recoveredPacket : fecDecoder.addFec(packet.payload())) {
                        media(recoveredPacket, arrivalNanos, Origin.RECOVERED, work);
                    }
                } catch (RtpFormatException exception) {
                    discarded++;
                }
            }
            return;
        }
        var apt = config.rtxPayloadTypes().get(payloadType);
        if (apt != null) {
            rtxSsrc = packet.ssrc();
            if (packet.payloadLength() < 2) {
                return;
            }
            if (mediaSsrc < 0) {
                discarded++;
                return;
            }
            try {
                var restored = Rtx.restore(packet, apt, mediaSsrc);
                retransmittedPackets++;
                retransmittedBytes += restored.payloadLength();
                dispatch(restored, arrivalNanos, Origin.RETRANSMISSION, work);
            } catch (RtpFormatException exception) {
                discarded++;
            }
            return;
        }
        if (mediaSsrc < 0) {
            mediaSsrc = packet.ssrc();
            createFecDecoder();
        } else if (packet.ssrc() != mediaSsrc) {
            discarded++;
            return;
        }
        if (packet.payloadLength() == 0 && packet.paddingLength() > 0) {
            statistics.update(packet.sequence(), packet.timestamp(), arrivalNanos, clockRateOf(payloadType));
            headerBytesReceived += packet.length();
            nackObserve(packet.sequence(), Origin.NETWORK, work, arrivalNanos);
            skip(unwrapper.unwrap(packet.sequence()), work);
            return;
        }
        dispatch(packet, arrivalNanos, Origin.NETWORK, work);
    }

    /// Unwraps RED and ULPFEC, then handles the media packet.
    private void dispatch(RtpPacket packet, long arrivalNanos, Origin origin, Work work) {
        if (origin == Origin.NETWORK) {
            statistics.update(packet.sequence(), packet.timestamp(), arrivalNanos, clockRateOf(packet.payloadType()));
            bytesReceived += packet.payloadLength();
            headerBytesReceived += packet.length() - packet.payloadLength();
        }
        var redPayloadType = redPayloadType();
        if (redPayloadType.isPresent() && packet.payloadType() == redPayloadType.getAsInt()) {
            List<Red.Block> blocks;
            try {
                blocks = Red.decode(packet.payload(), packet.timestamp());
            } catch (RtpFormatException exception) {
                discarded++;
                return;
            }
            var primary = blocks.getLast();
            var ulpfec = config.fec().filter(fec -> fec instanceof FecConfig.Ulpfec).map(FecConfig.Ulpfec.class::cast);
            if (ulpfec.isPresent() && primary.payloadType() == ulpfec.get().ulpfecPayloadType()) {
                fecPackets++;
                fecBytes += primary.data().remaining();
                nackObserve(packet.sequence(), origin, work, arrivalNanos);
                skip(unwrapper.unwrap(packet.sequence()), work);
                if (fecDecoder != null) {
                    try {
                        for (var recoveredPacket : fecDecoder.addFec(primary.data())) {
                            media(recoveredPacket, arrivalNanos, Origin.RECOVERED, work);
                        }
                    } catch (RtpFormatException exception) {
                        discarded++;
                    }
                }
                return;
            }
            var redundant = blocks.size() - 1;
            for (var i = 0; i < redundant; i++) {
                var block = blocks.get(i);
                var sequence = (packet.sequence() - (redundant - i)) & 0xFFFF;
                var unwrapped = unwrapper.peek(sequence);
                if (!isDelivered(unwrapped) && (nextExpected == Long.MIN_VALUE || unwrapped >= nextExpected - 64)) {
                    var rebuilt = rebuild(packet, block.payloadType(), sequence, block.timestamp(), false, block.data());
                    if (rebuilt != null) {
                        media(rebuilt, arrivalNanos, Origin.RECOVERED, work);
                    }
                }
            }
            var media = rebuild(packet, primary.payloadType(), packet.sequence(), packet.timestamp(), packet.marker(),
                    primary.data());
            if (media != null) {
                media(media, arrivalNanos, origin, work);
            }
            return;
        }
        media(packet, arrivalNanos, origin, work);
    }

    private OptionalInt redPayloadType() {
        if (config.redPayloadType().isPresent()) {
            return config.redPayloadType();
        }
        return config.fec().filter(fec -> fec instanceof FecConfig.Ulpfec)
                .map(fec -> OptionalInt.of(((FecConfig.Ulpfec) fec).redPayloadType())).orElse(OptionalInt.empty());
    }

    /// Rebuilds a media packet from a RED block: the RED packet's header with another payload type, sequence number,
    /// timestamp and marker, and the block as payload.
    private static RtpPacket rebuild(RtpPacket red, int payloadType, int sequence, long timestamp, boolean marker,
                                     ByteBuffer data) {
        var header = red.headerLength();
        var out = ByteBuffer.allocate(header + data.remaining());
        out.put(red.buffer().slice(0, header));
        out.put(0, (byte) (out.get(0) & ~0x20));
        out.put(1, (byte) ((marker ? 0x80 : 0) | payloadType));
        out.putShort(2, (short) sequence);
        out.putInt(4, (int) timestamp);
        out.put(data.duplicate());
        try {
            return RtpPacket.parse(out.flip());
        } catch (RtpFormatException exception) {
            return null;
        }
    }

    /// Handles a media packet (RED and RTX removed): duplicates, NACK state, FEC, ordering.
    private void media(RtpPacket packet, long arrivalNanos, Origin origin, Work work) {
        var sequence = unwrapper.unwrap(packet.sequence());
        if (isDelivered(sequence) || held.containsKey(sequence)) {
            if (origin == Origin.NETWORK) {
                duplicated++;
            }
            return;
        }
        if (highestDelivered != Long.MIN_VALUE && sequence <= highestDelivered - DELIVERED_WINDOW) {
            discarded++;
            return;
        }
        if (origin == Origin.RECOVERED) {
            recovered++;
        }
        if (nackObserve(packet.sequence(), origin, work, arrivalNanos) && origin == Origin.NETWORK) {
            retransmittedPackets++;
            retransmittedBytes += packet.payloadLength();
        }
        if (fecDecoder != null && origin != Origin.RECOVERED) {
            for (var recoveredPacket : fecDecoder.addMedia(zeroSendTimeExtensions(packet))) {
                media(recoveredPacket, arrivalNanos, Origin.RECOVERED, work);
            }
        }
        order(sequence, packet, arrivalNanos, work, origin != Origin.NETWORK);
    }

    /// Updates the NACK state; returns whether the packet had been NACKed.
    private boolean nackObserve(int wireSequence, Origin origin, Work work, long nowNanos) {
        if (nack == null) {
            return false;
        }
        var nacked = nack.onPacket(unwrapper.peek(wireSequence), origin != Origin.NETWORK);
        collectNacks(nowNanos, work);
        return nacked;
    }

    /// Delivers or holds a packet so the receiver sees sequence order.
    private void order(long sequence, RtpPacket packet, long nowNanos, Work work, boolean owned) {
        var reorder = config.reorderDelay().toNanos();
        if (nextExpected == Long.MIN_VALUE || sequence < nextExpected) {
            deliver(sequence, packet, work);
            if (nextExpected == Long.MIN_VALUE) {
                nextExpected = sequence + 1;
            }
            return;
        }
        if (sequence == nextExpected || reorder == 0) {
            deliver(sequence, packet, work);
            nextExpected = sequence + 1;
            drainHeld(work);
            return;
        }
        held.put(sequence, owned ? packet : packet.copy());
        if (heldSinceNanos == Long.MIN_VALUE) {
            heldSinceNanos = nowNanos;
        }
        if (held.size() > MAX_HELD) {
            releaseHeld(work);
        }
    }

    private void drainHeld(Work work) {
        while (!held.isEmpty() && held.firstKey() == nextExpected) {
            var entry = held.pollFirstEntry();
            deliver(entry.getKey(), entry.getValue(), work);
            nextExpected++;
        }
        if (held.isEmpty()) {
            heldSinceNanos = Long.MIN_VALUE;
        }
    }

    private void releaseHeld(Work work) {
        if (held.isEmpty()) {
            return;
        }
        nextExpected = held.firstKey();
        drainHeld(work);
        if (!held.isEmpty()) {
            heldSinceNanos = session.now();
        }
    }

    /// Accounts for a sequence number that carries no media (an FEC or padding packet on the media SSRC), so it
    /// is not waited for.
    private void skip(long sequence, Work work) {
        markDelivered(sequence);
        if (nextExpected == Long.MIN_VALUE || sequence == nextExpected) {
            nextExpected = sequence + 1;
            drainHeld(work);
        }
    }

    private void deliver(long sequence, RtpPacket packet, Work work) {
        markDelivered(sequence);
        work.addDelivery(packet);
    }

    private void markDelivered(long sequence) {
        delivered[(int) Math.floorMod(sequence, (long) DELIVERED_WINDOW)] = sequence + 1;
        if (highestDelivered == Long.MIN_VALUE || sequence > highestDelivered) {
            highestDelivered = sequence;
        }
    }

    private boolean isDelivered(long sequence) {
        return delivered[(int) Math.floorMod(sequence, (long) DELIVERED_WINDOW)] == sequence + 1;
    }

    /// Copies a packet with its transport-wide sequence number and absolute send time zeroed, the values the sender
    /// computed its FEC over.
    private RtpPacket zeroSendTimeExtensions(RtpPacket packet) {
        if (transportSequenceId.isEmpty() && absSendTimeId.isEmpty()) {
            return packet;
        }
        var copy = packet.copy();
        var buffer = copy.buffer();
        var bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        var writable = ByteBuffer.wrap(bytes);
        zero(copy, transportSequenceId, writable);
        zero(copy, absSendTimeId, writable);
        try {
            return RtpPacket.parse(writable);
        } catch (RtpFormatException exception) {
            return packet;
        }
    }

    private static void zero(RtpPacket packet, OptionalInt id, ByteBuffer bytes) {
        if (id.isEmpty()) {
            return;
        }
        var offset = packet.extensionOffset(id.getAsInt());
        var value = packet.extension(id.getAsInt());
        if (offset.isPresent() && value.isPresent()) {
            for (var i = 0; i < value.get().remaining(); i++) {
                bytes.put(offset.getAsInt() + i, (byte) 0);
            }
        }
    }

    private void collectNacks(long nowNanos, Work work) {
        if (nack == null || mediaSsrc < 0) {
            return;
        }
        var due = nack.due(nowNanos, session.rttNanos());
        if (!due.isEmpty()) {
            var sequences = new ArrayList<Integer>(due.size());
            for (var sequence : due) {
                sequences.add((int) (sequence & 0xFFFF));
            }
            work.addFeedback(new Nack(session.feedbackSsrc(), mediaSsrc, sequences));
            nackCount++;
        }
        if (nack.takeKeyframeNeeded()) {
            nack.clear();
            requestKeyframeIfAllowed(nowNanos, work);
        }
    }

    private void requestKeyframeIfAllowed(long nowNanos, Work work) {
        if (lastKeyframeRequestNanos != Long.MIN_VALUE
                && nowNanos - lastKeyframeRequestNanos < KEYFRAME_REQUEST_INTERVAL_NANOS) {
            return;
        }
        var method = config.feedback().contains(FeedbackMechanism.PLI) ? Optional.of(KeyframeMethod.PLI)
                : config.feedback().contains(FeedbackMechanism.FIR) ? Optional.of(KeyframeMethod.FIR)
                : Optional.<KeyframeMethod>empty();
        method.flatMap(value -> keyframeRequest(value, nowNanos)).ifPresent(work::addFeedback);
    }

    private Optional<RtcpPacket> keyframeRequest(KeyframeMethod method, long nowNanos) {
        if (mediaSsrc < 0) {
            return Optional.empty();
        }
        lastKeyframeRequestNanos = nowNanos;
        if (method == KeyframeMethod.PLI) {
            pliCount++;
            return Optional.of(new PictureLossIndication(session.feedbackSsrc(), mediaSsrc));
        }
        firCount++;
        var entry = new FullIntraRequest.Entry(mediaSsrc, firSequence);
        firSequence = (firSequence + 1) & 0xFF;
        return Optional.of(new FullIntraRequest(session.feedbackSsrc(), List.of(entry)));
    }

    /// Runs the stream's timers: NACK retries, keyframe fallback, reorder release. Called under the session lock.
    void onTick(long nowNanos, Work work) {
        collectNacks(nowNanos, work);
        var reorder = config.reorderDelay().toNanos();
        if (heldSinceNanos != Long.MIN_VALUE && nowNanos - heldSinceNanos >= reorder) {
            releaseHeld(work);
        }
    }

    /// {@return the earliest time the stream's timers need to run}
    long nextDeadline() {
        var deadline = Long.MAX_VALUE;
        if (nack != null && nack.missingCount() > 0) {
            var due = nack.nextDeadline(session.rttNanos());
            deadline = Math.min(deadline, due);
        }
        if (heldSinceNanos != Long.MIN_VALUE) {
            deadline = Math.min(deadline, heldSinceNanos + config.reorderDelay().toNanos());
        }
        return deadline;
    }

    /// Hands released packets to the receiver, outside the session lock, one call at a time.
    void deliver(Work work) {
        var count = work.deliveryCount();
        if (count == 0) {
            return;
        }
        deliveryLock.lock();
        try {
            var current = receiver;
            for (var index = 0; index < count; index++) {
                current.accept(work.delivery(index));
            }
        } finally {
            deliveryLock.unlock();
        }
    }

    /// Records a sender report from the stream's source. Called under the session lock.
    void onSenderReport(SenderReport report, long arrivalNanos) {
        lastSr = report;
        senderReports++;
        lastSenderReport = NtpTime.compact(report.ntpTimestamp());
        lastSenderReportArrival = arrivalNanos;
        senderClock = new NtpRtpMapping(report.ntpTimestamp(), report.rtpTimestamp(), config.defaultClockRate(),
                arrivalNanos);
    }

    /// Records a round-trip time measured as a receiver. Called under the session lock.
    void onReceiverRtt(long rttNanos) {
        receiverRttNanos = rttNanos;
    }

    /// {@return the stream's reception report block, or empty before its first packet}. Called under the session
    /// lock.
    Optional<ReceptionReport> reportBlock(long nowNanos) {
        if (!statistics.started() || mediaSsrc < 0) {
            return Optional.empty();
        }
        return Optional.of(statistics.report(mediaSsrc, lastSenderReport, nowNanos - lastSenderReportArrival,
                nowNanos));
    }

    private int clockRateOf(int payloadType) {
        return config.payloadTypes().getOrDefault(payloadType, config.defaultClockRate());
    }

    /// {@return the counters statistics do not expose, for tests}
    Map<String, Long> counters() {
        return Map.of("duplicated", duplicated, "discarded", discarded, "recovered", recovered,
                "retransmitted", retransmittedPackets, "fec", fecPackets);
    }

    @Override
    public String toString() {
        return "RtpReceiveStream[mid=" + config.mid().orElse("-") + config.rid().map(rid -> ", rid=" + rid).orElse("")
                + ", ssrc=" + (mediaSsrc < 0 ? "?" : mediaSsrc) + "]";
    }
}
