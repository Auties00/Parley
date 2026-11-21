package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.NtpTime;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.extension.AbsSendTime;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.rtp.extension.TransportSequenceNumber;
import com.github.auties00.parley.rtp.rtcp.Bye;
import com.github.auties00.parley.rtp.rtcp.ExtendedReport;
import com.github.auties00.parley.rtp.rtcp.FullIntraRequest;
import com.github.auties00.parley.rtp.rtcp.Nack;
import com.github.auties00.parley.rtp.rtcp.PictureLossIndication;
import com.github.auties00.parley.rtp.rtcp.ReceiverReport;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.RtcpFormatException;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.SenderReport;
import com.github.auties00.parley.rtp.rtcp.SourceDescription;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import com.github.auties00.parley.transport.RtpTransport;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.SplittableRandom;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.random.RandomGenerator;

/// The RTP session of one BUNDLE group: every RTP and RTCP packet that crosses one [RtpTransport].
///
/// The session owns the send and receive streams of the group, routes incoming packets to receive streams
/// ([RtpDemuxer]), serves and generates feedback, and runs the RTCP timer: sender and receiver reports with full
/// reception statistics, source descriptions with the CNAME, extended reports for receive-only round-trip times,
/// and early or reduced-size feedback as the [RtcpConfig] allows.
///
/// {@snippet lang = java :
/// var session = RtpSession.builder(transport)
///         .cname("parley")
///         .extensions(bundleExtensions)
///         .build();
/// var audio = session.createSendStream(SendStreamConfig.builder("0", 0x1234, 111, 48_000)
///         .extensions(bundleExtensions)
///         .build());
/// audio.send(List.of(opusFrame), timestamp, false, Map.of(), OutgoingPacketScheduler.Priority.AUDIO);
/// }
///
/// # Congestion control
///
/// Outgoing packets go through an [OutgoingPacketScheduler] (by default sent immediately); the [PacketSink] it calls
/// stamps the transport-wide sequence number and the absolute send time at the moment of sending and reports every
/// packet to the [TransportFeedbackObserver], which also receives every transport-wide feedback, REMB and reception
/// report. On the receive side every packet's arrival is reported to the arrival observer, from which transport-wide
/// feedback and REMB are generated.
///
/// # Threading
///
/// Every method is thread-safe. Incoming packets are processed on the transport's reader threads; RTCP timing, NACK
/// retries and the reorder delay run on one timer thread from the builder's [ThreadFactory]. Listeners are called on
/// those threads, outside the session's lock, and must not block.
///
/// # Lifecycle
///
/// The session installs itself as the transport's RTP and RTCP receiver when built. [#close()] sends a BYE for every
/// local SSRC, stops the timer thread and detaches from the transport; the transport itself stays open, its owner
/// closes it.
///
/// @see RtpSendStream
/// @see RtpReceiveStream
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3611.html RFC 3611: RTP Control Protocol Extended Reports (RTCP XR)
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
public final class RtpSession implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(RtpSession.class.getName());

    /// The largest compound RTCP packet the session builds; more feedback goes in further packets.
    static final int MAX_COMPOUND_BYTES = 1200;
    /// The sender reports remembered to compute round-trip times from the `LSR` echoed back.
    static final int REMEMBERED_REPORTS = 64;
    /// How long a remote SSRC counts as a session member after its last packet.
    static final long MEMBER_TIMEOUT_NANOS = 30_000_000_000L;
    /// How long after reporting an unsignaled SSRC the session reports it again.
    static final long UNSIGNALED_REPORT_INTERVAL_NANOS = 1_000_000_000L;

    /// What an outgoing packet is, for the statistics.
    enum PacketKind {
        MEDIA, RETRANSMISSION, FEC, PADDING
    }

    /// One packet ready for the scheduler.
    record Outgoing(ByteBuffer buffer, OutgoingPacketScheduler.Priority priority, long ssrc, PacketKind kind,
                    RtpSendStream stream) {
    }

    private final SessionTransport transport;
    private final MonotonicClock clock;
    private final InstantSource wallClock;
    private final OutgoingPacketScheduler scheduler;
    private final TransportFeedbackObserver feedbackObserver;
    private final Consumer<PacketArrival> arrivalObserver;
    private final RtcpConfig rtcpConfig;
    private final String cname;
    private final long localSsrc;
    private final RandomGenerator random;
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantLock sendLock = new ReentrantLock();
    private final List<RtpSendStream> sendStreams = new ArrayList<>();
    private final List<RtpReceiveStream> receiveStreams = new ArrayList<>();
    private HeaderExtensionMap extensions;
    private RtpDemuxer<RtpReceiveStream> demuxer;
    private final RtcpScheduler rtcpScheduler;
    private final Map<Long, Long> senderReportsSent = boundedMap();
    private final Map<Long, Long> referenceTimesSent = boundedMap();
    private final Map<Long, long[]> peerReferenceTimes = new HashMap<>();
    private final List<RtcpPacket> pendingFeedback = new ArrayList<>();
    private final Map<Long, Long> remoteSsrcs = new HashMap<>();
    private final Map<Long, Long> unsignaledReported = boundedMap();
    private final Map<Long, String> remoteCnames = new HashMap<>();
    private int transportSequence;
    private volatile long rttNanos = -1;
    private volatile boolean closed;
    private volatile Consumer<UnsignaledStream> unhandledStreamListener = stream -> {
    };
    private volatile Consumer<RtcpPacket> rtcpListener = packet -> {
    };
    private final Thread timerThread;
    private long malformedRtp;
    private long malformedRtcp;
    private long unhandledRtp;

    private RtpSession(Builder builder) {
        this.transport = builder.transport;
        this.clock = builder.clock != null ? builder.clock : MonotonicClock.system();
        this.wallClock = builder.wallClock;
        this.scheduler = builder.scheduler;
        this.feedbackObserver = builder.feedbackObserver;
        this.arrivalObserver = builder.arrivalObserver;
        this.rtcpConfig = builder.rtcp;
        this.random = builder.random;
        this.cname = builder.cname != null ? builder.cname : randomCname(random);
        this.localSsrc = builder.localSsrc >= 0 ? builder.localSsrc : random.nextLong(1, 1L << 32);
        this.extensions = builder.extensions;
        this.demuxer = RtpDemuxer.create(extensions, List.of());
        this.rtcpScheduler = new RtcpScheduler(rtcpConfig, random, clock.nanos(), 100);
        transport.setRtpReceiver(this::onRtp);
        transport.setRtcpReceiver(this::onRtcp);
        scheduler.setPaddingSource(this::sendPadding);
        if (builder.manualTimers) {
            this.timerThread = null;
        } else {
            this.timerThread = builder.threadFactory.newThread(this::runTimers);
            timerThread.start();
        }
    }

    private static <K, V> Map<K, V> boundedMap() {
        return new LinkedHashMap<>(16, 0.75f, false) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > REMEMBERED_REPORTS * 16;
            }
        };
    }

    private static String randomCname(RandomGenerator random) {
        var bytes = new byte[12];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /// {@return a builder for a session over a transport}
    ///
    /// @param transport the SRTP transport of the BUNDLE group; the session installs itself as its RTP and RTCP
    ///                  receiver
    public static Builder builder(RtpTransport transport) {
        return new Builder(SessionTransport.of(Objects.requireNonNull(transport, "transport cannot be null")));
    }

    /// {@return a builder over the transport seam, for tests}
    static Builder builder(SessionTransport transport) {
        return new Builder(transport);
    }

    /// {@return the canonical name the session reports in its source descriptions}
    public String cname() {
        return cname;
    }

    /// {@return the SSRC the session reports and sends feedback as while it has no send stream}
    public long localSsrc() {
        return localSsrc;
    }

    /// Creates a send stream.
    ///
    /// @param config the stream's parameters
    /// @return the stream, ready to send
    /// @throws IllegalArgumentException if one of its SSRCs is already used by a local stream
    /// @throws IllegalStateException    if the session is closed
    public RtpSendStream createSendStream(SendStreamConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        lock.lock();
        try {
            checkOpen();
            for (var stream : sendStreams) {
                if (stream.ownsSsrc(config.ssrc()) || config.rtxSsrc().stream().anyMatch(stream::ownsSsrc)) {
                    throw new IllegalArgumentException("SSRC already used by " + stream);
                }
            }
            var stream = new RtpSendStream(this, config, random.nextInt(1 << 15));
            sendStreams.add(stream);
            return stream;
        } finally {
            lock.unlock();
        }
    }

    /// Creates a receive stream and routes to it what its configuration signals.
    ///
    /// @param config the stream's parameters
    /// @return the stream, receiving from now on
    /// @throws IllegalStateException if the session is closed
    public RtpReceiveStream createReceiveStream(ReceiveStreamConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        lock.lock();
        try {
            checkOpen();
            var stream = new RtpReceiveStream(this, config);
            receiveStreams.add(stream);
            var routes = new ArrayList<>(demuxer.routes());
            routes.add(stream.route());
            demuxer = demuxer.withRoutes(extensions, routes);
            return stream;
        } finally {
            lock.unlock();
        }
    }

    /// Removes a send stream; it sends nothing more and its SSRCs are announced in a BYE.
    ///
    /// @param stream a stream of this session
    /// @throws IOException if sending the BYE fails
    public void removeSendStream(RtpSendStream stream) throws IOException {
        Objects.requireNonNull(stream, "stream cannot be null");
        List<RtcpPacket> bye;
        lock.lock();
        try {
            if (!sendStreams.remove(stream) || closed) {
                return;
            }
            var ssrcs = new ArrayList<Long>();
            ssrcs.add(stream.ssrc());
            stream.config().rtxSsrc().ifPresent(ssrcs::add);
            bye = List.of(new ReceiverReport(feedbackSsrc(), List.of()), new Bye(ssrcs, Optional.empty()));
        } finally {
            lock.unlock();
        }
        transport.sendRtcp(RtcpPacket.encodeCompound(bye, transport.protectionOverhead()));
    }

    /// Removes a receive stream and every route to it.
    ///
    /// @param stream a stream of this session
    public void removeReceiveStream(RtpReceiveStream stream) {
        Objects.requireNonNull(stream, "stream cannot be null");
        lock.lock();
        try {
            if (receiveStreams.remove(stream)) {
                var routes = new ArrayList<RtpDemuxer.Route<RtpReceiveStream>>();
                for (var route : demuxer.routes()) {
                    if (route.target() != stream) {
                        routes.add(route);
                    }
                }
                demuxer = demuxer.withRoutes(extensions, routes);
            }
        } finally {
            lock.unlock();
        }
    }

    /// Replaces the routing of incoming RTP, after a renegotiation changed MIDs, RIDs, SSRCs, payload types or
    /// extension ids. SSRC bindings learned from packets are kept for streams that are still routed.
    ///
    /// @param table the new routing; every route must lead to a receive stream of this session
    /// @throws IllegalArgumentException if a route leads to a stream of another session
    public void updateRoutes(RtpRoutingTable table) {
        Objects.requireNonNull(table, "table cannot be null");
        lock.lock();
        try {
            for (var route : table.routes()) {
                if (!receiveStreams.contains(route.target())) {
                    throw new IllegalArgumentException("route to a stream of another session: " + route.target());
                }
            }
            extensions = table.extensions();
            demuxer = demuxer.withRoutes(extensions, table.routes());
        } finally {
            lock.unlock();
        }
    }

    /// Sets the listener told of incoming SSRCs no receive stream claims; it may create a receive stream for one,
    /// after which the packet that triggered the report is routed again. Each SSRC is reported at most once a second.
    ///
    /// @param listener the listener, called on the transport's reader thread
    public void setUnhandledStreamListener(Consumer<UnsignaledStream> listener) {
        this.unhandledStreamListener = Objects.requireNonNull(listener, "listener cannot be null");
    }

    /// Sets the listener told of every received RTCP packet the session does not consume: application data, BYEs,
    /// RFC 8888 feedback, unknown packets, and REMB or transport-wide feedback when no feedback observer was given.
    ///
    /// @param listener the listener, called on the transport's reader thread
    public void setRtcpListener(Consumer<RtcpPacket> listener) {
        this.rtcpListener = Objects.requireNonNull(listener, "listener cannot be null");
    }

    /// Sends RTCP packets now, such as transport-wide feedback generated outside the session.
    ///
    /// Packets that start with a sender or receiver report, or any packets when reduced-size RTCP was negotiated,
    /// are sent as given; otherwise the session prepends a receiver report and its source description so the
    /// compound packet is valid.
    ///
    /// @param packets the packets, at least one
    /// @throws IOException              if the transport fails
    /// @throws IllegalArgumentException if `packets` is empty
    /// @throws IllegalStateException    if the session is closed
    public void sendRtcp(RtcpPacket... packets) throws IOException {
        Objects.requireNonNull(packets, "packets cannot be null");
        if (packets.length == 0) {
            throw new IllegalArgumentException("packets cannot be empty");
        }
        var list = List.of(packets);
        List<RtcpPacket> compound;
        lock.lock();
        try {
            checkOpen();
            var first = list.getFirst();
            if (rtcpConfig.reducedSize() || first instanceof SenderReport || first instanceof ReceiverReport) {
                compound = list;
            } else {
                compound = new ArrayList<>(list.size() + 2);
                compound.add(new ReceiverReport(feedbackSsrc(), List.of()));
                compound.add(SourceDescription.ofCname(feedbackSsrc(), cname));
                compound.addAll(list);
            }
        } finally {
            lock.unlock();
        }
        sendCompound(compound);
    }

    /// {@return the send streams}
    public List<RtpSendStream> sendStreams() {
        lock.lock();
        try {
            return List.copyOf(sendStreams);
        } finally {
            lock.unlock();
        }
    }

    /// {@return the receive streams}
    public List<RtpReceiveStream> receiveStreams() {
        lock.lock();
        try {
            return List.copyOf(receiveStreams);
        } finally {
            lock.unlock();
        }
    }

    /// {@return the CNAME a remote SSRC announced in its source descriptions}
    ///
    /// @param ssrc the remote SSRC
    public Optional<String> remoteCname(long ssrc) {
        lock.lock();
        try {
            return Optional.ofNullable(remoteCnames.get(ssrc));
        } finally {
            lock.unlock();
        }
    }

    /// {@return the latest round-trip time measured, from reception reports or extended reports, in nanoseconds,
    /// or `-1` before the first measurement}
    public long roundTripTimeNanos() {
        return rttNanos;
    }

    /// Closes the session: sends a BYE for every local SSRC, stops the timer thread and stops receiving. The
    /// transport stays open. Calling it again does nothing.
    @Override
    public void close() {
        List<RtcpPacket> bye;
        lock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            var ssrcs = new ArrayList<Long>();
            for (var stream : sendStreams) {
                ssrcs.add(stream.ssrc());
                stream.config().rtxSsrc().ifPresent(ssrcs::add);
            }
            if (ssrcs.isEmpty()) {
                ssrcs.add(localSsrc);
            }
            bye = List.of(new ReceiverReport(feedbackSsrc(), List.of()),
                    SourceDescription.ofCname(feedbackSsrc(), cname),
                    new Bye(ssrcs.subList(0, Math.min(31, ssrcs.size())), Optional.empty()));
        } finally {
            lock.unlock();
        }
        transport.setRtpReceiver((packet, arrival) -> {
        });
        transport.setRtcpReceiver((packet, arrival) -> {
        });
        try {
            transport.sendRtcp(RtcpPacket.encodeCompound(bye, transport.protectionOverhead()));
        } catch (IOException | RuntimeException exception) {
            LOGGER.log(Level.DEBUG, "could not send the closing BYE", exception);
        }
        if (timerThread != null) {
            timerThread.interrupt();
        }
    }

    ReentrantLock lock() {
        return lock;
    }

    long now() {
        return clock.nanos();
    }

    long rttNanos() {
        return rttNanos;
    }

    int tailroom() {
        return transport.protectionOverhead();
    }

    void checkOpen() {
        if (closed) {
            throw new IllegalStateException("the session is closed");
        }
    }

    /// {@return the SSRC feedback and receiver reports are sent as: the first send stream's, else the local one}
    long feedbackSsrc() {
        return sendStreams.isEmpty() ? localSsrc : sendStreams.getFirst().ssrc();
    }

    long malformedRtpCount() {
        return malformedRtp;
    }

    long malformedRtcpCount() {
        return malformedRtcp;
    }

    long unhandledRtpCount() {
        return unhandledRtp;
    }

    /// Hands packets to the scheduler; with the immediate scheduler, sends them and reports the first failure.
    void dispatch(List<Outgoing> outgoing) throws IOException {
        IOException failure = null;
        for (var packet : outgoing) {
            OutgoingPacketScheduler.PacketSink sink = new OutgoingPacketScheduler.PacketSink() {
                @Override
                public void send(ByteBuffer plainRtp) throws IOException {
                    sendNow(packet, plainRtp, false);
                }

                @Override
                public void send(ByteBuffer plainRtp, boolean probe) throws IOException {
                    sendNow(packet, plainRtp, probe);
                }
            };
            if (scheduler == ImmediateScheduler.INSTANCE) {
                try {
                    sink.send(packet.buffer());
                } catch (IOException exception) {
                    if (failure == null) {
                        failure = exception;
                    } else {
                        failure.addSuppressed(exception);
                    }
                }
            } else {
                scheduler.schedule(packet.buffer(), packet.priority(), packet.ssrc(), sink);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    /// Stamps the send-time extensions, protects and sends one packet, then accounts for it.
    private void sendNow(Outgoing packet, ByteBuffer buffer, boolean probe) throws IOException {
        int sequence = -1;
        int size;
        int payloadBytes;
        int headerBytes;
        long sentAt;
        sendLock.lock();
        try {
            sentAt = clock.nanos();
            RtpPacket view;
            try {
                view = RtpPacket.parse(buffer);
            } catch (RtpFormatException exception) {
                throw new IOException("the scheduler returned a malformed packet", exception);
            }
            var twcc = packet.stream().transportSequenceId();
            if (twcc.isPresent()) {
                var offset = view.extensionOffset(twcc.getAsInt());
                if (offset.isPresent()) {
                    sequence = transportSequence;
                    transportSequence = (transportSequence + 1) & 0xFFFF;
                    TransportSequenceNumber.stamp(buffer, offset.getAsInt(), sequence);
                }
            }
            var abs = packet.stream().absSendTimeId();
            if (abs.isPresent()) {
                var offset = view.extensionOffset(abs.getAsInt());
                if (offset.isPresent()) {
                    AbsSendTime.stamp(buffer, offset.getAsInt(), sentAt);
                }
            }
            size = view.length();
            payloadBytes = view.payloadLength();
            headerBytes = size - payloadBytes;
            transport.sendRtp(buffer);
        } finally {
            sendLock.unlock();
        }
        lock.lock();
        try {
            packet.stream().onSent(packet.kind(), payloadBytes, headerBytes, sentAt);
        } finally {
            lock.unlock();
        }
        var observer = feedbackObserver;
        if (observer != null) {
            observer.onPacketSent(sequence, size, sentAt, packet.priority(), probe);
        }
    }

    /// The padding source given to the scheduler.
    private int sendPadding(int targetBytes, boolean probe) throws IOException {
        if (targetBytes <= 0) {
            return 0;
        }
        var outgoing = new ArrayList<Outgoing>();
        int produced;
        lock.lock();
        try {
            if (closed) {
                return 0;
            }
            RtpSendStream chosen = null;
            for (var stream : sendStreams) {
                if (stream.sentSince(Long.MIN_VALUE + 1)
                        && (chosen == null || stream.config().rtxSsrc().isPresent()
                        && chosen.config().rtxSsrc().isEmpty())) {
                    chosen = stream;
                }
            }
            if (chosen == null) {
                return 0;
            }
            produced = chosen.padding(targetBytes, outgoing);
        } finally {
            lock.unlock();
        }
        for (var packet : outgoing) {
            sendNow(packet, packet.buffer(), probe);
        }
        return produced;
    }

    /// Receives one decrypted RTP packet from the transport.
    private void onRtp(ByteBuffer buffer, long arrivalNanos) {
        if (closed) {
            return;
        }
        RtpPacket packet;
        try {
            packet = RtpPacket.parse(buffer);
        } catch (RtpFormatException exception) {
            lock.lock();
            try {
                malformedRtp++;
            } finally {
                lock.unlock();
            }
            return;
        }
        var observer = arrivalObserver;
        if (observer != null) {
            observer.accept(arrival(packet, arrivalNanos));
        }
        var work = new RtpReceiveStream.Work();
        var target = route(packet, arrivalNanos, work);
        if (target.isEmpty()) {
            return;
        }
        var stream = target.get();
        sendFeedbackQuietly(work.feedback());
        stream.deliver(work.deliveries());
        if (stream.nextDeadline() != Long.MAX_VALUE) {
            wakeTimer();
        }
    }

    private PacketArrival arrival(RtpPacket packet, long arrivalNanos) {
        HeaderExtensionMap map;
        lock.lock();
        try {
            map = extensions;
        } finally {
            lock.unlock();
        }
        var transportSequenceValue = OptionalInt.empty();
        var twcc = map.find(packet, HeaderExtensionUris.TRANSPORT_WIDE_CC);
        if (twcc.isPresent() && twcc.get().remaining() >= 2) {
            transportSequenceValue = OptionalInt.of(twcc.get().getShort(0) & 0xFFFF);
        }
        var absValue = OptionalInt.empty();
        var abs = map.find(packet, HeaderExtensionUris.ABS_SEND_TIME);
        if (abs.isPresent() && abs.get().remaining() >= 3) {
            var value = abs.get();
            absValue = OptionalInt.of((value.get(0) & 0xFF) << 16 | (value.get(1) & 0xFF) << 8 | value.get(2) & 0xFF);
        }
        return new PacketArrival(packet.ssrc(), packet.length(), transportSequenceValue, absValue, arrivalNanos);
    }

    private Optional<RtpReceiveStream> route(RtpPacket packet, long arrivalNanos, RtpReceiveStream.Work work) {
        UnsignaledStream unsignaled;
        lock.lock();
        try {
            remoteSsrcs.put(packet.ssrc(), arrivalNanos);
            switch (demuxer.route(packet)) {
                case RtpDemuxer.Result.Matched<RtpReceiveStream>(var stream) -> {
                    stream.receive(packet, arrivalNanos, work);
                    return Optional.of(stream);
                }
                case RtpDemuxer.Result.Unmatched<RtpReceiveStream>(var stream) -> unsignaled = stream;
            }
            var last = unsignaledReported.get(packet.ssrc());
            if (last != null && arrivalNanos - last < UNSIGNALED_REPORT_INTERVAL_NANOS) {
                unhandledRtp++;
                return Optional.empty();
            }
            unsignaledReported.put(packet.ssrc(), arrivalNanos);
        } finally {
            lock.unlock();
        }
        try {
            unhandledStreamListener.accept(unsignaled);
        } catch (RuntimeException exception) {
            LOGGER.log(Level.WARNING, "the unhandled-stream listener failed", exception);
        }
        lock.lock();
        try {
            if (closed) {
                return Optional.empty();
            }
            if (demuxer.route(packet) instanceof RtpDemuxer.Result.Matched<RtpReceiveStream>(var stream)) {
                stream.receive(packet, arrivalNanos, work);
                return Optional.of(stream);
            }
            unhandledRtp++;
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    /// Receives one decrypted compound RTCP packet from the transport.
    private void onRtcp(ByteBuffer buffer, long arrivalNanos) {
        if (closed) {
            return;
        }
        List<RtcpPacket> packets;
        try {
            packets = RtcpPacket.parseCompound(buffer);
        } catch (RtcpFormatException exception) {
            lock.lock();
            try {
                malformedRtcp++;
            } finally {
                lock.unlock();
            }
            return;
        }
        var outgoing = new ArrayList<Outgoing>();
        var keyframes = new ArrayList<Map.Entry<RtpSendStream, KeyframeRequest>>();
        var forwarded = new ArrayList<RtcpPacket>();
        var reports = new ArrayList<ReceptionReport>();
        var reportRtt = -1L;
        var observer = feedbackObserver;
        lock.lock();
        try {
            for (var packet : packets) {
                switch (packet) {
                    case SenderReport report -> {
                        remoteSsrcs.put(report.ssrc(), arrivalNanos);
                        for (var stream : receiveStreams) {
                            if (stream.mediaSsrc().isPresent() && stream.mediaSsrc().getAsLong() == report.ssrc()) {
                                stream.onSenderReport(report, arrivalNanos);
                            }
                        }
                        reportRtt = Math.max(reportRtt, onReceptionReports(report.reports(), arrivalNanos, reports));
                    }
                    case ReceiverReport report -> {
                        remoteSsrcs.put(report.ssrc(), arrivalNanos);
                        reportRtt = Math.max(reportRtt, onReceptionReports(report.reports(), arrivalNanos, reports));
                    }
                    case SourceDescription description -> {
                        for (var chunk : description.chunks()) {
                            chunk.find(SourceDescription.Item.CNAME)
                                    .ifPresent(value -> remoteCnames.put(chunk.ssrc(), value));
                        }
                    }
                    case Bye bye -> {
                        for (var ssrc : bye.ssrcs()) {
                            remoteSsrcs.remove(ssrc);
                            demuxer.unbind(ssrc);
                        }
                        forwarded.add(bye);
                    }
                    case ExtendedReport report -> onExtendedReport(report, arrivalNanos);
                    case Nack nack -> {
                        var stream = sendStreamOf(nack.mediaSsrc());
                        if (stream != null) {
                            stream.onNack(nack, arrivalNanos, rttNanos, outgoing);
                        }
                    }
                    case PictureLossIndication pli -> {
                        var stream = sendStreamOf(pli.mediaSsrc());
                        if (stream != null) {
                            stream.onKeyframeRequest(KeyframeMethod.PLI, pli.senderSsrc(), 0, arrivalNanos)
                                    .ifPresent(request -> keyframes.add(Map.entry(stream, request)));
                        }
                    }
                    case FullIntraRequest fir -> {
                        for (var entry : fir.entries()) {
                            var stream = sendStreamOf(entry.ssrc());
                            if (stream != null) {
                                stream.onKeyframeRequest(KeyframeMethod.FIR, fir.senderSsrc(), entry.sequence(),
                                        arrivalNanos).ifPresent(request -> keyframes.add(Map.entry(stream, request)));
                            }
                        }
                    }
                    case Remb remb -> {
                        if (observer == null) {
                            forwarded.add(remb);
                        }
                    }
                    case TransportFeedback feedback -> {
                        if (observer == null) {
                            forwarded.add(feedback);
                        }
                    }
                    default -> forwarded.add(packet);
                }
            }
        } finally {
            lock.unlock();
        }
        if (observer != null) {
            for (var packet : packets) {
                switch (packet) {
                    case TransportFeedback feedback -> observer.onTransportFeedback(feedback, arrivalNanos);
                    case Remb remb -> observer.onRemb(remb, arrivalNanos);
                    default -> {
                    }
                }
            }
            if (!reports.isEmpty()) {
                observer.onReceptionReports(List.copyOf(reports), reportRtt, arrivalNanos);
            }
        }
        for (var entry : keyframes) {
            try {
                entry.getKey().keyframeListener().accept(entry.getValue());
            } catch (RuntimeException exception) {
                LOGGER.log(Level.WARNING, "a keyframe request listener failed", exception);
            }
        }
        for (var packet : forwarded) {
            try {
                rtcpListener.accept(packet);
            } catch (RuntimeException exception) {
                LOGGER.log(Level.WARNING, "the RTCP listener failed", exception);
            }
        }
        try {
            dispatch(outgoing);
        } catch (IOException exception) {
            LOGGER.log(Level.DEBUG, "could not send a retransmission", exception);
        }
    }

    /// Applies report blocks about local streams. Called under the lock; returns the round-trip time measured.
    private long onReceptionReports(List<ReceptionReport> blocks, long arrivalNanos, List<ReceptionReport> local) {
        var measured = -1L;
        for (var block : blocks) {
            var stream = sendStreamOf(block.ssrc());
            if (stream == null || stream.ssrc() != block.ssrc()) {
                continue;
            }
            var rtt = -1L;
            if (block.lastSenderReport() != 0) {
                var sent = senderReportsSent.get(block.lastSenderReport());
                if (sent != null) {
                    rtt = Math.max(0, arrivalNanos - sent - NtpTime.compactToNanos(block.delaySinceLastSenderReport()));
                    measured = rtt;
                    rttNanos = rtt;
                }
            }
            stream.onReceptionReport(block, rtt);
            local.add(block);
        }
        return measured;
    }

    /// Applies an extended report: remembers receiver reference times to answer, measures round trips from
    /// answered ones. Called under the lock.
    private void onExtendedReport(ExtendedReport report, long arrivalNanos) {
        for (var block : report.blocks()) {
            switch (block) {
                case ExtendedReport.ReceiverReferenceTime(var ntp) ->
                        peerReferenceTimes.put(report.ssrc(), new long[]{NtpTime.compact(ntp), arrivalNanos});
                case ExtendedReport.Dlrr(var entries) -> {
                    for (var entry : entries) {
                        if (entry.ssrc() != feedbackSsrc() && entry.ssrc() != localSsrc) {
                            continue;
                        }
                        var sent = referenceTimesSent.get(entry.lastReceiverReport());
                        if (sent == null) {
                            continue;
                        }
                        var rtt = Math.max(0, arrivalNanos - sent
                                - NtpTime.compactToNanos(entry.delaySinceLastReceiverReport()));
                        rttNanos = rtt;
                        for (var stream : receiveStreams) {
                            stream.onReceiverRtt(rtt);
                        }
                    }
                }
                case ExtendedReport.UnknownBlock ignored -> {
                }
            }
        }
    }

    private RtpSendStream sendStreamOf(long ssrc) {
        for (var stream : sendStreams) {
            if (stream.ownsSsrc(ssrc)) {
                return stream;
            }
        }
        return null;
    }

    /// Sends feedback the receive path generated, as the RTCP configuration allows, logging failures.
    private void sendFeedbackQuietly(List<RtcpPacket> feedback) {
        if (feedback.isEmpty()) {
            return;
        }
        try {
            sendFeedbackNow(feedback);
        } catch (IOException exception) {
            LOGGER.log(Level.DEBUG, "could not send RTCP feedback", exception);
        }
    }

    /// Sends feedback now as a reduced-size or early compound packet, or queues it for the next regular report when
    /// AVPF timing does not allow an early one.
    void sendFeedbackNow(List<RtcpPacket> feedback) throws IOException {
        List<RtcpPacket> compound;
        lock.lock();
        try {
            if (closed) {
                return;
            }
            var now = clock.nanos();
            if (rtcpConfig.reducedSize()) {
                compound = feedback;
            } else if (rtcpScheduler.tryEarly(now, members(now), senders(now), weSent(now))) {
                compound = new ArrayList<>(feedback.size() + 2);
                compound.add(new ReceiverReport(feedbackSsrc(), List.of()));
                compound.add(SourceDescription.ofCname(feedbackSsrc(), cname));
                compound.addAll(feedback);
            } else {
                pendingFeedback.addAll(feedback);
                return;
            }
        } finally {
            lock.unlock();
        }
        var size = sendCompound(compound);
        lock.lock();
        try {
            rtcpScheduler.onFeedbackSent(size);
        } finally {
            lock.unlock();
        }
    }

    /// Sends a compound packet, splitting it when larger than [#MAX_COMPOUND_BYTES]; returns the bytes sent.
    private int sendCompound(List<RtcpPacket> compound) throws IOException {
        var total = 0;
        var batch = new ArrayList<RtcpPacket>();
        var batchBytes = 0;
        for (var packet : compound) {
            var length = packet.encodedLength();
            if (!batch.isEmpty() && batchBytes + length > MAX_COMPOUND_BYTES) {
                transport.sendRtcp(RtcpPacket.encodeCompound(batch, transport.protectionOverhead()));
                total += batchBytes;
                batch.clear();
                batchBytes = 0;
                if (!(packet instanceof SenderReport) && !(packet instanceof ReceiverReport)
                        && !rtcpConfig.reducedSize()) {
                    var head = new ReceiverReport(feedbackSsrcLocked(), List.of());
                    batch.add(head);
                    batchBytes += head.encodedLength();
                }
            }
            batch.add(packet);
            batchBytes += length;
        }
        if (!batch.isEmpty()) {
            transport.sendRtcp(RtcpPacket.encodeCompound(batch, transport.protectionOverhead()));
            total += batchBytes;
        }
        return total;
    }

    private long feedbackSsrcLocked() {
        lock.lock();
        try {
            return feedbackSsrc();
        } finally {
            lock.unlock();
        }
    }

    private int members(long now) {
        var members = Math.max(1, sendStreams.size());
        for (var seen : remoteSsrcs.values()) {
            if (now - seen < MEMBER_TIMEOUT_NANOS) {
                members++;
            }
        }
        return members;
    }

    private int senders(long now) {
        var senders = 0;
        var window = 2 * rtcpConfig.minimumInterval().toNanos();
        for (var stream : sendStreams) {
            if (stream.sentSince(now - window)) {
                senders++;
            }
        }
        for (var stream : receiveStreams) {
            var last = stream.lastPacketNanos();
            if (last != Long.MIN_VALUE && now - last < window) {
                senders++;
            }
        }
        return senders;
    }

    private boolean weSent(long now) {
        var window = 2 * rtcpConfig.minimumInterval().toNanos();
        for (var stream : sendStreams) {
            if (stream.sentSince(now - window)) {
                return true;
            }
        }
        return false;
    }

    /// Runs every timer that is due and returns the next deadline. Package-private so tests drive it with a manual
    /// clock.
    long tick() {
        var works = new ArrayList<Map.Entry<RtpReceiveStream, RtpReceiveStream.Work>>();
        List<List<RtcpPacket>> regular = List.of();
        long next;
        lock.lock();
        try {
            if (closed) {
                return Long.MAX_VALUE;
            }
            var now = clock.nanos();
            for (var stream : receiveStreams) {
                var work = new RtpReceiveStream.Work();
                stream.onTick(now, work);
                if (!work.deliveries().isEmpty() || !work.feedback().isEmpty()) {
                    works.add(Map.entry(stream, work));
                }
            }
            if (rtcpScheduler.regularDue(now)) {
                var members = members(now);
                var senders = senders(now);
                var weSent = weSent(now);
                var allowed = rtcpScheduler.trrAllows(now);
                var size = 0;
                if (allowed) {
                    regular = buildRegular(now);
                    for (var compound : regular) {
                        for (var packet : compound) {
                            size += packet.encodedLength();
                        }
                    }
                }
                rtcpScheduler.onRegular(now, size, allowed, members, senders, weSent);
            }
            next = rtcpScheduler.nextRegularNanos();
            for (var stream : receiveStreams) {
                next = Math.min(next, stream.nextDeadline());
            }
        } finally {
            lock.unlock();
        }
        for (var entry : works) {
            sendFeedbackQuietly(entry.getValue().feedback());
            entry.getKey().deliver(entry.getValue().deliveries());
        }
        for (var compound : regular) {
            try {
                sendCompound(compound);
            } catch (IOException exception) {
                LOGGER.log(Level.DEBUG, "could not send an RTCP report", exception);
            }
        }
        return next;
    }

    /// Builds the regular compound packets: reports, source description, extended report and queued feedback.
    /// Called under the lock.
    private List<List<RtcpPacket>> buildRegular(long now) {
        var blocks = new ArrayList<ReceptionReport>();
        for (var stream : receiveStreams) {
            stream.reportBlock(now).ifPresent(blocks::add);
        }
        var ntp = NtpTime.fromInstant(wallClock.instant());
        var window = 2 * rtcpConfig.minimumInterval().toNanos();
        var compound = new ArrayList<RtcpPacket>();
        var reporters = new ArrayList<Long>();
        var first = true;
        for (var stream : sendStreams) {
            if (!stream.sentSince(now - window)) {
                continue;
            }
            var own = first ? List.copyOf(blocks.subList(0, Math.min(31, blocks.size()))) : List.<ReceptionReport>of();
            var report = stream.senderReport(ntp, now, own);
            if (report.isPresent()) {
                compound.add(report.get());
                reporters.add(stream.ssrc());
                if (first) {
                    blocks.subList(0, own.size()).clear();
                }
                first = false;
            }
        }
        if (compound.isEmpty()) {
            var own = List.copyOf(blocks.subList(0, Math.min(31, blocks.size())));
            blocks.subList(0, own.size()).clear();
            compound.add(new ReceiverReport(feedbackSsrc(), own));
            reporters.add(feedbackSsrc());
        } else {
            senderReportsSent.put(NtpTime.compact(ntp), now);
        }
        while (!blocks.isEmpty()) {
            var own = List.copyOf(blocks.subList(0, Math.min(31, blocks.size())));
            blocks.subList(0, own.size()).clear();
            compound.add(new ReceiverReport(feedbackSsrc(), own));
        }
        var chunks = new ArrayList<SourceDescription.Chunk>();
        for (var ssrc : reporters.subList(0, Math.min(31, reporters.size()))) {
            chunks.add(new SourceDescription.Chunk(ssrc, List.of(SourceDescription.Item.cname(cname))));
        }
        compound.add(new SourceDescription(chunks));
        var xrBlocks = new ArrayList<ExtendedReport.Block>();
        if (rtcpConfig.extendedReports() && reporters.size() == 1 && compound.getFirst() instanceof ReceiverReport) {
            xrBlocks.add(new ExtendedReport.ReceiverReferenceTime(ntp));
            referenceTimesSent.put(NtpTime.compact(ntp), now);
        }
        if (!peerReferenceTimes.isEmpty()) {
            var entries = new ArrayList<ExtendedReport.DlrrEntry>();
            for (var entry : peerReferenceTimes.entrySet()) {
                entries.add(new ExtendedReport.DlrrEntry(entry.getKey(), entry.getValue()[0],
                        NtpTime.compactOfNanos(now - entry.getValue()[1])));
            }
            peerReferenceTimes.clear();
            xrBlocks.add(new ExtendedReport.Dlrr(entries));
        }
        if (!xrBlocks.isEmpty()) {
            compound.add(new ExtendedReport(feedbackSsrc(), xrBlocks));
        }
        compound.addAll(pendingFeedback);
        pendingFeedback.clear();
        return List.of(compound);
    }

    private void wakeTimer() {
        if (timerThread != null) {
            LockSupport.unpark(timerThread);
        }
    }

    private void runTimers() {
        while (!closed && !Thread.currentThread().isInterrupted()) {
            long next;
            try {
                next = tick();
            } catch (RuntimeException exception) {
                LOGGER.log(Level.WARNING, "an RTP session timer failed", exception);
                next = clock.nanos() + 100_000_000L;
            }
            var wait = next - clock.nanos();
            if (wait > 0) {
                LockSupport.parkNanos(this, Math.min(wait, 1_000_000_000L));
            }
        }
    }

    @Override
    public String toString() {
        return "RtpSession[cname=" + cname + ", send=" + sendStreams.size() + ", receive=" + receiveStreams.size()
                + (closed ? ", closed" : "") + "]";
    }

    /// Builds an [RtpSession]; every setting has a default.
    public static final class Builder {
        private final SessionTransport transport;
        private MonotonicClock clock;
        private InstantSource wallClock = InstantSource.system();
        private OutgoingPacketScheduler scheduler = OutgoingPacketScheduler.immediate();
        private TransportFeedbackObserver feedbackObserver;
        private Consumer<PacketArrival> arrivalObserver;
        private RtcpConfig rtcp = RtcpConfig.webrtc();
        private String cname;
        private long localSsrc = -1;
        private HeaderExtensionMap extensions = HeaderExtensionMap.empty();
        private ThreadFactory threadFactory = Thread.ofVirtual().name("parley-rtp-", 0).factory();
        private RandomGenerator random = new SplittableRandom();
        private boolean manualTimers;

        private Builder(SessionTransport transport) {
            this.transport = transport;
        }

        /// Sets the clock every time is measured with; by default the system's monotonic clock.
        ///
        /// @param clock the clock
        /// @return this builder
        public Builder clock(MonotonicClock clock) {
            this.clock = Objects.requireNonNull(clock, "clock cannot be null");
            return this;
        }

        /// Sets the wall clock sender reports and reference times are stamped with; by default the system clock.
        ///
        /// @param wallClock the wall clock
        /// @return this builder
        public Builder wallClock(InstantSource wallClock) {
            this.wallClock = Objects.requireNonNull(wallClock, "wallClock cannot be null");
            return this;
        }

        /// Sets the scheduler outgoing packets go through; by default [OutgoingPacketScheduler#immediate()].
        ///
        /// @param scheduler the scheduler, which the session gives its padding source
        /// @return this builder
        public Builder scheduler(OutgoingPacketScheduler scheduler) {
            this.scheduler = Objects.requireNonNull(scheduler, "scheduler cannot be null");
            return this;
        }

        /// Sets the observer of sent packets and congestion feedback; none by default.
        ///
        /// @param observer the observer
        /// @return this builder
        public Builder feedbackObserver(TransportFeedbackObserver observer) {
            this.feedbackObserver = Objects.requireNonNull(observer, "observer cannot be null");
            return this;
        }

        /// Sets the observer of every incoming RTP packet's arrival, called on the transport's reader thread before
        /// the packet is routed; none by default.
        ///
        /// @param observer the observer
        /// @return this builder
        public Builder arrivalObserver(Consumer<PacketArrival> observer) {
            this.arrivalObserver = Objects.requireNonNull(observer, "observer cannot be null");
            return this;
        }

        /// Sets the RTCP timing and shape; [RtcpConfig#webrtc()] by default.
        ///
        /// @param rtcp the configuration
        /// @return this builder
        public Builder rtcp(RtcpConfig rtcp) {
            this.rtcp = Objects.requireNonNull(rtcp, "rtcp cannot be null");
            return this;
        }

        /// Sets the canonical name; a random 16-character name by default, as browsers generate one per
        /// connection.
        ///
        /// @param cname the canonical name
        /// @return this builder
        public Builder cname(String cname) {
            this.cname = Objects.requireNonNull(cname, "cname cannot be null");
            return this;
        }

        /// Sets the SSRC used for reports and feedback while the session has no send stream; random by default.
        ///
        /// @param localSsrc an unsigned 32-bit value
        /// @return this builder
        public Builder localSsrc(long localSsrc) {
            SessionChecks.ssrc(localSsrc, "localSsrc");
            this.localSsrc = localSsrc;
            return this;
        }

        /// Sets the header extension ids of the BUNDLE group, which the demultiplexer reads MID, RID and the
        /// transport-wide sequence number with; none by default.
        ///
        /// @param extensions the extension ids
        /// @return this builder
        public Builder extensions(HeaderExtensionMap extensions) {
            this.extensions = Objects.requireNonNull(extensions, "extensions cannot be null");
            return this;
        }

        /// Sets the factory of the timer thread; virtual threads named `parley-rtp-N` by default.
        ///
        /// @param threadFactory the factory
        /// @return this builder
        public Builder threadFactory(ThreadFactory threadFactory) {
            this.threadFactory = Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
            return this;
        }

        Builder random(RandomGenerator random) {
            this.random = random;
            return this;
        }

        Builder manualTimers() {
            this.manualTimers = true;
            return this;
        }

        /// {@return the session, receiving from its transport and running its timer}
        public RtpSession build() {
            return new RtpSession(this);
        }
    }
}
