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
import com.github.auties00.parley.rtp.rtcp.CongestionControlFeedback;
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
import java.time.Duration;
import java.time.InstantSource;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
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
///         .rtcpListener(packet -> log(packet))
///         .build();
/// var audio = session.createSendStream(SendStreamConfig.builder("0", 0x1234, 111, 48_000)
///         .extensions(bundleExtensions)
///         .build());
/// audio.send(List.of(new RtpSendStream.Payload(opusFrame, false, Map.of())), timestamp,
///         OutgoingPacketScheduler.Priority.AUDIO);
/// }
///
/// # Members and collisions
///
/// The session keeps one table of remote members (RFC 3550 section 6.2.1): every remote SSRC heard in RTP or RTCP,
/// with its CNAME and the receiver reference time it asked to be answered. SSRCs are the peer's to choose, so the
/// table is bounded ([MemberTable#CAPACITY] members, the least recently heard dropped first) and forgets a member
/// silent for [#MEMBER_TIMEOUT_NANOS]. A CNAME is recorded only for a member heard in RTP, bound to a receive stream
/// or that sent a sender report, and the first CNAME of a member wins: a later different one is a third-party SSRC
/// collision, counted and remembered for a while (RFC 3550 section 8.2).
///
/// A remote packet carrying one of the session's own SSRCs is a collision, or a loop of the session's own traffic
/// when it comes with the session's own CNAME. A loop is dropped and counted. A collision moves the local stream to
/// a new random SSRC: the old one is announced in a receiver report, a source description and a BYE, and the
/// configuration's SSRC change listener is told ([SsrcChange]). A stream changes SSRC at most once per
/// [#COLLISION_HOLDOFF_NANOS]; repeated collisions inside it are dropped and counted, so a peer cannot make the
/// session renumber its streams at line rate.
///
/// # Leaving
///
/// [#removeSendStream(RtpSendStream)] and [#close()] announce the leaving SSRCs (media, RTX and FlexFEC) in a compound
/// packet of a receiver report, the CNAME and BYE packets of at most 31 sources each. With more than
/// [#BYE_RECONSIDERATION_MEMBERS] members the BYE waits for the reconsideration timer of RFC 3550 section 6.3.7, so a
/// large session does not flood its members with simultaneous BYEs.
///
/// # Congestion control
///
/// Outgoing packets go through an [OutgoingPacketScheduler] (by default sent immediately); the
/// [OutgoingPacketScheduler.PacketSink] it calls stamps the transport-wide sequence number and the absolute send time
/// at the moment of sending and reports every packet to the [TransportFeedbackObserver], which also receives every
/// transport-wide feedback, RFC 8888 feedback, REMB and reception report. Transport-wide feedback that names no
/// packet this session could have sent is dropped and counted before it reaches the observer. On the receive side
/// every packet's arrival is reported to the arrival observer, from which feedback is generated.
///
/// # Threading
///
/// Every method is thread-safe. Incoming packets are processed on the transport's reader threads; RTCP timing, NACK
/// retries, the reorder delay and delayed BYEs run on one timer thread from the builder's [ThreadFactory]. Listeners
/// are given to the builder, so none can miss an event; they are called on those threads, outside the session's
/// lock, and must not block.
///
/// # Lifecycle
///
/// The session installs itself as the transport's RTP and RTCP receiver when built. [#close()] sends a BYE for every
/// local SSRC, stops the timer thread once any delayed BYE has left, and detaches from the transport; the transport
/// itself stays open, its owner closes it.
///
/// @implNote This implementation cannot tell a loop or a third-party collision by the source transport address, as
/// RFC 3550 section 8.2 does: a BUNDLE transport delivers every packet from the one address ICE selected. It tells a
/// loop by the session's own CNAME instead, and keeps the first CNAME of a contested SSRC.
///
/// @see RtpSendStream
/// @see RtpReceiveStream
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3611.html RFC 3611: RTP Control Protocol Extended Reports (RTCP XR)
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
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
    /// The shortest time between two SSRC changes of one local stream.
    static final long COLLISION_HOLDOFF_NANOS = 5_000_000_000L;
    /// How long a loop of the session's own traffic makes it treat RTP carrying a local SSRC as looped.
    static final long LOOP_MEMORY_NANOS = 30_000_000_000L;
    /// How long a third-party collision is remembered.
    static final long CONFLICT_TIMEOUT_NANOS = 30_000_000_000L;
    /// The third-party collisions remembered at most.
    static final int MAX_CONFLICTS = 64;
    /// The members above which a BYE waits for the reconsideration timer (RFC 3550 section 6.3.7).
    static final int BYE_RECONSIDERATION_MEMBERS = 50;
    /// The most sources one BYE packet names.
    static final int MAX_BYE_SOURCES = 31;
    /// The most receiver reference times one DLRR block answers.
    static final int MAX_DLRR_ENTRIES = 31;
    /// The transport-wide sequence numbers back from the last one sent that feedback may name: half the space.
    static final int FEEDBACK_WINDOW = 0x8000;

    /// What an outgoing packet is, for the statistics.
    enum PacketKind {
        MEDIA, RETRANSMISSION, FEC, PADDING
    }

    /// One packet ready for the scheduler, and the sink the scheduler hands it back to.
    ///
    /// The layout lets the sender stamp the send-time extensions without parsing the packet again; offsets count
    /// from the packet's first byte.
    ///
    /// @param scheduledNanos          when it was handed to the scheduler, so the pacer queue time is measured
    /// @param headerLength            the header length, or `-1` when the layout is unknown and the sender parses
    ///                                the packet
    /// @param payloadLength           the payload length
    /// @param transportSequenceOffset the offset of the transport-wide sequence number value, or `-1`
    /// @param absSendTimeOffset       the offset of the abs-send-time value, or `-1`
    /// @param retained                whether the send stream's history keeps the packet itself for
    ///                                retransmission, so the transport gets a read-only view and protects a copy
    record Outgoing(ByteBuffer buffer, OutgoingPacketScheduler.Priority priority, long ssrc, PacketKind kind,
                    RtpSendStream stream, long scheduledNanos, int headerLength, int payloadLength,
                    int transportSequenceOffset, int absSendTimeOffset, boolean retained)
            implements OutgoingPacketScheduler.PacketSink {
        /// Creates an entry the history does not keep, whose layout the sender finds by parsing the packet.
        Outgoing(ByteBuffer buffer, OutgoingPacketScheduler.Priority priority, long ssrc, PacketKind kind,
                 RtpSendStream stream, long scheduledNanos) {
            this(buffer, priority, ssrc, kind, stream, scheduledNanos, -1, 0, -1, -1, false);
        }

        @Override
        public void send(ByteBuffer plainRtp) throws IOException {
            stream.session().sendNow(this, plainRtp);
        }
    }

    /// A BYE waiting for the reconsideration timer.
    private static final class PendingBye {
        final List<RtcpPacket> compound;
        final long startNanos;
        final int size;
        long dueNanos;
        int byeMembers = 1;

        PendingBye(List<RtcpPacket> compound, long startNanos, int size, long dueNanos) {
            this.compound = compound;
            this.startNanos = startNanos;
            this.size = size;
            this.dueNanos = dueNanos;
        }
    }

    private final SessionTransport transport;
    private final MonotonicClock clock;
    private final InstantSource wallClock;
    private final OutgoingPacketScheduler scheduler;
    private final TransportFeedbackObserver feedbackObserver;
    private final Consumer<PacketArrival> arrivalObserver;
    private final Consumer<? super UnsignaledStream> unsignaledStreamListener;
    private final Consumer<? super RtcpPacket> rtcpListener;
    private final Consumer<? super SsrcChange> ssrcChangedListener;
    private final RtcpConfig rtcpConfig;
    private final String cname;
    private volatile long localSsrc;
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
    private final MemberTable members = new MemberTable(MEMBER_TIMEOUT_NANOS);
    private final List<RtcpPacket> pendingFeedback = new ArrayList<>();
    private final Map<Long, Long> unsignaledReported = boundedMap();
    private final Map<Long, Long> conflicts = new LinkedHashMap<>();
    private final Map<Long, Long> lastSsrcChange = new LinkedHashMap<>();
    private final ArrayDeque<PendingBye> pendingByes = new ArrayDeque<>();
    private int transportSequence;
    private boolean transportSequenceUsed;
    private volatile long rttNanos = -1;
    private volatile boolean closed;
    private final Thread timerThread;
    private long malformedRtp;
    private long malformedRtcp;
    private long unhandledRtp;
    private long loopedPackets;
    private long collisions;
    private long ignoredCollisions;
    private long thirdPartyCollisions;
    private long droppedFeedback;
    private long lastLoopNanos = Long.MIN_VALUE;

    private RtpSession(Builder builder) {
        this.transport = builder.transport;
        this.clock = builder.clock != null ? builder.clock : MonotonicClock.system();
        this.wallClock = builder.wallClock;
        this.scheduler = builder.scheduler;
        this.feedbackObserver = builder.feedbackObserver;
        this.arrivalObserver = builder.arrivalObserver;
        this.unsignaledStreamListener = builder.unsignaledStreamListener;
        this.rtcpListener = builder.rtcpListener;
        this.ssrcChangedListener = builder.ssrcChangedListener;
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
            var stream = new RtpSendStream(this, config, random.nextInt(1 << 15));
            for (var existing : sendStreams) {
                for (var ssrc : stream.ssrcs()) {
                    if (existing.ownsSsrc(ssrc)) {
                        throw new IllegalArgumentException("SSRC already used by " + existing);
                    }
                }
            }
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

    /// Removes a send stream; it sends nothing more and its SSRCs (media, RTX and FlexFEC) are announced in a
    /// compound packet of a receiver report, the CNAME and a BYE, delayed by the reconsideration timer in a session
    /// of more than [#BYE_RECONSIDERATION_MEMBERS] members.
    ///
    /// The stream is marked removed under the session's lock, so a send racing the removal on another thread is
    /// dropped rather than sent after the BYE.
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
            stream.markRemoved();
            bye = leaving(stream.ssrcs(), feedbackSsrc());
            if (delayBye(bye)) {
                return;
            }
        } finally {
            lock.unlock();
        }
        sendCompound(bye);
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

    /// Sends RTCP packets now, such as feedback generated outside the session.
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

    /// {@return the CNAME a remote SSRC announced in its source descriptions, while it is a member}
    ///
    /// @param ssrc the remote SSRC
    public Optional<String> remoteCname(long ssrc) {
        lock.lock();
        try {
            return members.peek(ssrc).map(member -> member.cname);
        } finally {
            lock.unlock();
        }
    }

    /// {@return the latest round-trip time measured, from reception reports or extended reports; empty before the
    /// first measurement}
    public Optional<Duration> roundTripTime() {
        var rtt = rttNanos;
        return rtt < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(rtt));
    }

    /// Closes the session: announces every local SSRC in a BYE, stops receiving, and stops the timer thread once a
    /// BYE delayed by reconsideration has left. The transport stays open. Calling it again does nothing.
    @Override
    public void close() {
        List<RtcpPacket> bye;
        boolean delayed;
        lock.lock();
        try {
            if (closed) {
                return;
            }
            var ssrcs = new ArrayList<Long>();
            for (var stream : sendStreams) {
                stream.markRemoved();
                ssrcs.addAll(stream.ssrcs());
            }
            if (ssrcs.isEmpty()) {
                ssrcs.add(localSsrc);
            }
            bye = leaving(ssrcs, feedbackSsrc());
            delayed = timerThread != null && delayBye(bye);
            closed = true;
        } finally {
            lock.unlock();
        }
        transport.setRtpReceiver((packet, arrival) -> {
        });
        transport.setRtcpReceiver((packet, arrival) -> {
        });
        if (!delayed) {
            try {
                sendCompound(bye);
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "could not send the closing BYE", exception);
            }
        }
        wakeTimer();
    }

    /// {@return the compound packet announcing that `ssrcs` leave: a receiver report and the CNAME of
    /// `reporterSsrc`, then BYE packets of at most [#MAX_BYE_SOURCES] sources each}
    private List<RtcpPacket> leaving(List<Long> ssrcs, long reporterSsrc) {
        var compound = new ArrayList<RtcpPacket>();
        compound.add(new ReceiverReport(reporterSsrc, List.of()));
        compound.add(SourceDescription.ofCname(reporterSsrc, cname));
        for (var from = 0; from < ssrcs.size(); from += MAX_BYE_SOURCES) {
            compound.add(new Bye(List.copyOf(ssrcs.subList(from, Math.min(ssrcs.size(), from + MAX_BYE_SOURCES))),
                    Optional.empty()));
        }
        return compound;
    }

    /// Queues a BYE for the reconsideration timer when the session has more than
    /// [#BYE_RECONSIDERATION_MEMBERS] members. Called under the lock.
    ///
    /// @return whether the BYE was queued
    private boolean delayBye(List<RtcpPacket> compound) {
        var now = clock.nanos();
        if (members(now) <= BYE_RECONSIDERATION_MEMBERS) {
            return false;
        }
        var size = 0;
        for (var packet : compound) {
            size += packet.encodedLength();
        }
        pendingByes.addLast(new PendingBye(compound, now, size, now + rtcpScheduler.byeInterval(1, size)));
        wakeTimer();
        return true;
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

    long loopedPacketCount() {
        return loopedPackets;
    }

    long collisionCount() {
        return collisions;
    }

    long ignoredCollisionCount() {
        return ignoredCollisions;
    }

    long thirdPartyCollisionCount() {
        return thirdPartyCollisions;
    }

    long droppedFeedbackCount() {
        return droppedFeedback;
    }

    int memberTableSize() {
        return members.size();
    }

    int pendingByeCount() {
        return pendingByes.size();
    }

    /// Moves a local stream from one of its SSRCs to a new one: sends the BYE compound for the old SSRC, replaces it
    /// and tells the SSRC change listener.
    ///
    /// @throws IOException if sending the BYE fails; the change is made anyway
    void changeSsrc(RtpSendStream stream, long oldSsrc, long newSsrc) throws IOException {
        List<RtcpPacket> bye;
        lock.lock();
        try {
            checkOpen();
            if (stream.isRemoved() || !sendStreams.contains(stream)) {
                throw new IllegalStateException("the stream was removed");
            }
            if (!stream.ownsSsrc(oldSsrc)) {
                throw new IllegalArgumentException("the stream does not use SSRC " + oldSsrc);
            }
            if (oldSsrc == newSsrc) {
                return;
            }
            if (sendStreamOf(newSsrc) != null || newSsrc == localSsrc) {
                throw new IllegalArgumentException("SSRC already used locally: " + newSsrc);
            }
            bye = leaving(List.of(oldSsrc), oldSsrc);
            stream.replaceSsrc(oldSsrc, newSsrc);
            lastSsrcChange.put(newSsrc, clock.nanos());
        } finally {
            lock.unlock();
        }
        notifySsrcChange(new SsrcChange(oldSsrc, newSsrc));
        sendCompound(bye);
    }

    private void notifySsrcChange(SsrcChange change) {
        try {
            ssrcChangedListener.accept(change);
        } catch (RuntimeException exception) {
            LOGGER.log(Level.WARNING, "the SSRC change listener failed", exception);
        }
    }

    /// Reacts to a remote packet carrying a local SSRC. Called under the lock.
    ///
    /// @param ssrc     the local SSRC
    /// @param looped   whether the packet came with the session's own CNAME
    /// @param nowNanos the time
    /// @return the BYE compound and the change to report, when the stream moves to a new SSRC
    private Optional<Map.Entry<List<RtcpPacket>, SsrcChange>> onLocalSsrc(long ssrc, boolean looped, long nowNanos) {
        if (looped || (lastLoopNanos != Long.MIN_VALUE && nowNanos - lastLoopNanos < LOOP_MEMORY_NANOS)) {
            if (looped) {
                lastLoopNanos = nowNanos;
            }
            loopedPackets++;
            return Optional.empty();
        }
        var last = lastSsrcChange.get(ssrc);
        if (last != null && nowNanos - last < COLLISION_HOLDOFF_NANOS) {
            ignoredCollisions++;
            return Optional.empty();
        }
        collisions++;
        var replacement = newSsrc();
        var bye = leaving(List.of(ssrc), ssrc);
        var stream = sendStreamOf(ssrc);
        if (stream != null) {
            stream.replaceSsrc(ssrc, replacement);
        } else {
            localSsrc = replacement;
        }
        lastSsrcChange.put(replacement, nowNanos);
        while (lastSsrcChange.size() > MAX_CONFLICTS) {
            lastSsrcChange.remove(lastSsrcChange.keySet().iterator().next());
        }
        return Optional.of(Map.entry(bye, new SsrcChange(ssrc, replacement)));
    }

    /// {@return a random SSRC no local stream and no known member uses}
    private long newSsrc() {
        while (true) {
            var candidate = random.nextLong(1, 1L << 32);
            if (candidate != localSsrc && sendStreamOf(candidate) == null && members.peek(candidate).isEmpty()) {
                return candidate;
            }
        }
    }

    /// {@return whether `ssrc` is one of the session's own SSRCs}
    private boolean isLocal(long ssrc) {
        return ssrc == localSsrc || sendStreamOf(ssrc) != null;
    }

    /// Hands packets to the scheduler; with the immediate scheduler, sends them and reports the first failure.
    void dispatch(List<Outgoing> outgoing) throws IOException {
        IOException failure = null;
        for (var index = 0; index < outgoing.size(); index++) {
            var packet = outgoing.get(index);
            if (scheduler == ImmediateScheduler.INSTANCE) {
                try {
                    sendNow(packet, packet.buffer());
                } catch (IOException exception) {
                    if (failure == null) {
                        failure = exception;
                    } else {
                        failure.addSuppressed(exception);
                    }
                }
            } else {
                scheduler.schedule(packet.buffer(), packet.priority(), packet.ssrc(), packet);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    /// Stamps the send-time extensions, protects and sends one packet, then accounts for it.
    void sendNow(Outgoing packet, ByteBuffer buffer) throws IOException {
        int sequence = -1;
        int size;
        int payloadBytes;
        int headerBytes;
        int rtpSequence;
        long sentAt;
        sendLock.lock();
        try {
            sentAt = clock.nanos();
            int transportSequenceIndex;
            int absSendTimeIndex;
            if (packet.headerLength() >= 0) {
                var start = buffer.position();
                transportSequenceIndex = packet.transportSequenceOffset() < 0 ? -1
                        : start + packet.transportSequenceOffset();
                absSendTimeIndex = packet.absSendTimeOffset() < 0 ? -1 : start + packet.absSendTimeOffset();
                size = buffer.remaining();
                payloadBytes = packet.payloadLength();
                rtpSequence = buffer.getShort(start + 2) & 0xFFFF;
            } else {
                RtpPacket view;
                try {
                    view = RtpPacket.parse(buffer);
                } catch (RtpFormatException exception) {
                    throw new IOException("the scheduler returned a malformed packet", exception);
                }
                var twcc = packet.stream().transportSequenceId();
                transportSequenceIndex = twcc.isPresent() ? view.extensionOffset(twcc.getAsInt()).orElse(-1) : -1;
                var abs = packet.stream().absSendTimeId();
                absSendTimeIndex = abs.isPresent() ? view.extensionOffset(abs.getAsInt()).orElse(-1) : -1;
                size = view.length();
                payloadBytes = view.payloadLength();
                rtpSequence = view.sequence();
            }
            if (transportSequenceIndex >= 0) {
                sequence = transportSequence;
                transportSequence = (transportSequence + 1) & 0xFFFF;
                transportSequenceUsed = true;
                TransportSequenceNumber.stamp(buffer, transportSequenceIndex, sequence);
            }
            if (absSendTimeIndex >= 0) {
                AbsSendTime.stamp(buffer, absSendTimeIndex, sentAt);
            }
            headerBytes = size - payloadBytes;
            // A packet the history keeps must survive protection: SRTP protects a copy of a read-only view
            transport.sendRtp(packet.retained() ? buffer.asReadOnlyBuffer() : buffer);
        } finally {
            sendLock.unlock();
        }
        lock.lock();
        try {
            packet.stream().onSent(packet.kind(), payloadBytes, headerBytes, sentAt, sentAt - packet.scheduledNanos());
        } finally {
            lock.unlock();
        }
        var observer = feedbackObserver;
        if (observer != null) {
            observer.onPacketSent(new SentPacket(sequence, size, sentAt, packet.priority(),
                    packet.kind() == PacketKind.RETRANSMISSION || packet.kind() == PacketKind.PADDING
                            && packet.ssrc() != packet.stream().ssrc(), packet.ssrc(), rtpSequence));
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
            sendNow(packet, packet.buffer());
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
        Optional<Map.Entry<List<RtcpPacket>, SsrcChange>> collision = Optional.empty();
        var own = false;
        lock.lock();
        try {
            if (isLocal(packet.ssrc())) {
                own = true;
                collision = onLocalSsrc(packet.ssrc(), false, arrivalNanos);
            }
        } finally {
            lock.unlock();
        }
        if (own) {
            collision.ifPresent(this::announceCollision);
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
        stream.deliver(work);
        if (stream.nextDeadline() != Long.MAX_VALUE) {
            wakeTimer();
        }
    }

    /// Sends the BYE of a collision and tells the listener.
    private void announceCollision(Map.Entry<List<RtcpPacket>, SsrcChange> collision) {
        notifySsrcChange(collision.getValue());
        try {
            sendCompound(collision.getKey());
        } catch (IOException exception) {
            LOGGER.log(Level.DEBUG, "could not send the BYE of a colliding SSRC", exception);
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
        return new PacketArrival(packet.ssrc(), packet.sequence(), packet.length(), transportSequenceValue, absValue,
                arrivalNanos);
    }

    private Optional<RtpReceiveStream> route(RtpPacket packet, long arrivalNanos, RtpReceiveStream.Work work) {
        UnsignaledStream unsignaled;
        lock.lock();
        try {
            members.heard(packet.ssrc(), arrivalNanos).sentRtp = true;
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
            unsignaledStreamListener.accept(unsignaled);
        } catch (RuntimeException exception) {
            LOGGER.log(Level.WARNING, "the unsignaled-stream listener failed", exception);
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

    /// {@return whether a remote SSRC may have its CNAME recorded: heard in RTP, sent a sender report, or bound to a
    /// receive stream}. Called under the lock.
    private boolean mayRecordCname(long ssrc, MemberTable.Member member) {
        if (member.sentRtp || member.sentSenderReport) {
            return true;
        }
        if (demuxer.boundTarget(ssrc).isPresent()) {
            return true;
        }
        for (var stream : receiveStreams) {
            if (stream.ownsSsrc(ssrc)) {
                return true;
            }
        }
        return false;
    }

    /// {@return whether a compound packet carries the session's own CNAME for `ssrc`, the mark of a loop}
    private boolean carriesOwnCname(List<RtcpPacket> packets, long ssrc) {
        for (var packet : packets) {
            if (packet instanceof SourceDescription description) {
                for (var chunk : description.chunks()) {
                    if (chunk.ssrc() == ssrc
                            && chunk.find(SourceDescription.Item.CNAME).map(cname::equals).orElse(false)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// {@return whether transport-wide feedback names packets this session could have sent: its base is at most
    /// [#FEEDBACK_WINDOW] behind the last transport-wide sequence number sent}. Called under the lock.
    private boolean plausible(TransportFeedback feedback) {
        if (!transportSequenceUsed) {
            return false;
        }
        var last = (transportSequence - 1) & 0xFFFF;
        var behind = (last - feedback.baseSequence()) & 0xFFFF;
        return behind < FEEDBACK_WINDOW;
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
        var observed = new ArrayList<RtcpPacket>();
        var reports = new ArrayList<ReceptionReport>();
        var changes = new ArrayList<Map.Entry<List<RtcpPacket>, SsrcChange>>();
        var reportRtt = -1L;
        var observer = feedbackObserver;
        lock.lock();
        try {
            for (var packet : packets) {
                switch (packet) {
                    case SenderReport report -> {
                        if (isLocal(report.ssrc())) {
                            onLocalSsrc(report.ssrc(), carriesOwnCname(packets, report.ssrc()), arrivalNanos)
                                    .ifPresent(changes::add);
                            continue;
                        }
                        members.heard(report.ssrc(), arrivalNanos).sentSenderReport = true;
                        for (var stream : receiveStreams) {
                            if (stream.mediaSsrc().isPresent() && stream.mediaSsrc().getAsLong() == report.ssrc()) {
                                stream.onSenderReport(report, arrivalNanos);
                            }
                        }
                        reportRtt = Math.max(reportRtt, onReceptionReports(report.reports(), arrivalNanos, reports));
                    }
                    case ReceiverReport report -> {
                        if (isLocal(report.ssrc())) {
                            onLocalSsrc(report.ssrc(), carriesOwnCname(packets, report.ssrc()), arrivalNanos)
                                    .ifPresent(changes::add);
                            continue;
                        }
                        members.heard(report.ssrc(), arrivalNanos);
                        reportRtt = Math.max(reportRtt, onReceptionReports(report.reports(), arrivalNanos, reports));
                    }
                    case SourceDescription description -> onSourceDescription(description, arrivalNanos);
                    case Bye bye -> {
                        for (var ssrc : bye.ssrcs()) {
                            if (isLocal(ssrc)) {
                                continue;
                            }
                            members.remove(ssrc);
                            demuxer.unbind(ssrc);
                        }
                        for (var pending : pendingByes) {
                            pending.byeMembers++;
                        }
                        forwarded.add(bye);
                    }
                    case ExtendedReport report -> {
                        if (!isLocal(report.ssrc())) {
                            onExtendedReport(report, arrivalNanos);
                        }
                    }
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
                    case Remb remb -> (observer == null ? forwarded : observed).add(remb);
                    case TransportFeedback feedback -> {
                        if (observer == null) {
                            forwarded.add(feedback);
                        } else if (plausible(feedback)) {
                            observed.add(feedback);
                        } else {
                            droppedFeedback++;
                        }
                    }
                    case CongestionControlFeedback feedback ->
                            (observer == null ? forwarded : observed).add(feedback);
                    default -> forwarded.add(packet);
                }
            }
        } finally {
            lock.unlock();
        }
        changes.forEach(this::announceCollision);
        if (observer != null) {
            for (var packet : observed) {
                switch (packet) {
                    case TransportFeedback feedback -> observer.onTransportFeedback(feedback, arrivalNanos);
                    case CongestionControlFeedback feedback ->
                            observer.onCongestionControlFeedback(feedback, arrivalNanos);
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

    /// Records the CNAMEs of a source description. Called under the lock.
    private void onSourceDescription(SourceDescription description, long arrivalNanos) {
        for (var chunk : description.chunks()) {
            var announced = chunk.find(SourceDescription.Item.CNAME);
            if (announced.isEmpty() || isLocal(chunk.ssrc())) {
                continue;
            }
            var member = members.peek(chunk.ssrc());
            if (member.isEmpty() || !mayRecordCname(chunk.ssrc(), member.get())) {
                continue;
            }
            var known = member.get().cname;
            if (known == null) {
                member.get().cname = announced.get();
            } else if (!known.equals(announced.get())) {
                thirdPartyCollisions++;
                conflicts.put(chunk.ssrc(), arrivalNanos);
                while (conflicts.size() > MAX_CONFLICTS) {
                    conflicts.remove(conflicts.keySet().iterator().next());
                }
            }
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

    /// Applies an extended report: remembers the receiver reference time of a member to answer, measures round
    /// trips from answered ones. Called under the lock.
    private void onExtendedReport(ExtendedReport report, long arrivalNanos) {
        for (var block : report.blocks()) {
            switch (block) {
                case ExtendedReport.ReceiverReferenceTime(var ntp) -> {
                    var member = members.heard(report.ssrc(), arrivalNanos);
                    member.referenceTimeNtpCompact = NtpTime.compact(ntp);
                    member.referenceTimeArrivalNanos = arrivalNanos;
                }
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
        return Math.max(1, sendStreams.size()) + members.activeCount(now);
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
        var byes = new ArrayList<List<RtcpPacket>>();
        long next;
        lock.lock();
        try {
            var now = clock.nanos();
            next = dueByes(now, byes);
            if (!closed) {
                members.expire(now);
                conflicts.values().removeIf(seen -> now - seen >= CONFLICT_TIMEOUT_NANOS);
                for (var stream : receiveStreams) {
                    var work = new RtpReceiveStream.Work();
                    stream.onTick(now, work);
                    if (!work.isEmpty()) {
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
                next = Math.min(next, rtcpScheduler.nextRegularNanos());
                for (var stream : receiveStreams) {
                    next = Math.min(next, stream.nextDeadline());
                }
            }
        } finally {
            lock.unlock();
        }
        for (var compound : byes) {
            try {
                sendCompound(compound);
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "could not send a delayed BYE", exception);
            }
        }
        for (var entry : works) {
            sendFeedbackQuietly(entry.getValue().feedback());
            entry.getKey().deliver(entry.getValue());
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

    /// Takes the BYEs whose reconsidered timer expired (RFC 3550 section 6.3.7: the interval is recomputed with
    /// the BYEs received meanwhile, and the BYE leaves only when the recomputed time has passed) and returns the
    /// next BYE deadline. Called under the lock.
    private long dueByes(long nowNanos, List<List<RtcpPacket>> out) {
        var next = Long.MAX_VALUE;
        for (var iterator = pendingByes.iterator(); iterator.hasNext(); ) {
            var pending = iterator.next();
            if (pending.dueNanos > nowNanos) {
                next = Math.min(next, pending.dueNanos);
                continue;
            }
            var reconsidered = pending.startNanos + rtcpScheduler.byeInterval(pending.byeMembers, pending.size);
            if (reconsidered > nowNanos) {
                pending.dueNanos = reconsidered;
                next = Math.min(next, reconsidered);
                continue;
            }
            iterator.remove();
            out.add(pending.compound);
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
        var referenceTimes = members.takeReferenceTimes(MAX_DLRR_ENTRIES);
        if (!referenceTimes.isEmpty()) {
            var entries = new ArrayList<ExtendedReport.DlrrEntry>();
            for (var reference : referenceTimes) {
                entries.add(new ExtendedReport.DlrrEntry(reference.ssrc(), reference.ntpCompact(),
                        NtpTime.compactOfNanos(now - reference.arrivalNanos())));
            }
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

    private boolean timerDone() {
        lock.lock();
        try {
            return closed && pendingByes.isEmpty();
        } finally {
            lock.unlock();
        }
    }

    private void runTimers() {
        while (!timerDone() && !Thread.currentThread().isInterrupted()) {
            long next;
            try {
                next = tick();
            } catch (RuntimeException exception) {
                LOGGER.log(Level.WARNING, "an RTP session timer failed", exception);
                next = clock.nanos() + 100_000_000L;
            }
            if (timerDone()) {
                return;
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
        private Consumer<? super UnsignaledStream> unsignaledStreamListener = _ -> {
        };
        private Consumer<? super RtcpPacket> rtcpListener = _ -> {
        };
        private Consumer<? super SsrcChange> ssrcChangedListener = _ -> {
        };
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

        /// Sets the listener told of incoming SSRCs no receive stream claims; it may create a receive stream for one,
        /// after which the packet that triggered the report is routed again. Each SSRC is reported at most once a
        /// second. None by default.
        ///
        /// @param listener the listener, called on the transport's reader thread
        /// @return this builder
        public Builder unsignaledStreamListener(Consumer<? super UnsignaledStream> listener) {
            this.unsignaledStreamListener = Objects.requireNonNull(listener, "listener cannot be null");
            return this;
        }

        /// Sets the listener told of every received RTCP packet the session does not consume: application data,
        /// BYEs, unknown packets, and REMB, transport-wide or RFC 8888 feedback when no feedback observer was given.
        /// None by default.
        ///
        /// @param listener the listener, called on the transport's reader thread
        /// @return this builder
        public Builder rtcpListener(Consumer<? super RtcpPacket> listener) {
            this.rtcpListener = Objects.requireNonNull(listener, "listener cannot be null");
            return this;
        }

        /// Sets the listener told when a local SSRC changes after a collision or
        /// [RtpSendStream#changeSsrc(long)]. None by default.
        ///
        /// @param listener the listener, called on the thread that detected the change, after the session's lock
        ///                 was released
        /// @return this builder
        public Builder ssrcChangedListener(Consumer<? super SsrcChange> listener) {
            this.ssrcChangedListener = Objects.requireNonNull(listener, "listener cannot be null");
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
