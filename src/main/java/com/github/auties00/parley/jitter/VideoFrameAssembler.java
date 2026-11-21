package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.Depacketizer;
import com.github.auties00.parley.payload.PacketBoundaries;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.payload.PayloadFormatException;
import com.github.auties00.parley.rtp.RtpPacket;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/// Assembles the packets of one incoming video stream into frames and releases them, in decode order, once they are
/// decodable.
///
/// The receiving thread [inserts][#insert(RtpPacket,long)] packets as they arrive, in any order; the decoding thread
/// calls [#next()], which blocks until a frame is ready. Each released frame's metadata carries its frame id and the
/// ids of the frames it references, all of which were released before it.
///
/// {@snippet lang = java :
/// var assembler = VideoFrameAssembler.create(PayloadFormat.of(Codec.vp8()), VideoAssemblerConfig.defaults(),
///         feedbackSink);
/// receiveStream.setPacketReceiver(packet -> assembler.insert(packet, clock.nanos()));
/// Thread.ofVirtual().start(() -> {
///     while (true) {
///         decoder.decode(assembler.next());
///     }
/// });
/// }
///
/// # Frames
///
/// Packets are grouped into frames by RTP timestamp, the start and end bits of the payload format (or of the
/// dependency descriptor) and the marker bit. The references of each frame are found per format (see the frame ids
/// in [com.github.auties00.parley.media.FrameMetadata]): a frame is decodable once it is a keyframe or every frame it
/// references was released. Frames are released in increasing frame id; a decodable frame waits while an older frame
/// or an older missing packet may still arrive, for at most the wait budget, and a frame older than one already
/// released is dropped.
///
/// # Loss
///
/// When a sequence number is skipped, the missing packets are requested with NACKs through the [FeedbackSink] (when
/// the configuration enables retransmissions), again every round-trip time, up to the configured limit. The wait
/// budget is three round-trip times, within the configured bounds; a packet still missing after it is given up, and
/// a frame that still cannot be decoded after it is dropped. A dropped frame, a malformed one, or too many buffered
/// packets trigger a keyframe request, at most one per configured interval.
///
/// # Threading
///
/// All methods are safe to call from any thread; [#next()] is meant for one consumer thread. Feedback is sent
/// outside the assembler's lock, on the thread that inserted a packet or asked for a frame.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
/// @spec https://www.w3.org/TR/webrtc-stats/ W3C Identifiers for WebRTC's Statistics API
public final class VideoFrameAssembler implements AutoCloseable {
    /// The longest a blocked [#next()] waits before checking timers again, in nanoseconds.
    private static final long MAX_WAIT_NANOS = TimeUnit.MILLISECONDS.toNanos(10);

    /// The longest sequence number gap treated as loss rather than a stream restart.
    private static final int MAX_GAP = 1000;

    /// The frame end sequence numbers remembered for frame start detection.
    private static final int REMEMBERED_ENDS = 256;

    /// The released frame ids remembered for reference checks.
    private static final int REMEMBERED_RELEASES = 1024;

    /// The settings.
    private final VideoAssemblerConfig config;

    /// The clock.
    private final MonotonicClock clock;

    /// The depacketizer.
    private final Depacketizer depacketizer;

    /// The feedback sink.
    private final FeedbackSink feedback;

    /// The reference finder.
    private final ReferenceFinder references;

    /// The lock that guards every field below.
    private final ReentrantLock lock = new ReentrantLock();

    /// Signalled on every insert and on close.
    private final Condition changed = lock.newCondition();

    /// The buffered packets by unwrapped sequence number.
    private final TreeMap<Long, Slot> packets = new TreeMap<>();

    /// The missing sequence numbers and their request state.
    private final TreeMap<Long, Missing> missing = new TreeMap<>();

    /// The sequence numbers the assembler gave up waiting for.
    private final TreeSet<Long> lost = new TreeSet<>();

    /// The sequence numbers that ended an assembled frame.
    private final TreeSet<Long> frameEnds = new TreeSet<>();

    /// The complete frames waiting for release, by frame id.
    private final TreeMap<Long, Pending> pending = new TreeMap<>();

    /// The ids of released frames.
    private final TreeSet<Long> released = new TreeSet<>();

    /// The frames ready for [#next()].
    private final ArrayDeque<EncodedFrame> ready = new ArrayDeque<>();

    /// The unwrapper of sequence numbers.
    private final Unwrapper sequences = new Unwrapper(16);

    /// The current round-trip time in nanoseconds.
    private long rttNanos;

    /// The highest unwrapped sequence number seen, or `-1`.
    private long highestSequence = -1;

    /// The sequence number below which packets are obsolete: the first one of the stream, then the first one of the
    /// last released frame; `-1` before the first packet.
    private long floorSequence = -1;

    /// The id of the last released frame, or `Long.MIN_VALUE`.
    private long lastReleasedId = Long.MIN_VALUE;

    /// Whether a keyframe request is due.
    private boolean keyframeNeeded;

    /// When the last keyframe request was sent, or `Long.MIN_VALUE`.
    private long lastKeyframeRequest = Long.MIN_VALUE;

    /// When the last frame was released, or `Long.MIN_VALUE`.
    private long lastReleaseNanos = Long.MIN_VALUE;

    /// The moving average of the gaps between releases, in nanoseconds, or `-1`.
    private double averageGapNanos = -1;

    /// Whether the assembler is closed.
    private boolean closed;

    /// The packets inserted.
    private long packetsReceived;

    /// The packets dropped.
    private long packetsDiscarded;

    /// The packets that arrived after a NACK.
    private long packetsRecovered;

    /// The packets given up.
    private long packetsLost;

    /// The NACK requests sent.
    private long nackCount;

    /// The keyframe requests sent.
    private long keyframeRequests;

    /// The frames assembled.
    private long framesReceived;

    /// The frames dropped.
    private long framesDropped;

    /// The keyframes released.
    private long keyframesReleased;

    /// The summed time from first arrival to release.
    private long jitterBufferDelayNanos;

    /// The frames released.
    private long emittedCount;

    /// The freezes.
    private long freezeCount;

    /// The summed freeze durations.
    private long freezeNanos;

    /// One buffered packet.
    ///
    /// @param packet     the packet, a copy that owns its bytes
    /// @param arrival    the arrival time
    /// @param boundaries what the packet says about its frame
    private record Slot(RtpPacket packet, long arrival, PacketBoundaries boundaries) {
    }

    /// The request state of one missing packet.
    private static final class Missing {
        /// When the packet was found missing.
        private final long since;

        /// When it was last requested, or `Long.MIN_VALUE`.
        private long lastRequest = Long.MIN_VALUE;

        /// How many times it was requested.
        private int requests;

        /// Creates the state.
        Missing(long since) {
            this.since = since;
        }
    }

    /// One complete frame waiting for release.
    ///
    /// @param frame         the frame
    /// @param identity      its id and reference rule
    /// @param firstSequence the unwrapped sequence number of its first packet
    /// @param firstArrival  the arrival time of its first packet
    /// @param completed     when it was assembled
    private record Pending(EncodedFrame frame, ReferenceFinder.Identity identity, long firstSequence,
                           long firstArrival, long completed) {
    }

    /// Creates an assembler.
    private VideoFrameAssembler(PayloadFormat format, VideoAssemblerConfig config, FeedbackSink feedback) {
        this.config = config;
        this.clock = config.clock();
        this.depacketizer = format.depacketizer(config.depacketizer());
        this.feedback = feedback;
        this.references = new ReferenceFinder(format);
        this.rttNanos = config.initialRtt().toNanos();
    }

    /// Creates an assembler for one incoming video stream.
    ///
    /// @param format   the stream's payload format, a video format
    /// @param config   the settings
    /// @param feedback where keyframe and retransmission requests go
    /// @return the assembler
    /// @throws IllegalArgumentException if `format` is not a video format
    public static VideoFrameAssembler create(PayloadFormat format, VideoAssemblerConfig config, FeedbackSink feedback) {
        Objects.requireNonNull(format, "format cannot be null");
        Objects.requireNonNull(config, "config cannot be null");
        Objects.requireNonNull(feedback, "feedback cannot be null");
        if (format.kind() != MediaKind.VIDEO) {
            throw new IllegalArgumentException("not a video format: " + format);
        }
        return new VideoFrameAssembler(format, config, feedback);
    }

    /// Inserts a packet of the stream.
    ///
    /// The assembler keeps a copy, so the packet's buffer may be reused once this returns. A malformed or duplicate
    /// packet, or one older than the last released frame, is counted and dropped. Feedback the packet triggers (a NACK
    /// for a gap it reveals) is sent before this returns.
    ///
    /// @param packet       the packet
    /// @param arrivalNanos the arrival time, from the assembler's clock
    public void insert(RtpPacket packet, long arrivalNanos) {
        Objects.requireNonNull(packet, "packet cannot be null");
        List<Runnable> actions;
        lock.lock();
        try {
            if (closed) {
                return;
            }
            packetsReceived++;
            var boundaries = depacketizer.inspect(packet);
            if (!boundaries.valid()) {
                packetsDiscarded++;
                return;
            }
            var sequence = sequences.unwrap(packet.sequence());
            if (floorSequence < 0) {
                floorSequence = sequence;
            }
            if (sequence < floorSequence || packets.containsKey(sequence)) {
                packetsDiscarded++;
                return;
            }
            var now = clock.nanos();
            if (missing.remove(sequence) != null) {
                packetsRecovered++;
            } else if (highestSequence >= 0 && sequence > highestSequence + 1) {
                if (sequence - highestSequence > MAX_GAP) {
                    restart();
                    floorSequence = sequence;
                } else {
                    for (var gap = highestSequence + 1; gap < sequence; gap++) {
                        missing.put(gap, new Missing(now));
                    }
                }
            }
            lost.remove(sequence);
            highestSequence = Math.max(highestSequence, sequence);
            packets.put(sequence, new Slot(packet.copy(), arrivalNanos, boundaries));
            if (packets.size() > config.maxPackets()) {
                while (packets.size() > config.maxPackets() / 2) {
                    packets.pollFirstEntry();
                    packetsDiscarded++;
                }
                keyframeNeeded = true;
            }
            complete(sequence, now);
            actions = evaluate(now);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        run(actions);
    }

    /// Blocks until a frame is decodable and returns it.
    ///
    /// @return the next frame in decode order
    /// @throws InterruptedException  if the thread is interrupted while waiting
    /// @throws IllegalStateException if the assembler is closed
    public EncodedFrame next() throws InterruptedException {
        while (true) {
            var frame = step(MAX_WAIT_NANOS);
            if (frame.isPresent()) {
                return frame.get();
            }
        }
    }

    /// Waits up to a timeout for a decodable frame.
    ///
    /// @param timeout the longest to wait
    /// @return the next frame in decode order, or an empty optional when none became decodable in time
    /// @throws InterruptedException  if the thread is interrupted while waiting
    /// @throws IllegalStateException if the assembler is closed
    public Optional<EncodedFrame> next(Duration timeout) throws InterruptedException {
        var deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            var remaining = deadline - System.nanoTime();
            var frame = step(Math.max(0, Math.min(remaining, MAX_WAIT_NANOS)));
            if (frame.isPresent() || remaining <= 0) {
                return frame;
            }
        }
    }

    /// Returns the next decodable frame without waiting, after running the timers that are due by the assembler's
    /// clock (NACK retries, give-ups, keyframe requests).
    ///
    /// @return the next frame in decode order, or an empty optional when none is decodable yet
    /// @throws IllegalStateException if the assembler is closed
    public Optional<EncodedFrame> poll() {
        try {
            return step(0);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    /// Updates the round-trip time the retransmission timers and the wait budget follow.
    ///
    /// @param rtt the measured round-trip time, positive
    /// @throws IllegalArgumentException if `rtt` is not positive
    public void updateRtt(Duration rtt) {
        if (!rtt.isPositive()) {
            throw new IllegalArgumentException("round-trip time must be positive: " + rtt);
        }
        lock.lock();
        try {
            rttNanos = rtt.toNanos();
        } finally {
            lock.unlock();
        }
    }

    /// Asks the sender for a keyframe now, unless one was asked for within the configured interval: for an
    /// application whose decoder failed on a released frame.
    public void requestKeyframe() {
        List<Runnable> actions;
        lock.lock();
        try {
            keyframeNeeded = true;
            actions = evaluate(clock.nanos());
        } finally {
            lock.unlock();
        }
        run(actions);
    }

    /// {@return a snapshot of the assembler's counters}
    public VideoAssemblerStatistics statistics() {
        lock.lock();
        try {
            return new VideoAssemblerStatistics(packetsReceived, packetsDiscarded, packetsRecovered, packetsLost,
                    nackCount, keyframeRequests, framesReceived, framesDropped, keyframesReleased,
                    Duration.ofNanos(jitterBufferDelayNanos), emittedCount, freezeCount, Duration.ofNanos(freezeNanos));
        } finally {
            lock.unlock();
        }
    }

    /// Closes the assembler: buffered packets and frames are dropped, later inserts are ignored, and a blocked
    /// [#next()] throws [IllegalStateException]. Closing twice has no effect.
    @Override
    public void close() {
        lock.lock();
        try {
            closed = true;
            packets.clear();
            pending.clear();
            ready.clear();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Runs the timers, takes a ready frame, and waits up to `waitNanos` for one when none is ready.
    private Optional<EncodedFrame> step(long waitNanos) throws InterruptedException {
        List<Runnable> actions;
        EncodedFrame frame;
        lock.lockInterruptibly();
        try {
            checkOpen();
            actions = evaluate(clock.nanos());
            frame = ready.poll();
            if (frame == null && actions.isEmpty() && waitNanos > 0) {
                changed.awaitNanos(waitNanos);
                checkOpen();
                actions = evaluate(clock.nanos());
                frame = ready.poll();
            }
        } finally {
            lock.unlock();
        }
        run(actions);
        return Optional.ofNullable(frame);
    }

    /// Throws if the assembler is closed.
    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("video frame assembler closed");
        }
    }

    /// Runs feedback actions outside the lock.
    private static void run(List<Runnable> actions) {
        for (var action : actions) {
            action.run();
        }
    }

    /// Forgets everything after a sequence number jump: the stream restarted.
    private void restart() {
        packets.clear();
        missing.clear();
        lost.clear();
        frameEnds.clear();
        pending.clear();
        floorSequence = -1;
        keyframeNeeded = true;
    }

    /// Assembles the frame a new packet completes, and the frames that completion unblocks.
    private void complete(long sequence, long now) {
        var candidate = sequence;
        while (candidate >= 0) {
            var end = tryComplete(candidate, now);
            if (end < 0 || !packets.containsKey(end + 1)) {
                return;
            }
            candidate = end + 1;
        }
    }

    /// Assembles the frame containing a packet if all of its packets are present.
    ///
    /// @return the sequence number of the frame's last packet, or `-1` when the frame is incomplete
    private long tryComplete(long sequence, long now) {
        var slot = packets.get(sequence);
        if (slot == null) {
            return -1;
        }
        var timestamp = slot.packet().timestamp();
        var start = sequence;
        while (true) {
            var current = packets.get(start);
            var boundaries = current.boundaries();
            if (boundaries.explicitStart() && boundaries.frameStart()) {
                break;
            }
            var previous = packets.get(start - 1);
            if (previous == null) {
                var boundary = frameEnds.contains(start - 1)
                        || (start - 1 < floorSequence || lost.contains(start - 1)) && boundaries.frameStart();
                if (boundary && !boundaries.explicitStart()) {
                    break;
                }
                return -1;
            }
            if (previous.packet().timestamp() != timestamp || previous.boundaries().frameEnd()) {
                if (boundaries.explicitStart()) {
                    return -1;
                }
                break;
            }
            start--;
        }
        var end = sequence;
        while (!packets.get(end).boundaries().frameEnd()) {
            var following = packets.get(end + 1);
            if (following == null || following.packet().timestamp() != timestamp) {
                return -1;
            }
            end++;
        }
        var run = new ArrayList<RtpPacket>((int) (end - start + 1));
        var firstArrival = Long.MAX_VALUE;
        for (var s = start; s <= end; s++) {
            var removed = packets.remove(s);
            run.add(removed.packet());
            firstArrival = Math.min(firstArrival, removed.arrival());
        }
        frameEnds.add(end);
        while (frameEnds.size() > REMEMBERED_ENDS) {
            frameEnds.pollFirst();
        }
        try {
            var frame = depacketizer.assemble(run);
            framesReceived++;
            var identity = references.identify(frame, start, end);
            if (identity.id() <= lastReleasedId || pending.containsKey(identity.id())) {
                framesDropped++;
            } else {
                pending.put(identity.id(), new Pending(frame, identity, start, firstArrival, now));
            }
        } catch (PayloadFormatException | IllegalArgumentException exception) {
            framesDropped++;
            keyframeNeeded = true;
        }
        return end;
    }

    /// Runs the timers and releases the decodable frames.
    ///
    /// @return the feedback to send outside the lock
    private List<Runnable> evaluate(long now) {
        var actions = new ArrayList<Runnable>(2);
        var budget = waitBudgetNanos();
        var retransmit = new ArrayList<Integer>();
        for (var iterator = missing.entrySet().iterator(); iterator.hasNext(); ) {
            var entry = iterator.next();
            var state = entry.getValue();
            if (now - state.since > budget || state.requests >= config.maxRetransmissionRequests()
                    && now - state.lastRequest > rttNanos) {
                iterator.remove();
                lost.add(entry.getKey());
                packetsLost++;
                continue;
            }
            if (config.retransmissions() && (state.lastRequest == Long.MIN_VALUE
                    || now - state.lastRequest >= Math.max(rttNanos, TimeUnit.MILLISECONDS.toNanos(5)))
                    && state.requests < config.maxRetransmissionRequests()) {
                state.lastRequest = now;
                state.requests++;
                retransmit.add((int) (entry.getKey() & 0xFFFF));
            }
        }
        while (lost.size() > REMEMBERED_ENDS) {
            lost.pollFirst();
        }
        if (!retransmit.isEmpty()) {
            nackCount += retransmit.size();
            var sequenceNumbers = List.copyOf(retransmit);
            actions.add(() -> feedback.requestRetransmission(sequenceNumbers));
        }
        for (var iterator = pending.values().iterator(); iterator.hasNext(); ) {
            var frame = iterator.next();
            if (now - frame.completed() > budget && !decodable(frame)) {
                iterator.remove();
                framesDropped++;
                keyframeNeeded = true;
            }
        }
        release(now);
        if (keyframeNeeded && (lastKeyframeRequest == Long.MIN_VALUE
                || now - lastKeyframeRequest >= config.keyframeRequestInterval().toNanos())) {
            keyframeNeeded = false;
            lastKeyframeRequest = now;
            keyframeRequests++;
            actions.add(feedback::requestKeyframe);
        }
        return actions;
    }

    /// Releases the decodable frames that nothing older still holds back.
    private void release(long now) {
        var budget = waitBudgetNanos();
        while (true) {
            Pending candidate = null;
            for (var frame : pending.values()) {
                if (decodable(frame)) {
                    candidate = frame;
                    break;
                }
            }
            if (candidate == null) {
                return;
            }
            var id = candidate.identity().id();
            var blocked = false;
            for (var older : pending.headMap(id, false).values()) {
                if (now - older.completed() <= budget) {
                    blocked = true;
                    break;
                }
            }
            if (!blocked) {
                var missingBefore = missing.headMap(candidate.firstSequence(), false);
                for (var state : missingBefore.values()) {
                    if (now - state.since <= budget) {
                        blocked = true;
                        break;
                    }
                }
            }
            if (blocked) {
                return;
            }
            var older = pending.headMap(id, false);
            framesDropped += older.size();
            older.clear();
            pending.remove(id);
            emit(candidate, now);
        }
    }

    /// Hands a frame to the consumer and updates the counters.
    private void emit(Pending candidate, long now) {
        var identity = candidate.identity();
        var dependencies = references.references(identity).orElse(List.of());
        var frame = candidate.frame();
        frame = frame.withMetadata(frame.metadata().withDependencies(identity.id(), dependencies));
        ready.add(frame);
        released.add(identity.id());
        while (released.size() > REMEMBERED_RELEASES) {
            released.pollFirst();
        }
        lastReleasedId = identity.id();
        floorSequence = Math.max(floorSequence, candidate.firstSequence());
        packets.headMap(floorSequence, false).clear();
        missing.headMap(floorSequence, false).clear();
        emittedCount++;
        if (frame.keyframe()) {
            keyframesReleased++;
        }
        jitterBufferDelayNanos += Math.max(0, now - candidate.firstArrival());
        if (lastReleaseNanos != Long.MIN_VALUE) {
            var gap = now - lastReleaseNanos;
            if (averageGapNanos >= 0 && emittedCount > 2) {
                var threshold = Math.max(3 * averageGapNanos,
                        averageGapNanos + TimeUnit.MILLISECONDS.toNanos(150));
                if (gap > threshold) {
                    freezeCount++;
                    freezeNanos += gap;
                }
            }
            averageGapNanos = averageGapNanos < 0 ? gap : averageGapNanos + (gap - averageGapNanos) / 30;
        }
        lastReleaseNanos = now;
    }

    /// {@return whether a frame's references were all released}
    private boolean decodable(Pending frame) {
        var identity = frame.identity();
        if (identity.keyframe()) {
            return true;
        }
        var dependencies = references.references(identity);
        if (dependencies.isEmpty()) {
            return false;
        }
        Set<Long> needed = new HashSet<>(dependencies.get());
        return released.containsAll(needed);
    }

    /// {@return how long a frame or packet may wait: three round trips within the configured bounds}
    private long waitBudgetNanos() {
        var budget = 3 * rttNanos;
        return Math.min(Math.max(budget, config.minimumWait().toNanos()), config.maximumWait().toNanos());
    }
}
