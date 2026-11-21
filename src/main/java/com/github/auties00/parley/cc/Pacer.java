package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.EnumMap;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/// A leaky-bucket packet pacer: holds the RTP packets an RTP session would send and releases them at the pacing
/// rate, highest [OutgoingPacketScheduler.Priority] first, so a keyframe does not leave the host as one burst that
/// overflows a bottleneck queue.
///
/// Within the order `AUDIO`, `RETRANSMISSION`, `VIDEO` and `FEC` together, `PADDING`, packets of the same level leave
/// in the order they were scheduled. Video and FEC share a level because ULPFEC travels in RED on the media stream's
/// source and sequence space: a FEC packet queued behind later video would leave a gap the receiver counts as loss
/// and asks to retransmit, and a sender that writes faster than the pacing rate would starve it outright. Audio is
/// sent as soon as it is scheduled unless the configuration paces it.
///
/// # Queue bounds
///
/// When the queue would take longer than the configured maximum queue time to drain at the pacing rate, the pacer
/// raises its rate until it would not. When the oldest queued packet has still waited longer than twice the maximum
/// queue time (a sink that blocks, such as a stalled TCP or TLS relay, or a rate far below what is scheduled), the
/// pacer drops the oldest queued packets until it has not: retransmissions first, then video, FEC and padding in
/// scheduling order. Audio is never dropped. [#droppedPackets()] counts what was dropped.
///
/// # Congestion window
///
/// While its [CongestionController] reports the congestion window full ([#setCongested(boolean)]), the pacer sends
/// only audio; the other packets wait (and age out under the queue bound), and no padding or probe is sent.
///
/// # Padding and probes
///
/// The pacer also sends the probes of its [CongestionController] and keeps up the padding rate, taking the bytes the
/// media queue cannot supply from the padding source the RTP session installs with
/// [#setPaddingSource(OutgoingPacketScheduler.PaddingSource)].
///
/// # Threading and failures
///
/// [#schedule(ByteBuffer, Priority, long, PacketSink)] may be called from any thread and never blocks. Packets are
/// handed to their [OutgoingPacketScheduler.PacketSink] on the pacer's own thread, started from the configured
/// [ThreadFactory]; a sink that throws loses that packet only ([#failedPackets()]). An unexpected exception inside
/// one step of the pacer is logged and counted ([#failures()]) and the pacer goes on with the next step; only
/// [#MAX_CONSECUTIVE_FAILURES] failed steps in a row, or an [Error], stop it: the pacer then closes, drops its queue
/// and reports the cause to its failure listener once. [#close()] stops the thread and drops what is still queued.
///
/// @implNote This implementation follows the debt-based pacing of the libwebrtc pacer rather than a fixed 5 ms
/// interval: each sent byte adds to a debt that drains at the pacing rate, and the thread sleeps exactly until the
/// debt is gone, so the rate is exact at any packet size.
public final class Pacer implements OutgoingPacketScheduler, AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(Pacer.class.getName());

    /// The failed steps in a row after which the pacer gives up and reports its failure.
    public static final int MAX_CONSECUTIVE_FAILURES = 16;

    /// The probe cluster a packet handed to a sink belongs to, bound while the pacer calls the sink so that the
    /// controller sees which packets are probes when the session reports them sent from inside the sink.
    static final ScopedValue<ProbeCluster> PROBE = ScopedValue.newInstance();

    /// The longest elapsed time one process step accounts for, so a stalled thread does not earn a burst.
    private static final long MAX_ELAPSED_NANOS = 2_000_000_000L;

    /// The most debt the pacer accumulates, in time at the pacing rate: one large frame cannot block the queue for
    /// longer than this.
    private static final long MAX_DEBT_NANOS = 500_000_000L;

    /// The padding requested per step, in time at the padding rate: 5 ms.
    private static final long PADDING_STEP_NANOS = 5_000_000L;

    /// How long the thread sleeps with nothing to do, so the ALR detector keeps seeing time pass.
    private static final long IDLE_NANOS = 250_000_000L;

    /// How long the thread waits after a failed step before the next one.
    private static final long FAILURE_BACKOFF_NANOS = 5_000_000L;

    /// The smallest padding request, in bytes.
    private static final int MIN_PADDING_BYTES = 50;

    /// The largest padding or probe request of one step, in bytes.
    private static final int MAX_PADDING_BYTES = 1200;

    /// A probe cluster is dropped when it has not completed this long after it started.
    private static final long PROBE_TIMEOUT_NANOS = 1_000_000_000L;

    /// The queues the time bound drops from: every one but audio.
    private static final Priority[] DROPPABLE = {Priority.RETRANSMISSION, Priority.VIDEO, Priority.PADDING};

    private record Queued(ByteBuffer packet, Priority priority, long ssrc, PacketSink sink, long enqueuedNanos,
                          int size) {
    }

    private static final class ProbeState {
        final ProbeCluster cluster;
        long startNanos = Long.MIN_VALUE;
        long bytesSent;
        int packetsSent;

        ProbeState(ProbeCluster cluster) {
            this.cluster = cluster;
        }

        boolean complete() {
            return bytesSent >= cluster.minBytes() && packetsSent >= cluster.minPackets();
        }
    }

    private sealed interface Action {
        record Media(Queued packet, ProbeState probe) implements Action {
        }

        record Padding(int bytes, ProbeState probe) implements Action {
        }
    }

    private final MonotonicClock clock;
    private final boolean paceAudio;
    private final long maxQueueTimeNanos;
    private final Consumer<? super Throwable> failureListener;
    private final ReentrantLock lock;
    private final Condition wake;
    private final EnumMap<Priority, ArrayDeque<Queued>> queues;
    private final ArrayDeque<ProbeState> probes;
    private final AlrDetector alr;
    private long queuedBytes;
    private int queuedPackets;
    private long pacingRateBps;
    private long paddingRateBps;
    private double mediaDebtBytes;
    private double paddingDebtBytes;
    private long lastProcessNanos;
    private boolean processed;
    private boolean mediaSent;
    private boolean signalled;
    private boolean closed;
    private boolean congested;
    private OutgoingPacketScheduler.PaddingSource paddingSource;
    private long sentPackets;
    private long sentBytes;
    private long failedPackets;
    private long droppedPackets;
    private long failures;

    /// Creates a pacer and, when `threadFactory` is present, starts its thread.
    ///
    /// @param clock             the clock
    /// @param pacingRateBps     the initial pacing rate
    /// @param maxQueueTimeNanos the queue time bound
    /// @param paceAudio         whether audio waits for the budget
    /// @param threadFactory     the factory of the pacer thread, or `null` for a pacer driven by [#process(long)]
    /// @param failureListener   told once when the pacer stops on a failure
    Pacer(MonotonicClock clock, long pacingRateBps, long maxQueueTimeNanos, boolean paceAudio,
          ThreadFactory threadFactory, Consumer<? super Throwable> failureListener) {
        this.clock = clock;
        this.paceAudio = paceAudio;
        this.maxQueueTimeNanos = maxQueueTimeNanos;
        this.failureListener = Objects.requireNonNull(failureListener, "failureListener");
        this.lock = new ReentrantLock();
        this.wake = lock.newCondition();
        this.queues = new EnumMap<>(Priority.class);
        for (var priority : Priority.values()) {
            queues.put(priority, new ArrayDeque<>());
        }
        this.probes = new ArrayDeque<>();
        this.pacingRateBps = pacingRateBps;
        this.alr = new AlrDetector(pacingRateBps);
        if (threadFactory != null) {
            var thread = threadFactory.newThread(this::run);
            thread.start();
        }
    }

    /// Queues `plainRtp` for sending; ownership of the buffer passes to the pacer. A packet scheduled after
    /// [#close()] is dropped.
    ///
    /// @param plainRtp the unprotected RTP packet, positioned at its first byte with its limit at its end
    /// @param priority the priority class
    /// @param ssrc     the synchronization source of the packet
    /// @param sink     where the packet is sent when its turn comes
    @Override
    public void schedule(ByteBuffer plainRtp, Priority priority, long ssrc, PacketSink sink) {
        Objects.requireNonNull(plainRtp, "plainRtp");
        Objects.requireNonNull(priority, "priority");
        Objects.requireNonNull(sink, "sink");
        var now = clock.nanos();
        lock.lock();
        try {
            if (closed) {
                return;
            }
            var queued = new Queued(plainRtp, priority, ssrc, sink, now, plainRtp.remaining());
            queues.get(level(priority)).addLast(queued);
            queuedBytes += queued.size();
            queuedPackets++;
            enforceQueueBound(now);
            signalled = true;
            wake.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// {@return the queue a priority is held in: FEC shares the video queue}
    ///
    /// @param priority the priority of a scheduled packet
    private static Priority level(Priority priority) {
        return priority == Priority.FEC ? Priority.VIDEO : priority;
    }

    /// Sets the rate media leaves the pacer at; the pacer also takes it as the rate the senders aim for when it
    /// decides whether they are application-limited.
    ///
    /// @param bitsPerSecond the pacing rate, positive
    /// @throws IllegalArgumentException if `bitsPerSecond` is not positive
    public void setPacingRate(long bitsPerSecond) {
        setRates(bitsPerSecond, bitsPerSecond);
    }

    /// Sets the pacing rate and the target rate the application-limited detection compares the sent rate with.
    ///
    /// @param pacingBps the pacing rate, positive
    /// @param targetBps the senders' target rate, positive
    void setRates(long pacingBps, long targetBps) {
        if (pacingBps <= 0 || targetBps <= 0) {
            throw new IllegalArgumentException("rates must be positive: " + pacingBps + ", " + targetBps);
        }
        lock.lock();
        try {
            pacingRateBps = pacingBps;
            alr.setTargetBitrate(targetBps);
            signalled = true;
            wake.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Sets the rate the pacer keeps the link busy at with padding when the media queue is empty; zero disables
    /// padding. Padding starts only once some media has been sent.
    ///
    /// @param bitsPerSecond the padding rate, zero or positive
    /// @throws IllegalArgumentException if `bitsPerSecond` is negative
    public void setPaddingRate(long bitsPerSecond) {
        if (bitsPerSecond < 0) {
            throw new IllegalArgumentException("bitsPerSecond must not be negative: " + bitsPerSecond);
        }
        lock.lock();
        try {
            paddingRateBps = bitsPerSecond;
            signalled = true;
            wake.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Holds every packet but audio while `congested` is `true`, as the congestion window pushback asks when more
    /// bytes are in flight than the window allows; releasing it resumes pacing at once.
    ///
    /// @param congested whether the congestion window is full
    void setCongested(boolean congested) {
        lock.lock();
        try {
            if (this.congested != congested) {
                this.congested = congested;
                signalled = true;
                wake.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    /// {@return whether the pacer holds non-audio packets because the congestion window is full}
    public boolean isCongested() {
        lock.lock();
        try {
            return congested;
        } finally {
            lock.unlock();
        }
    }

    /// Installs the padding source of an RTP session, which sends padding and probe bytes through its own send path,
    /// replacing the previous one. Until one is installed, probes carry only queued media and no padding is sent.
    ///
    /// @param source the session's padding source
    @Override
    public void setPaddingSource(OutgoingPacketScheduler.PaddingSource source) {
        Objects.requireNonNull(source, "source");
        lock.lock();
        try {
            paddingSource = source;
        } finally {
            lock.unlock();
        }
    }

    /// {@return how long the oldest queued packet has waited; zero when the queue is empty}
    public Duration queueDelay() {
        var now = clock.nanos();
        lock.lock();
        try {
            var oldest = oldestEnqueueNanos();
            return oldest.isPresent() ? Duration.ofNanos(Math.max(0, now - oldest.getAsLong())) : Duration.ZERO;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the bytes waiting in the queue}
    public long queuedBytes() {
        lock.lock();
        try {
            return queuedBytes;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the packets waiting in the queue}
    public int queuedPackets() {
        lock.lock();
        try {
            return queuedPackets;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the current pacing rate, in bits per second}
    public long pacingRate() {
        lock.lock();
        try {
            return pacingRateBps;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the packets handed to their sink so far, padding included}
    public long sentPackets() {
        lock.lock();
        try {
            return sentPackets;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the bytes handed to their sink so far, padding included}
    public long sentBytes() {
        lock.lock();
        try {
            return sentBytes;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the packets whose sink threw}
    public long failedPackets() {
        lock.lock();
        try {
            return failedPackets;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the packets dropped from the queue because they waited longer than twice the maximum queue time}
    public long droppedPackets() {
        lock.lock();
        try {
            return droppedPackets;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the pacer steps that failed with an unexpected exception and were skipped}
    public long failures() {
        lock.lock();
        try {
            return failures;
        } finally {
            lock.unlock();
        }
    }

    /// {@return whether the pacer is closed, by [#close()] or after a failure}
    public boolean isClosed() {
        lock.lock();
        try {
            return closed;
        } finally {
            lock.unlock();
        }
    }

    /// Stops the pacer thread and drops the queued packets. Idempotent.
    @Override
    public void close() {
        lock.lock();
        try {
            closed = true;
            for (var queue : queues.values()) {
                queue.clear();
            }
            probes.clear();
            queuedBytes = 0;
            queuedPackets = 0;
            wake.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Queues a probe cluster; clusters are sent one after the other.
    ///
    /// @param cluster the cluster
    void addProbe(ProbeCluster cluster) {
        lock.lock();
        try {
            if (!closed) {
                probes.addLast(new ProbeState(cluster));
                signalled = true;
                wake.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    /// {@return when the sender became application-limited, empty when it is not}
    OptionalLong alrStartNanos() {
        lock.lock();
        try {
            return alr.alrStartNanos();
        } finally {
            lock.unlock();
        }
    }

    /// Sends every packet due at `nowNanos`.
    ///
    /// @param nowNanos the current time
    /// @return when the pacer next has something to do
    long process(long nowNanos) {
        while (true) {
            Action action;
            lock.lock();
            try {
                if (closed) {
                    return Long.MAX_VALUE;
                }
                advance(nowNanos);
                enforceQueueBound(nowNanos);
                var next = nextAction(nowNanos);
                if (next instanceof NextWake(var wakeNanos)) {
                    return wakeNanos;
                }
                action = ((Next) next).action();
            } finally {
                lock.unlock();
            }
            perform(action, nowNanos);
        }
    }

    private sealed interface Step {
    }

    private record NextWake(long nanos) implements Step {
    }

    private record Next(Action action) implements Step {
    }

    private Step nextAction(long nowNanos) {
        if (congested) {
            var audio = queues.get(Priority.AUDIO).peekFirst();
            if (audio != null && (!paceAudio || mediaDebtBytes <= 0)) {
                return new Next(new Action.Media(poll(Priority.AUDIO), null));
            }
            if (audio != null) {
                return new NextWake(nowNanos + Math.max(1, (long) (mediaDebtBytes * 8e9 / effectiveRate(nowNanos))));
            }
            return new NextWake(nowNanos + IDLE_NANOS);
        }
        while (!probes.isEmpty()) {
            var probe = probes.peekFirst();
            if (probe.startNanos == Long.MIN_VALUE) {
                probe.startNanos = nowNanos;
            }
            if (probe.complete() || nowNanos - probe.startNanos > PROBE_TIMEOUT_NANOS) {
                probes.removeFirst();
                continue;
            }
            var dueNanos = probe.startNanos + (long) (probe.bytesSent * 8e9 / probe.cluster.bitrateBps());
            if (dueNanos > nowNanos) {
                var audio = queues.get(Priority.AUDIO).peekFirst();
                if (audio != null && !paceAudio) {
                    return new Next(new Action.Media(poll(Priority.AUDIO), null));
                }
                return new NextWake(dueNanos);
            }
            var packet = pollHighest();
            if (packet != null) {
                return new Next(new Action.Media(packet, probe));
            }
            if (paddingSource == null) {
                probes.removeFirst();
                continue;
            }
            var bytes = Math.clamp(probe.cluster.minBytes() - probe.bytesSent, MIN_PADDING_BYTES, MAX_PADDING_BYTES);
            return new Next(new Action.Padding(bytes, probe));
        }
        var highest = peekHighest();
        if (highest != null) {
            if ((highest.priority() == Priority.AUDIO && !paceAudio) || mediaDebtBytes <= 0) {
                return new Next(new Action.Media(poll(highest.priority()), null));
            }
            return new NextWake(nowNanos + Math.max(1, (long) (mediaDebtBytes * 8e9 / effectiveRate(nowNanos))));
        }
        if (paddingRateBps > 0 && mediaSent && paddingSource != null) {
            if (paddingDebtBytes <= 0) {
                var bytes = Math.clamp(paddingRateBps * PADDING_STEP_NANOS / 8 / 1_000_000_000L,
                        MIN_PADDING_BYTES, MAX_PADDING_BYTES);
                return new Next(new Action.Padding(bytes, null));
            }
            return new NextWake(nowNanos + Math.max(1, (long) (paddingDebtBytes * 8e9 / paddingRateBps)));
        }
        return new NextWake(nowNanos + IDLE_NANOS);
    }

    private void perform(Action action, long nowNanos) {
        switch (action) {
            case Action.Media(var packet, var probe) -> {
                var sent = send(packet.packet(), packet.sink(), probe);
                account(packet.size(), probe, sent, nowNanos);
            }
            case Action.Padding(var bytes, var probe) -> {
                OutgoingPacketScheduler.PaddingSource source;
                lock.lock();
                try {
                    source = paddingSource;
                } finally {
                    lock.unlock();
                }
                sendPadding(source, bytes, probe, nowNanos);
            }
        }
    }

    /// Asks the session's padding source for `bytes` of padding inside the probe binding, and accounts what it sent.
    private void sendPadding(OutgoingPacketScheduler.PaddingSource source, int bytes, ProbeState probe,
                             long nowNanos) {
        int sent;
        try {
            if (source == null) {
                sent = 0;
            } else if (probe == null) {
                sent = source.sendPadding(bytes, false);
            } else {
                sent = ScopedValue.where(PROBE, probe.cluster).call(() -> source.sendPadding(bytes, true));
            }
        } catch (IOException | RuntimeException exception) {
            LOGGER.log(System.Logger.Level.DEBUG, "The session's padding source failed", exception);
            sent = 0;
        }
        if (sent <= 0) {
            lock.lock();
            try {
                if (probe != null) {
                    probes.remove(probe);
                } else {
                    paddingDebtBytes += bytes;
                }
            } finally {
                lock.unlock();
            }
            return;
        }
        account(sent, probe, true, nowNanos);
    }

    private boolean send(ByteBuffer packet, PacketSink sink, ProbeState probe) {
        try {
            if (probe == null) {
                sink.send(packet);
            } else {
                ScopedValue.where(PROBE, probe.cluster).call(() -> {
                    sink.send(packet);
                    return null;
                });
            }
            return true;
        } catch (IOException | RuntimeException exception) {
            LOGGER.log(System.Logger.Level.DEBUG, "Dropping a packet the sink failed to send", exception);
            return false;
        }
    }

    private void account(int size, ProbeState probe, boolean sent, long nowNanos) {
        lock.lock();
        try {
            if (probe != null) {
                probe.bytesSent += size;
                probe.packetsSent++;
            }
            if (!sent) {
                failedPackets++;
                return;
            }
            sentPackets++;
            sentBytes += size;
            mediaSent = true;
            var maxDebt = pacingRateBps * MAX_DEBT_NANOS / 8e9;
            mediaDebtBytes = Math.min(mediaDebtBytes + size, maxDebt);
            paddingDebtBytes = Math.min(paddingDebtBytes + size, Math.max(paddingRateBps * MAX_DEBT_NANOS / 8e9, size));
            alr.onBytesSent(size, nowNanos);
        } finally {
            lock.unlock();
        }
    }

    private void advance(long nowNanos) {
        if (!processed) {
            processed = true;
            lastProcessNanos = nowNanos;
        }
        var elapsed = Math.clamp(nowNanos - lastProcessNanos, 0, MAX_ELAPSED_NANOS);
        lastProcessNanos = Math.max(lastProcessNanos, nowNanos);
        if (elapsed > 0) {
            mediaDebtBytes = Math.max(0, mediaDebtBytes - effectiveRate(nowNanos) * elapsed / 8e9);
            paddingDebtBytes = Math.max(0, paddingDebtBytes - paddingRateBps * elapsed / 8e9);
            alr.onBytesSent(0, nowNanos);
        }
    }

    /// Drops the oldest droppable packets while the oldest queued packet has waited longer than twice the maximum
    /// queue time: retransmissions first, then the oldest of video, FEC and padding. Audio is never dropped. Called
    /// under the lock.
    private void enforceQueueBound(long nowNanos) {
        var bound = 2 * maxQueueTimeNanos;
        while (true) {
            var oldest = Long.MAX_VALUE;
            for (var priority : DROPPABLE) {
                var first = queues.get(priority).peekFirst();
                if (first != null) {
                    oldest = Math.min(oldest, first.enqueuedNanos());
                }
            }
            if (oldest == Long.MAX_VALUE || nowNanos - oldest <= bound) {
                return;
            }
            Priority victim;
            if (!queues.get(Priority.RETRANSMISSION).isEmpty()) {
                victim = Priority.RETRANSMISSION;
            } else {
                var video = queues.get(Priority.VIDEO).peekFirst();
                var padding = queues.get(Priority.PADDING).peekFirst();
                victim = video != null && (padding == null || video.enqueuedNanos() <= padding.enqueuedNanos())
                        ? Priority.VIDEO : Priority.PADDING;
            }
            poll(victim);
            droppedPackets++;
        }
    }

    private double effectiveRate(long nowNanos) {
        double rate = pacingRateBps;
        if (queuedBytes > 0) {
            var oldest = oldestEnqueueNanos();
            if (oldest.isPresent()) {
                var timeLeft = Math.max(1_000_000L, maxQueueTimeNanos - (nowNanos - oldest.getAsLong()));
                rate = Math.max(rate, queuedBytes * 8e9 / timeLeft);
            }
        }
        return rate;
    }

    private OptionalLong oldestEnqueueNanos() {
        var oldest = Long.MAX_VALUE;
        for (var queue : queues.values()) {
            var first = queue.peekFirst();
            if (first != null && first.enqueuedNanos() < oldest) {
                oldest = first.enqueuedNanos();
            }
        }
        return oldest == Long.MAX_VALUE ? OptionalLong.empty() : OptionalLong.of(oldest);
    }

    private Queued peekHighest() {
        for (var priority : Priority.values()) {
            var first = queues.get(priority).peekFirst();
            if (first != null) {
                return first;
            }
        }
        return null;
    }

    private Queued pollHighest() {
        var highest = peekHighest();
        return highest == null ? null : poll(highest.priority());
    }

    private Queued poll(Priority priority) {
        var packet = queues.get(level(priority)).pollFirst();
        if (packet != null) {
            queuedBytes -= packet.size();
            queuedPackets--;
        }
        return packet;
    }

    /// Runs the pacer: one [#process(long)] step and one wait per iteration, each iteration isolated, so a failure
    /// costs that iteration only.
    private void run() {
        var consecutiveFailures = 0;
        while (true) {
            try {
                var next = process(clock.nanos());
                if (!await(next)) {
                    return;
                }
                consecutiveFailures = 0;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return;
            } catch (RuntimeException exception) {
                consecutiveFailures++;
                lock.lock();
                try {
                    failures++;
                } finally {
                    lock.unlock();
                }
                if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                    fail(exception);
                    return;
                }
                LOGGER.log(System.Logger.Level.WARNING, "A pacer step failed; skipping it", exception);
                if (!backOff()) {
                    return;
                }
            } catch (Error error) {
                fail(error);
                throw error;
            }
        }
    }

    /// Waits until `next` or a signal; returns `false` once the pacer is closed.
    private boolean await(long next) throws InterruptedException {
        lock.lock();
        try {
            if (closed) {
                return false;
            }
            if (signalled) {
                signalled = false;
                return true;
            }
            var wait = next == Long.MAX_VALUE ? IDLE_NANOS : next - clock.nanos();
            if (wait > 0) {
                wake.await(wait, TimeUnit.NANOSECONDS);
            }
            signalled = false;
            return !closed;
        } finally {
            lock.unlock();
        }
    }

    /// Waits a moment after a failed iteration without reading the clock, which may be what failed; returns `false`
    /// once the pacer is closed.
    private boolean backOff() {
        lock.lock();
        try {
            if (!closed) {
                wake.awaitNanos(FAILURE_BACKOFF_NANOS);
            }
            return !closed;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return false;
        } finally {
            lock.unlock();
        }
    }

    /// Closes the pacer after a failure it cannot go on from and reports it.
    private void fail(Throwable cause) {
        LOGGER.log(System.Logger.Level.ERROR, "The pacer stopped after a failure", cause);
        close();
        try {
            failureListener.accept(cause);
        } catch (RuntimeException exception) {
            LOGGER.log(System.Logger.Level.WARNING, "The pacer failure listener failed", exception);
        }
    }
}
