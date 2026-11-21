package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.EnumMap;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/// A leaky-bucket packet pacer: holds the RTP packets an RTP session would send and releases them at the pacing rate, highest [OutgoingPacketScheduler.Priority] first, so a keyframe does
/// not leave the host as one burst that overflows a bottleneck queue.
///
/// Within the order `AUDIO`, `RETRANSMISSION`, `VIDEO` and `FEC` together, `PADDING`, packets of the same level leave
/// in the order they were scheduled. Video and FEC share a level because ULPFEC travels in RED on the media stream's
/// source and sequence space: a FEC packet queued behind later video would leave a gap the receiver counts as loss
/// and asks to retransmit, and a sender that writes faster than the pacing rate would starve it outright. Audio is sent as soon as it is scheduled unless the configuration paces it. When the
/// queue would take longer than the configured maximum queue time to drain at the pacing rate, the pacer raises its
/// rate until it would not.
///
/// The pacer also sends the probes of its [CongestionController] and keeps up the padding rate, taking the bytes
/// the media queue cannot supply from the padding source the RTP session installs with
/// [#setPaddingSource(OutgoingPacketScheduler.PaddingSource)], or from a
/// [com.github.auties00.parley.cc.PaddingSource] given to
/// [#setPaddingSource(com.github.auties00.parley.cc.PaddingSource)].
///
/// # Threading
///
/// [#schedule(ByteBuffer, Priority, long, PacketSink)] may be called from any thread and never blocks. Packets are
/// handed to their [OutgoingPacketScheduler.PacketSink] on the pacer's own thread, started from the configured
/// [ThreadFactory]; a sink that throws [IOException] loses that packet only. [#close()] stops the thread and drops
/// what is still queued.
///
/// @implNote This implementation follows the debt-based pacing of the libwebrtc pacer rather than a fixed 5 ms
/// interval: each sent byte adds to a debt that drains at the pacing rate, and the thread sleeps exactly until the
/// debt is gone, so the rate is exact at any packet size.
public final class Pacer implements OutgoingPacketScheduler, AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(Pacer.class.getName());

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

    /// The smallest padding request, in bytes.
    private static final int MIN_PADDING_BYTES = 50;

    /// The largest padding or probe request of one step, in bytes.
    private static final int MAX_PADDING_BYTES = 1200;

    /// A probe cluster is dropped when it has not completed this long after it started.
    private static final long PROBE_TIMEOUT_NANOS = 1_000_000_000L;

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
    private com.github.auties00.parley.cc.PaddingSource paddingSource;
    private OutgoingPacketScheduler.PaddingSource sessionPaddingSource;
    private long sentPackets;
    private long sentBytes;
    private long failedPackets;

    /// Creates a pacer and, when `threadFactory` is present, starts its thread.
    ///
    /// @param clock             the clock
    /// @param pacingRateBps     the initial pacing rate
    /// @param maxQueueTimeNanos the queue time bound
    /// @param paceAudio         whether audio waits for the budget
    /// @param threadFactory     the factory of the pacer thread, or `null` for a pacer driven by [#process(long)]
    Pacer(MonotonicClock clock, long pacingRateBps, long maxQueueTimeNanos, boolean paceAudio,
          ThreadFactory threadFactory) {
        this.clock = clock;
        this.paceAudio = paceAudio;
        this.maxQueueTimeNanos = maxQueueTimeNanos;
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

    /// Installs the source of padding and probe packets, replacing the previous one. Until one is installed, probes
    /// carry only queued media and no padding is sent.
    ///
    /// @param source the padding source
    public void setPaddingSource(com.github.auties00.parley.cc.PaddingSource source) {
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
                com.github.auties00.parley.cc.PaddingSource source;
                OutgoingPacketScheduler.PaddingSource sessionSource;
                lock.lock();
                try {
                    source = paddingSource;
                    sessionSource = sessionPaddingSource;
                } finally {
                    lock.unlock();
                }
                if (source == null && sessionSource != null) {
                    sendSessionPadding(sessionSource, bytes, probe, nowNanos);
                    return;
                }
                List<PaddingPacket> packets;
                try {
                    packets = source == null ? List.of() : source.generatePadding(bytes);
                } catch (RuntimeException exception) {
                    LOGGER.log(System.Logger.Level.WARNING, "Padding source failed", exception);
                    packets = List.of();
                }
                if (packets.isEmpty()) {
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
                for (var padding : packets) {
                    var size = padding.plainRtp().remaining();
                    var sent = send(padding.plainRtp(), padding.sink(), probe);
                    account(size, probe, sent, nowNanos);
                }
            }
        }
    }

    /// Installs the padding source of an RTP session, which sends the padding itself through its own send path; a
    /// source given to [#setPaddingSource(com.github.auties00.parley.cc.PaddingSource)] takes precedence.
    ///
    /// @param source the session's padding source
    @Override
    public void setPaddingSource(OutgoingPacketScheduler.PaddingSource source) {
        Objects.requireNonNull(source, "source");
        lock.lock();
        try {
            sessionPaddingSource = source;
        } finally {
            lock.unlock();
        }
    }

    /// Asks a session's padding source for `bytes` of padding inside the probe binding, and accounts what it sent.
    private void sendSessionPadding(OutgoingPacketScheduler.PaddingSource source, int bytes, ProbeState probe,
                                    long nowNanos) {
        int sent;
        try {
            if (probe == null) {
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

    private void run() {
        try {
            while (true) {
                var next = process(clock.nanos());
                lock.lock();
                try {
                    if (closed) {
                        return;
                    }
                    if (signalled) {
                        signalled = false;
                        continue;
                    }
                    var wait = next == Long.MAX_VALUE ? IDLE_NANOS : next - clock.nanos();
                    if (wait > 0) {
                        wake.await(wait, TimeUnit.NANOSECONDS);
                    }
                    signalled = false;
                } finally {
                    lock.unlock();
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException exception) {
            LOGGER.log(System.Logger.Level.ERROR, "Pacer thread failed", exception);
        }
    }
}
