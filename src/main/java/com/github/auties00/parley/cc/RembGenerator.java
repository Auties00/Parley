package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/// A receive-side bandwidth estimator that reports its estimate to the sender in [Remb] messages, for senders that
/// do not use transport-wide congestion control.
///
/// It runs the delay-based half of GCC on the receiver: the `abs-send-time` header extension gives each packet's
/// departure time, packet groups' inter-arrival delay variation feeds the trendline filter and over-use detector,
/// and an AIMD controller whose decrease is based on the measured incoming rate produces the estimate. The estimate
/// is sent at least every [#REPORT_INTERVAL], and at once when it falls by more than [#DECREASE_REPORT_RATIO].
///
/// # Threading
///
/// Every method may be called from any thread. The sink is called without the generator's lock held, serially.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03 RTCP message for Receiver Estimated Maximum Bitrate
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/abs-send-time/README.md Absolute Send Time
public final class RembGenerator implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(RembGenerator.class.getName());

    /// The longest spacing of two reports: 1 s.
    public static final Duration REPORT_INTERVAL = Duration.ofSeconds(1);

    /// A fall of the estimate below this fraction of the last reported one is reported at once.
    public static final double DECREASE_REPORT_RATIO = 0.97;

    /// The lowest estimate reported: 10 kbit/s.
    public static final long MIN_BITRATE_BPS = 10_000;

    /// The highest estimate reported: 1 Gbit/s.
    static final long MAX_BITRATE_BPS = 1_000_000_000L;

    /// The window of the incoming rate measurement: 1 s.
    static final long RATE_WINDOW_NANOS = 1_000_000_000L;

    /// The incoming rate is trusted only after this much data: 500 ms.
    static final long MIN_RATE_WINDOW_NANOS = 500_000_000L;

    /// The smallest spacing of two rate controller updates while not over-using: 100 ms.
    static final long UPDATE_INTERVAL_NANOS = 100_000_000L;

    /// A stream not seen for this long is left out of the reported SSRC list: 2 s.
    static final long SSRC_TIMEOUT_NANOS = 2_000_000_000L;

    /// The `abs-send-time` resolution: 6.18 fixed point seconds.
    private static final int ABS_SEND_TIME_FRACTION_BITS = 18;

    private final long senderSsrc;
    private final MonotonicClock clock;
    private final Consumer<? super RtcpPacket> sink;
    private final ReentrantLock lock;
    private final ReentrantLock sinkLock;
    private final Condition wake;
    private final SequenceUnwrapper sendTimeUnwrapper;
    private final InterArrival interArrival;
    private final TrendlineEstimator trendline;
    private final ArrayDeque<long[]> incoming;
    private final Map<Long, Long> ssrcs;
    private AimdRateController controller;
    private long incomingBytes;
    private long firstArrivalNanos;
    private boolean anyPacket;
    private long lastUpdateNanos;
    private boolean updated;
    private long rttNanos;
    private long lastReportedBps;
    private long lastReportNanos;
    private boolean reported;
    private boolean closed;
    private boolean started;

    private RembGenerator(long senderSsrc, MonotonicClock clock, Consumer<? super RtcpPacket> sink) {
        this.senderSsrc = senderSsrc;
        this.clock = clock;
        this.sink = sink;
        this.lock = new ReentrantLock();
        this.sinkLock = new ReentrantLock();
        this.wake = lock.newCondition();
        this.sendTimeUnwrapper = new SequenceUnwrapper(24);
        this.interArrival = new InterArrival();
        this.trendline = new TrendlineEstimator();
        this.incoming = new ArrayDeque<>();
        this.ssrcs = new HashMap<>();
        this.rttNanos = GoogleCongestionController.DEFAULT_RTT_NANOS;
    }

    /// Creates a generator.
    ///
    /// @param senderSsrc the SSRC REMB messages are sent from (the receiver's RTCP SSRC)
    /// @param clock      the clock arrival times are read on
    /// @param sink       where REMB messages go, typically the RTP session's RTCP sender
    /// @return the generator, with no thread running
    /// @throws IllegalArgumentException if `senderSsrc` is not an unsigned 32-bit value
    public static RembGenerator create(long senderSsrc, MonotonicClock clock, Consumer<? super RtcpPacket> sink) {
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(sink, "sink");
        checkSsrc(senderSsrc);
        return new RembGenerator(senderSsrc, clock, sink);
    }

    /// Records the arrival of a packet carrying the `abs-send-time` header extension, and sends a REMB at once when
    /// the estimate dropped.
    ///
    /// @param ssrc         the SSRC of the packet
    /// @param absSendTime  the 24-bit extension value, seconds in 6.18 fixed point
    /// @param sizeBytes    the packet size, header included
    /// @param arrivalNanos the arrival time, on this generator's clock
    /// @throws IllegalArgumentException if `ssrc` is not an unsigned 32-bit value or `sizeBytes` is negative
    public void onPacketReceived(long ssrc, int absSendTime, int sizeBytes, long arrivalNanos) {
        checkSsrc(ssrc);
        if (sizeBytes < 0) {
            throw new IllegalArgumentException("sizeBytes must not be negative: " + sizeBytes);
        }
        Optional<Remb> report;
        lock.lock();
        try {
            ssrcs.put(ssrc, arrivalNanos);
            if (!anyPacket) {
                anyPacket = true;
                firstArrivalNanos = arrivalNanos;
            }
            incoming.addLast(new long[]{arrivalNanos, sizeBytes});
            incomingBytes += sizeBytes;
            expireIncoming(arrivalNanos);
            var sendTime = sendTimeUnwrapper.unwrap(absSendTime & 0xFFFFFF);
            var sendNanos = (sendTime >> ABS_SEND_TIME_FRACTION_BITS) * 1_000_000_000L
                    + (((sendTime & ((1L << ABS_SEND_TIME_FRACTION_BITS) - 1)) * 1_000_000_000L) >> ABS_SEND_TIME_FRACTION_BITS);
            var deltas = interArrival.onPacket(sendNanos, arrivalNanos, sizeBytes);
            var usage = deltas.map(trendline::update).orElse(trendline.state());
            report = maybeUpdate(usage, arrivalNanos, deltas.isPresent());
        } finally {
            lock.unlock();
        }
        report.ifPresent(this::deliver);
    }

    /// Sends a REMB if the report interval elapsed since the last one.
    public void process() {
        Optional<Remb> report = Optional.empty();
        lock.lock();
        try {
            var now = clock.nanos();
            if (controller != null && (!reported || now - lastReportNanos >= REPORT_INTERVAL.toNanos())) {
                report = Optional.of(reportLocked(now));
            }
        } finally {
            lock.unlock();
        }
        report.ifPresent(this::deliver);
    }

    /// Sets the round-trip time the rate controller's additive increase is sized by.
    ///
    /// @param rtt the round-trip time, positive
    /// @throws IllegalArgumentException if `rtt` is not positive
    public void setRtt(Duration rtt) {
        Objects.requireNonNull(rtt, "rtt");
        if (rtt.isNegative() || rtt.isZero()) {
            throw new IllegalArgumentException("rtt must be positive: " + rtt);
        }
        lock.lock();
        try {
            rttNanos = rtt.toNanos();
        } finally {
            lock.unlock();
        }
    }

    /// {@return the current estimate, in bits per second, once enough data arrived to make one}
    public OptionalLong currentEstimate() {
        lock.lock();
        try {
            return controller == null ? OptionalLong.empty() : OptionalLong.of(controller.estimate());
        } finally {
            lock.unlock();
        }
    }

    /// {@return the incoming rate over the last second, in bits per second}
    public long incomingBitrate() {
        lock.lock();
        try {
            expireIncoming(clock.nanos());
            return incomingBytes * 8;
        } finally {
            lock.unlock();
        }
    }

    /// Starts a thread that sends due reports until [#close()].
    ///
    /// @param threadFactory the factory of the thread
    /// @throws IllegalStateException if the thread was already started or the generator is closed
    public void start(ThreadFactory threadFactory) {
        Objects.requireNonNull(threadFactory, "threadFactory");
        lock.lock();
        try {
            if (started || closed) {
                throw new IllegalStateException(closed ? "generator is closed" : "generator already started");
            }
            started = true;
        } finally {
            lock.unlock();
        }
        threadFactory.newThread(this::run).start();
    }

    /// Stops the thread, if one runs. Idempotent.
    @Override
    public void close() {
        lock.lock();
        try {
            closed = true;
            wake.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private Optional<Remb> maybeUpdate(BandwidthUsage usage, long nowNanos, boolean newSample) {
        if (nowNanos - firstArrivalNanos < MIN_RATE_WINDOW_NANOS) {
            return Optional.empty();
        }
        var incomingBps = incomingBytes * 8 * 1_000_000_000L / Math.min(RATE_WINDOW_NANOS, Math.max(1, nowNanos - firstArrivalNanos));
        if (controller == null) {
            controller = new AimdRateController(MIN_BITRATE_BPS, Math.max(MIN_BITRATE_BPS, incomingBps), MAX_BITRATE_BPS);
            lastUpdateNanos = nowNanos;
            updated = true;
            return Optional.of(reportLocked(nowNanos));
        }
        if (!newSample) {
            return Optional.empty();
        }
        if (usage != BandwidthUsage.OVERUSING && updated && nowNanos - lastUpdateNanos < UPDATE_INTERVAL_NANOS) {
            return Optional.empty();
        }
        controller.update(usage, OptionalLong.of(incomingBps), rttNanos, nowNanos);
        lastUpdateNanos = nowNanos;
        updated = true;
        if (reported && controller.estimate() < DECREASE_REPORT_RATIO * lastReportedBps) {
            return Optional.of(reportLocked(nowNanos));
        }
        return Optional.empty();
    }

    private Remb reportLocked(long nowNanos) {
        var estimate = controller.estimate();
        lastReportedBps = estimate;
        lastReportNanos = nowNanos;
        reported = true;
        ssrcs.values().removeIf(seen -> nowNanos - seen > SSRC_TIMEOUT_NANOS);
        var list = new ArrayList<>(ssrcs.keySet());
        list.sort(Long::compare);
        return new Remb(senderSsrc, estimate, List.copyOf(list));
    }

    private void expireIncoming(long nowNanos) {
        while (!incoming.isEmpty() && nowNanos - incoming.peekFirst()[0] > RATE_WINDOW_NANOS) {
            incomingBytes -= incoming.pollFirst()[1];
        }
    }

    private void deliver(Remb remb) {
        sinkLock.lock();
        try {
            sink.accept(remb);
        } catch (RuntimeException exception) {
            LOGGER.log(System.Logger.Level.WARNING, "REMB sink failed", exception);
        } finally {
            sinkLock.unlock();
        }
    }

    private void run() {
        var period = REPORT_INTERVAL.toNanos() / 4;
        try {
            while (true) {
                lock.lock();
                try {
                    if (closed) {
                        return;
                    }
                    wake.awaitNanos(period);
                    if (closed) {
                        return;
                    }
                } finally {
                    lock.unlock();
                }
                process();
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private static void checkSsrc(long ssrc) {
        if (ssrc < 0 || ssrc > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("ssrc must be an unsigned 32-bit value: " + ssrc);
        }
    }
}
