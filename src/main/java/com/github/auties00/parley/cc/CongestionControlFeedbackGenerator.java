package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.rtcp.CongestionControlFeedback;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/// The receive side of RFC 8888 congestion control feedback, the standard alternative to transport-wide feedback a
/// session uses when `a=rtcp-fb:* ack ccfb` was negotiated: records the arrival time of every RTP packet by SSRC and
/// sequence number and reports them to the sender in [CongestionControlFeedback] messages.
///
/// Each feedback covers, per SSRC, the sequence numbers from the first one not yet reported to the highest one
/// received; missing ones are reported lost, and a packet that arrives after its sequence number was reported is
/// ignored. Arrival times travel as offsets before the report timestamp in units of `1/1024` second; an arrival too
/// old for the 13-bit offset is reported received with the over-range value. One message reports at most
/// [#MAX_METRICS_PER_FEEDBACK] packets; more go in further messages of the same round.
///
/// The SSRCs tracked are bounded by [#MAX_SSRCS] (the stalest is forgotten), so a peer cannot grow the generator's
/// state by inventing sources.
///
/// Feedback is sent every [#DEFAULT_INTERVAL] once [#start(ThreadFactory)] runs the generator's thread, or whenever
/// the owner calls [#sendFeedback()].
///
/// # Threading
///
/// Every method may be called from any thread. The sink is called without the generator's lock held, serially.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
public final class CongestionControlFeedbackGenerator implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(CongestionControlFeedbackGenerator.class.getName());

    /// The feedback interval: 100 ms, which RFC 8888 section 2 puts within the range of one report per frame to one
    /// per round trip.
    public static final Duration DEFAULT_INTERVAL = Duration.ofMillis(100);

    /// The most packets one feedback message reports, which keeps the encoded message well under a typical MTU.
    public static final int MAX_METRICS_PER_FEEDBACK = 500;

    /// The most SSRCs whose arrivals are tracked at once.
    public static final int MAX_SSRCS = 64;

    /// The furthest ahead of the last reported sequence number a packet may be before the generator assumes the
    /// sender restarted its counter and starts that SSRC over.
    private static final long MAX_SEQUENCE_JUMP = 0x4000;

    /// The arrival state of one SSRC.
    private static final class Stream {
        final SequenceUnwrapper unwrapper = new SequenceUnwrapper(16);
        final TreeMap<Long, Long> arrivals = new TreeMap<>();
        long nextToReport;
        boolean reportingStarted;
        long lastArrivalNanos;
    }

    private final long senderSsrc;
    private final MonotonicClock clock;
    private final Consumer<? super RtcpPacket> sink;
    private final ReentrantLock lock;
    private final ReentrantLock sinkLock;
    private final Condition wake;
    private final Map<Long, Stream> streams;
    private final long intervalNanos;
    private boolean closed;
    private boolean started;

    private CongestionControlFeedbackGenerator(long senderSsrc, MonotonicClock clock, Consumer<? super RtcpPacket> sink,
                                               Duration interval) {
        this.senderSsrc = senderSsrc;
        this.clock = clock;
        this.sink = sink;
        this.lock = new ReentrantLock();
        this.sinkLock = new ReentrantLock();
        this.wake = lock.newCondition();
        this.streams = new LinkedHashMap<>(16, 0.75f, true);
        this.intervalNanos = interval.toNanos();
    }

    /// Creates a generator that reports every [#DEFAULT_INTERVAL].
    ///
    /// @param senderSsrc the SSRC feedback is sent from (the receiver's RTCP SSRC)
    /// @param clock      the clock arrival times are read on
    /// @param sink       where feedback messages go, typically the RTP session's RTCP sender
    /// @return the generator, with no thread running
    /// @throws IllegalArgumentException if `senderSsrc` is not an unsigned 32-bit value
    public static CongestionControlFeedbackGenerator create(long senderSsrc, MonotonicClock clock,
                                                            Consumer<? super RtcpPacket> sink) {
        return create(senderSsrc, clock, sink, DEFAULT_INTERVAL);
    }

    /// Creates a generator.
    ///
    /// @param senderSsrc the SSRC feedback is sent from (the receiver's RTCP SSRC)
    /// @param clock      the clock arrival times are read on
    /// @param sink       where feedback messages go
    /// @param interval   the feedback interval, positive
    /// @return the generator, with no thread running
    /// @throws IllegalArgumentException if `senderSsrc` is not an unsigned 32-bit value or `interval` is not positive
    public static CongestionControlFeedbackGenerator create(long senderSsrc, MonotonicClock clock,
                                                            Consumer<? super RtcpPacket> sink, Duration interval) {
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(sink, "sink");
        Objects.requireNonNull(interval, "interval");
        checkSsrc(senderSsrc);
        if (interval.isNegative() || interval.isZero()) {
            throw new IllegalArgumentException("interval must be positive: " + interval);
        }
        return new CongestionControlFeedbackGenerator(senderSsrc, clock, sink, interval);
    }

    /// Records the arrival of an RTP packet.
    ///
    /// @param ssrc         the packet's SSRC
    /// @param sequence     the packet's RTP sequence number
    /// @param arrivalNanos the arrival time, on this generator's clock
    /// @throws IllegalArgumentException if `ssrc` is not an unsigned 32-bit value
    public void onPacketReceived(long ssrc, int sequence, long arrivalNanos) {
        checkSsrc(ssrc);
        lock.lock();
        try {
            var stream = streams.get(ssrc);
            if (stream == null) {
                if (streams.size() >= MAX_SSRCS) {
                    var stalest = streams.keySet().iterator().next();
                    streams.remove(stalest);
                }
                stream = new Stream();
                streams.put(ssrc, stream);
            }
            stream.lastArrivalNanos = arrivalNanos;
            var unwrapped = stream.unwrapper.unwrap(sequence & 0xFFFF);
            if (stream.reportingStarted) {
                if (unwrapped < stream.nextToReport) {
                    return;
                }
                if (unwrapped - stream.nextToReport > MAX_SEQUENCE_JUMP) {
                    stream.arrivals.clear();
                    stream.nextToReport = unwrapped;
                }
            }
            stream.arrivals.putIfAbsent(unwrapped, arrivalNanos);
        } finally {
            lock.unlock();
        }
    }

    /// Sends feedback about every packet received since the last feedback, now; nothing is sent when there is
    /// nothing to report.
    public void sendFeedback() {
        List<CongestionControlFeedback> feedback;
        lock.lock();
        try {
            feedback = buildLocked(clock.nanos());
        } finally {
            lock.unlock();
        }
        deliver(feedback);
    }

    /// Starts a thread that sends feedback every interval until [#close()].
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

    /// Stops the thread, if one runs. Idempotent; packets recorded afterwards are still reported by explicit calls.
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

    private void run() {
        try {
            var next = clock.nanos() + intervalNanos;
            while (true) {
                lock.lock();
                try {
                    while (true) {
                        if (closed) {
                            return;
                        }
                        var wait = next - clock.nanos();
                        if (wait <= 0) {
                            break;
                        }
                        wake.awaitNanos(Math.min(wait, intervalNanos));
                    }
                } finally {
                    lock.unlock();
                }
                sendFeedback();
                next = TransportFeedbackGenerator.nextDeadline(next, intervalNanos, clock.nanos());
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private void deliver(List<CongestionControlFeedback> feedback) {
        if (feedback.isEmpty()) {
            return;
        }
        sinkLock.lock();
        try {
            for (var message : feedback) {
                sink.accept(message);
            }
        } catch (RuntimeException exception) {
            LOGGER.log(System.Logger.Level.WARNING, "Congestion control feedback sink failed", exception);
        } finally {
            sinkLock.unlock();
        }
    }

    /// Builds the messages of one round. Called under the lock.
    private List<CongestionControlFeedback> buildLocked(long nowNanos) {
        var messages = new ArrayList<CongestionControlFeedback>();
        var reportUnits = Math.floorDiv(nowNanos, 1_000_000_000L) * 65_536
                + Math.floorMod(nowNanos, 1_000_000_000L) * 65_536 / 1_000_000_000L;
        var reportTimestamp = reportUnits & 0xFFFFFFFFL;
        var reportNanos = Math.floorDiv(nowNanos, 1_000_000_000L) * 1_000_000_000L
                + Math.floorMod(nowNanos, 1_000_000_000L) * 65_536 / 1_000_000_000L * 1_000_000_000L / 65_536;
        var reports = new ArrayList<CongestionControlFeedback.StreamReport>();
        var budget = MAX_METRICS_PER_FEEDBACK;
        for (var entry : streams.entrySet()) {
            var stream = entry.getValue();
            if (stream.arrivals.isEmpty()) {
                continue;
            }
            if (!stream.reportingStarted) {
                stream.reportingStarted = true;
                stream.nextToReport = stream.arrivals.firstKey();
            }
            var highest = stream.arrivals.lastKey();
            while (stream.nextToReport <= highest) {
                if (budget == 0) {
                    messages.add(new CongestionControlFeedback(senderSsrc, List.copyOf(reports), reportTimestamp));
                    reports.clear();
                    budget = MAX_METRICS_PER_FEEDBACK;
                }
                var count = (int) Math.min(budget, highest - stream.nextToReport + 1);
                var metrics = new ArrayList<CongestionControlFeedback.Metric>(count);
                for (var i = 0; i < count; i++) {
                    var arrival = stream.arrivals.get(stream.nextToReport + i);
                    if (arrival == null) {
                        metrics.add(CongestionControlFeedback.Metric.lost());
                        continue;
                    }
                    var offset = Math.floorDiv((reportNanos - arrival) * 1_024, 1_000_000_000L);
                    var value = offset < 0 ? 0 : offset >= CongestionControlFeedback.Metric.OVER_RANGE
                            ? CongestionControlFeedback.Metric.OVER_RANGE : (int) offset;
                    metrics.add(new CongestionControlFeedback.Metric(true, 0, value));
                }
                reports.add(new CongestionControlFeedback.StreamReport(entry.getKey(),
                        (int) (stream.nextToReport & 0xFFFF), metrics));
                budget -= count;
                stream.nextToReport += count;
                stream.arrivals.headMap(stream.nextToReport, false).clear();
            }
        }
        if (!reports.isEmpty()) {
            messages.add(new CongestionControlFeedback(senderSsrc, List.copyOf(reports), reportTimestamp));
        }
        return messages;
    }

    private static void checkSsrc(long ssrc) {
        if (ssrc < 0 || ssrc > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("ssrc must be an unsigned 32-bit value: " + ssrc);
        }
    }
}
