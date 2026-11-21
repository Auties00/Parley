package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/// The receive side of transport-wide congestion control: records the arrival time of every packet that carries the
/// `transport-wide-cc` header extension and reports them to the sender in [TransportFeedback] messages.
///
/// Each feedback covers the sequence numbers from the first one not yet reported to the highest one received;
/// missing ones are reported lost and a packet that arrives after its sequence number was reported is ignored. The
/// arrival times are quantized to the 250 microsecond ticks of the wire format: the first received packet of a
/// feedback is relative to the reference time (in 64 ms units, the arrival of that packet rounded down) and every
/// later one to the previous received packet. A feedback ends early, and the next one continues, when a delta does
/// not fit the 16-bit signed tick count or the feedback reaches [#MAX_PACKETS_PER_FEEDBACK] packets.
///
/// Feedback is sent every [#DEFAULT_INTERVAL] once [#start(ThreadFactory)] runs the generator's thread, or whenever
/// the owner calls [#sendFeedback()] or [#process()].
///
/// # Threading
///
/// Every method may be called from any thread. The sink is called without the generator's lock held, serially.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
public final class TransportFeedbackGenerator implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(TransportFeedbackGenerator.class.getName());

    /// The default feedback interval: 100 ms.
    public static final Duration DEFAULT_INTERVAL = Duration.ofMillis(100);

    /// The most packets one feedback reports, which keeps the encoded message well under a typical MTU even when
    /// every delta needs two bytes.
    public static final int MAX_PACKETS_PER_FEEDBACK = 400;

    /// The receive-delta tick of the wire format, in microseconds.
    static final long TICK_MICROS = 250;

    /// The reference time unit of the wire format, in microseconds.
    static final long REFERENCE_TIME_MICROS = 64_000;

    /// The furthest ahead of the last reported sequence number a packet may be before the generator assumes the
    /// sender restarted its counter and starts over.
    private static final long MAX_SEQUENCE_JUMP = 0x4000;

    private final long senderSsrc;
    private final MonotonicClock clock;
    private final Consumer<? super RtcpPacket> sink;
    private final ReentrantLock lock;
    private final ReentrantLock sinkLock;
    private final Condition wake;
    private final SequenceUnwrapper unwrapper;
    private final TreeMap<Long, Long> arrivals;
    private long nextToReport;
    private boolean reportingStarted;
    private long mediaSsrc;
    private long epochNanos;
    private boolean epochSet;
    private int feedbackCount;
    private long intervalNanos;
    private long lastFeedbackNanos;
    private boolean closed;
    private boolean started;

    private TransportFeedbackGenerator(long senderSsrc, MonotonicClock clock, Consumer<? super RtcpPacket> sink) {
        this.senderSsrc = senderSsrc;
        this.clock = clock;
        this.sink = sink;
        this.lock = new ReentrantLock();
        this.sinkLock = new ReentrantLock();
        this.wake = lock.newCondition();
        this.unwrapper = new SequenceUnwrapper(16);
        this.arrivals = new TreeMap<>();
        // TODO: adapt the interval to the incoming rate (50 to 250 ms, feedback kept near 5% of the media rate) as
        //  libwebrtc does; it stays at the configured value.
        this.intervalNanos = DEFAULT_INTERVAL.toNanos();
    }

    /// Creates a generator.
    ///
    /// @param senderSsrc the SSRC feedback is sent from (the receiver's RTCP SSRC)
    /// @param clock      the clock arrival times are read on
    /// @param sink       where feedback messages go, typically the RTP session's RTCP sender
    /// @return the generator, with no thread running
    /// @throws IllegalArgumentException if `senderSsrc` is not an unsigned 32-bit value
    public static TransportFeedbackGenerator create(long senderSsrc, MonotonicClock clock,
                                                    Consumer<? super RtcpPacket> sink) {
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(sink, "sink");
        checkSsrc(senderSsrc);
        return new TransportFeedbackGenerator(senderSsrc, clock, sink);
    }

    /// Records the arrival of a packet carrying a transport-wide sequence number.
    ///
    /// @param transportSequence the 16-bit sequence number from the header extension
    /// @param mediaSsrc         the SSRC of the packet; the first one seen is named as the media source of the feedback
    /// @param arrivalNanos      the arrival time, on this generator's clock
    /// @throws IllegalArgumentException if `mediaSsrc` is not an unsigned 32-bit value
    public void onPacketReceived(int transportSequence, long mediaSsrc, long arrivalNanos) {
        checkSsrc(mediaSsrc);
        lock.lock();
        try {
            if (!epochSet) {
                epochSet = true;
                epochNanos = arrivalNanos;
                this.mediaSsrc = mediaSsrc;
                lastFeedbackNanos = arrivalNanos;
            }
            var sequence = unwrapper.unwrap(transportSequence & 0xFFFF);
            if (reportingStarted) {
                if (sequence < nextToReport) {
                    return;
                }
                if (sequence - nextToReport > MAX_SEQUENCE_JUMP) {
                    arrivals.clear();
                    nextToReport = sequence;
                }
            }
            arrivals.putIfAbsent(sequence, arrivalNanos);
        } finally {
            lock.unlock();
        }
    }

    /// Sends feedback about every packet received since the last feedback, now; nothing is sent when there is
    /// nothing to report.
    public void sendFeedback() {
        List<TransportFeedback> feedback;
        lock.lock();
        try {
            feedback = buildLocked();
            lastFeedbackNanos = clock.nanos();
        } finally {
            lock.unlock();
        }
        deliver(feedback);
    }

    /// Sends feedback if the feedback interval has elapsed since the last one.
    public void process() {
        List<TransportFeedback> feedback;
        lock.lock();
        try {
            var now = clock.nanos();
            if (now - lastFeedbackNanos < intervalNanos) {
                return;
            }
            feedback = buildLocked();
            lastFeedbackNanos = now;
        } finally {
            lock.unlock();
        }
        deliver(feedback);
    }

    /// Changes the feedback interval.
    ///
    /// @param interval the interval, positive
    /// @throws IllegalArgumentException if `interval` is not positive
    public void setInterval(Duration interval) {
        Objects.requireNonNull(interval, "interval");
        if (interval.isNegative() || interval.isZero()) {
            throw new IllegalArgumentException("interval must be positive: " + interval);
        }
        lock.lock();
        try {
            intervalNanos = interval.toNanos();
            wake.signalAll();
        } finally {
            lock.unlock();
        }
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
            while (true) {
                lock.lock();
                try {
                    if (closed) {
                        return;
                    }
                    wake.awaitNanos(intervalNanos);
                    if (closed) {
                        return;
                    }
                } finally {
                    lock.unlock();
                }
                sendFeedback();
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private void deliver(List<TransportFeedback> feedback) {
        if (feedback.isEmpty()) {
            return;
        }
        sinkLock.lock();
        try {
            for (var message : feedback) {
                sink.accept(message);
            }
        } catch (RuntimeException exception) {
            LOGGER.log(System.Logger.Level.WARNING, "Transport feedback sink failed", exception);
        } finally {
            sinkLock.unlock();
        }
    }

    private List<TransportFeedback> buildLocked() {
        var result = new ArrayList<TransportFeedback>();
        if (arrivals.isEmpty()) {
            return result;
        }
        if (!reportingStarted) {
            reportingStarted = true;
            nextToReport = arrivals.firstKey();
        }
        var highest = arrivals.lastKey();
        while (nextToReport <= highest) {
            var first = arrivals.ceilingEntry(nextToReport);
            if (first == null) {
                break;
            }
            var firstMicros = micros(first.getValue());
            var referenceUnits = Math.floorDiv(firstMicros, REFERENCE_TIME_MICROS);
            var previousTicks = Math.floorDiv(referenceUnits * REFERENCE_TIME_MICROS, TICK_MICROS);
            var base = nextToReport;
            var results = new ArrayList<TransportFeedback.PacketResult>();
            var sequence = base;
            for (; sequence <= highest && results.size() < MAX_PACKETS_PER_FEEDBACK; sequence++) {
                var arrival = arrivals.get(sequence);
                if (arrival == null) {
                    results.add(new TransportFeedback.PacketResult((int) (sequence & 0xFFFF), OptionalLong.empty()));
                    continue;
                }
                var ticks = Math.floorDiv(micros(arrival), TICK_MICROS);
                var delta = ticks - previousTicks;
                if (delta < Short.MIN_VALUE || delta > Short.MAX_VALUE) {
                    break;
                }
                previousTicks = ticks;
                results.add(new TransportFeedback.PacketResult((int) (sequence & 0xFFFF),
                        OptionalLong.of(delta * TICK_MICROS)));
            }
            while (!results.isEmpty() && results.getLast().receiveDeltaMicros().isEmpty()) {
                results.removeLast();
                sequence--;
            }
            if (results.isEmpty()) {
                break;
            }
            result.add(new TransportFeedback(senderSsrc, mediaSsrc, (int) (base & 0xFFFF),
                    referenceUnits & 0xFFFFFF, feedbackCount, List.copyOf(results)));
            feedbackCount = (feedbackCount + 1) & 0xFF;
            nextToReport = sequence;
            arrivals.headMap(nextToReport, false).clear();
        }
        return result;
    }

    private long micros(long arrivalNanos) {
        return Math.floorDiv(arrivalNanos - epochNanos, 1_000L) + REFERENCE_TIME_MICROS;
    }

    private static void checkSsrc(long ssrc) {
        if (ssrc < 0 || ssrc > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("ssrc must be an unsigned 32-bit value: " + ssrc);
        }
    }
}
