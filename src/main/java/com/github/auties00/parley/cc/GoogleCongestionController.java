package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.rtcp.CongestionControlFeedback;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import com.github.auties00.parley.rtp.session.SentPacket;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/// The Google Congestion Control estimator of draft-ietf-rmcat-gcc-02, in its send-side form driven by
/// transport-wide congestion control feedback or RFC 8888 congestion control feedback.
///
/// The target is the smallest of three estimates, clamped to the configured bounds:
///
/// - the delay-based estimate: packet groups' inter-arrival delay variation is filtered into a trend, an over-use
///   detector with an adaptive threshold classifies it, and an AIMD controller raises or lowers the rate, using the
///   acknowledged throughput as the base of a decrease and the result of probes as a direct measurement;
/// - the loss-based estimate, from the loss the feedback reports (or, when no feedback arrives, from receiver
///   reports), capped at the delay-based one;
/// - the most recent REMB, the receiver's own limit.
///
/// The congestion window then bounds the bytes in flight to what the target sends in one round trip plus
/// [CongestionController#WINDOW_QUEUE_ALLOWANCE]: while more are in flight the pacer holds every packet but audio,
/// and the reported target is lowered step by step with the window's fill (and raised back as it drains). The window
/// applies only while feedback keeps arriving.
///
/// The pacer runs at the target times the configured pacing factor. Probing starts with the first sent packet: two
/// initial probes and exponential probing, then periodic probes while the sender is application-limited.
///
/// Without any feedback (a peer that only sends REMB and receiver reports) the delay-based estimate is absent and the
/// target follows the loss-based estimate capped at the REMB.
///
/// @implNote This implementation runs the loss-based controller the GCC draft specifies (section 6), not the
/// heuristic "loss-based v2" controller of later libwebrtc releases, which no specification describes; the choice is
/// deliberate.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
/// @spec https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03 RTCP message for Receiver Estimated Maximum Bitrate
final class GoogleCongestionController implements CongestionController {
    private static final System.Logger LOGGER = System.getLogger(GoogleCongestionController.class.getName());

    /// The round-trip time assumed before any measurement: 200 ms.
    static final long DEFAULT_RTT_NANOS = 200_000_000L;

    /// Receiver-report loss is used only when no feedback reported loss for this long.
    static final long TWCC_LOSS_FRESHNESS_NANOS = 2_000_000_000L;

    /// The congestion window applies only while feedback arrived within this long.
    static final long WINDOW_FEEDBACK_TIMEOUT_NANOS = 2_000_000_000L;

    /// The smallest congestion window, in bytes: a few packets, so a low target can still make progress.
    static final long MIN_WINDOW_BYTES = 6_000;

    /// The lowest share of the estimate the congestion window pushback lowers the reported target to.
    static final double MIN_PUSHBACK_RATIO = 0.1;

    /// The receivers whose report state is remembered at most; reports name local send streams only.
    static final int MAX_REPORTED_SSRCS = 64;

    /// The smoothing of feedback-derived round-trip time samples.
    private static final double RTT_SMOOTHING = 0.9;

    private final CongestionConfig config;
    private final MonotonicClock clock;
    private final Pacer pacer;
    private final ReentrantLock lock;
    private final ReentrantLock listenerLock;
    private final SendHistory history;
    private final InterArrival interArrival;
    private final TrendlineEstimator trendline;
    private final AimdRateController delayBased;
    private final LossBasedController lossBased;
    private final AcknowledgedBitrateEstimator acknowledged;
    private final ProbeController probeController;
    private final ProbeBitrateEstimator probeEstimator;
    private final Map<Long, long[]> receiverReportState;
    private final Consumer<? super TargetBitrate> listener;
    private TargetBitrate target;
    private long targetSequence;
    private long deliveredSequence;
    private long maxBitrateBps;
    private long rembLimitBps;
    private long rttNanos;
    private boolean reportedRtt;
    private boolean feedbackRttKnown;
    private boolean transportFeedbackSeen;
    private long lastFeedbackNanos;
    private long lastTwccLossNanos;
    private boolean twccLossSeen;
    private boolean probingStarted;
    private long referenceTime;
    private boolean referenceTimeKnown;
    private long reportTimestamp;
    private boolean reportTimestampKnown;
    private double pushbackRatio = 1;
    private boolean congested;

    /// Creates a controller.
    ///
    /// @param config      the configuration
    /// @param startThread whether the pacer runs its own thread; tests drive it through [Pacer#process(long)]
    GoogleCongestionController(CongestionConfig config, boolean startThread) {
        this.config = Objects.requireNonNull(config, "config");
        this.clock = config.clock();
        var startPacing = (long) (config.startBitrateBps() * config.pacingFactor());
        this.pacer = new Pacer(clock, startPacing, config.maxQueueTime().toNanos(), config.paceAudio(),
                startThread ? config.threadFactory() : null, config.failureListener());
        this.lock = new ReentrantLock();
        this.listenerLock = new ReentrantLock();
        this.history = new SendHistory();
        this.interArrival = new InterArrival();
        this.trendline = new TrendlineEstimator();
        this.delayBased = new AimdRateController(config.minBitrateBps(), config.startBitrateBps(), config.maxBitrateBps());
        this.lossBased = new LossBasedController(config.minBitrateBps(), config.startBitrateBps(), config.maxBitrateBps());
        this.acknowledged = new AcknowledgedBitrateEstimator();
        this.probeController = new ProbeController(config.maxBitrateBps());
        this.probeEstimator = new ProbeBitrateEstimator();
        this.receiverReportState = new HashMap<>();
        this.listener = config.targetListener();
        this.maxBitrateBps = config.maxBitrateBps();
        this.rembLimitBps = Long.MAX_VALUE;
        this.rttNanos = DEFAULT_RTT_NANOS;
        this.target = new TargetBitrate(config.startBitrateBps(), config.startBitrateBps(), 0,
                Duration.ofNanos(rttNanos), clock.nanos());
    }

    @Override
    public Pacer pacer() {
        return pacer;
    }

    @Override
    public TargetBitrate currentTarget() {
        lock.lock();
        try {
            return target;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long bytesInFlight() {
        lock.lock();
        try {
            return history.bytesInFlight();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void setMaxBitrate(long maxBitrateBps) {
        if (maxBitrateBps < config.minBitrateBps()) {
            throw new IllegalArgumentException("maxBitrateBps must be at least " + config.minBitrateBps());
        }
        Update update;
        lock.lock();
        try {
            var now = clock.nanos();
            this.maxBitrateBps = maxBitrateBps;
            delayBased.setMaxBitrate(maxBitrateBps);
            lossBased.setMaxBitrate(maxBitrateBps);
            var probes = probeController.onMaxBitrate(maxBitrateBps, now);
            update = recompute(now, probes);
        } finally {
            lock.unlock();
        }
        apply(update);
    }

    /// Records a sent packet; a packet sent while the pacer sends a probe is attributed to that probe.
    ///
    /// @param packet the packet
    @Override
    public void onPacketSent(SentPacket packet) {
        Objects.requireNonNull(packet, "packet");
        var cluster = Pacer.PROBE.isBound() ? Optional.of(Pacer.PROBE.get()) : Optional.<ProbeCluster>empty();
        List<ProbeCluster> initialProbes = List.of();
        boolean congestedNow;
        lock.lock();
        try {
            history.add(packet.transportSequence(), packet.ssrc(), packet.sequence(), packet.size(),
                    packet.sendNanos(), packet.priority(), cluster);
            if (!probingStarted) {
                probingStarted = true;
                initialProbes = probeController.onStart(target.bitsPerSecond(), packet.sendNanos());
            }
            congestedNow = updateCongestion(packet.sendNanos());
        } finally {
            lock.unlock();
        }
        pacer.setCongested(congestedNow);
        initialProbes.forEach(pacer::addProbe);
    }

    @Override
    public void onTransportFeedback(TransportFeedback feedback, long arrivalNanos) {
        Objects.requireNonNull(feedback, "feedback");
        Update update;
        lock.lock();
        try {
            update = handleTransportFeedback(feedback, arrivalNanos);
        } finally {
            lock.unlock();
        }
        apply(update);
    }

    @Override
    public void onCongestionControlFeedback(CongestionControlFeedback feedback, long arrivalNanos) {
        Objects.requireNonNull(feedback, "feedback");
        Update update;
        lock.lock();
        try {
            update = handleCongestionControlFeedback(feedback, arrivalNanos);
        } finally {
            lock.unlock();
        }
        apply(update);
    }

    @Override
    public void onRemb(Remb remb, long arrivalNanos) {
        Objects.requireNonNull(remb, "remb");
        Update update;
        lock.lock();
        try {
            rembLimitBps = Math.max(config.minBitrateBps(), remb.bitrateBps());
            lossBased.capAt(rembLimitBps);
            update = recompute(arrivalNanos, List.of());
        } finally {
            lock.unlock();
        }
        apply(update);
    }

    @Override
    public void onReceptionReports(List<ReceptionReport> reports, long rttNanos, long arrivalNanos) {
        Objects.requireNonNull(reports, "reports");
        Update update;
        lock.lock();
        try {
            if (rttNanos > 0) {
                this.rttNanos = rttNanos;
                reportedRtt = true;
            }
            long expected = 0;
            long lost = 0;
            for (var report : reports) {
                if (!receiverReportState.containsKey(report.ssrc())
                        && receiverReportState.size() >= MAX_REPORTED_SSRCS) {
                    continue;
                }
                var previous = receiverReportState.put(report.ssrc(),
                        new long[]{report.extendedHighestSequence(), report.cumulativeLost()});
                if (previous != null) {
                    var expectedDelta = report.extendedHighestSequence() - previous[0];
                    if (expectedDelta > 0) {
                        expected += expectedDelta;
                        lost += report.cumulativeLost() - previous[1];
                    }
                }
            }
            var twccFresh = twccLossSeen && arrivalNanos - lastTwccLossNanos < TWCC_LOSS_FRESHNESS_NANOS;
            if (!twccFresh && expected > 0) {
                lossBased.onLoss(expected, Math.clamp(lost, 0, expected), this.rttNanos, arrivalNanos);
                if (transportFeedbackSeen) {
                    lossBased.capAt(delayBased.estimate());
                }
            }
            update = recompute(arrivalNanos, List.of());
        } finally {
            lock.unlock();
        }
        apply(update);
    }

    @Override
    public void close() {
        pacer.close();
    }

    /// {@return the receivers whose report state is remembered}
    int reportedSsrcs() {
        lock.lock();
        try {
            return receiverReportState.size();
        } finally {
            lock.unlock();
        }
    }

    private record Received(SendHistory.SentPacket packet, long arrivalNanos) {
    }

    private record Update(List<ProbeCluster> probes, long pacingRateBps, long targetBps, boolean congested,
                          Optional<TargetBitrate> target, long sequence, Consumer<? super TargetBitrate> listener) {
    }

    private Update handleTransportFeedback(TransportFeedback feedback, long nowNanos) {
        var reference = feedback.referenceTime64ms() & 0xFFFFFF;
        referenceTime = referenceTimeKnown ? SequenceUnwrapper.nearest(referenceTime, reference, 1 << 24) : reference;
        referenceTimeKnown = true;
        var arrivalNanos = referenceTime * 64_000_000L;
        var received = new ArrayList<Received>();
        long expected = 0;
        long lost = 0;
        for (var result : feedback.results()) {
            var unwrapped = history.unwrap(result.transportSequence());
            var sent = history.get(unwrapped);
            if (sent.isPresent()) {
                history.markReported(unwrapped);
            }
            if (result.receiveDeltaMicros().isPresent()) {
                arrivalNanos += result.receiveDeltaMicros().getAsLong() * 1_000L;
                if (sent.isPresent()) {
                    received.add(new Received(sent.get(), arrivalNanos));
                    expected++;
                }
            } else if (sent.isPresent()) {
                expected++;
                lost++;
            }
        }
        return onFeedback(received, expected, lost, nowNanos);
    }

    /// Matches RFC 8888 feedback against the send history by SSRC and sequence number. A packet reported more than
    /// once (reports overlap when a receiver repeats its window) counts only the first time.
    private Update handleCongestionControlFeedback(CongestionControlFeedback feedback, long nowNanos) {
        var timestamp = feedback.reportTimestamp();
        reportTimestamp = reportTimestampKnown
                ? SequenceUnwrapper.nearest(reportTimestamp, timestamp, 1L << 32) : timestamp;
        reportTimestampKnown = true;
        var reportNanos = reportTimestamp / 65_536 * 1_000_000_000L
                + (reportTimestamp % 65_536) * 1_000_000_000L / 65_536;
        var received = new ArrayList<Received>();
        long expected = 0;
        long lost = 0;
        for (var report : feedback.reports()) {
            var sequence = report.beginSequence();
            for (var metric : report.metrics()) {
                var sent = history.takeBySsrc(report.ssrc(), sequence);
                sequence = (sequence + 1) & 0xFFFF;
                if (sent.isEmpty()) {
                    continue;
                }
                expected++;
                if (!metric.received()) {
                    lost++;
                    continue;
                }
                var offset = metric.arrivalTimeOffset();
                if (offset == CongestionControlFeedback.Metric.OVER_RANGE
                        || offset == CongestionControlFeedback.Metric.UNAVAILABLE) {
                    continue;
                }
                received.add(new Received(sent.get(), reportNanos - offset * 1_000_000_000L / 1_024));
            }
        }
        return onFeedback(received, expected, lost, nowNanos);
    }

    /// Runs the estimators on the packets one feedback reported.
    private Update onFeedback(List<Received> received, long expected, long lost, long nowNanos) {
        transportFeedbackSeen = true;
        lastFeedbackNanos = nowNanos;
        if (expected > 0) {
            lossBased.onLoss(expected, lost, rttNanos, nowNanos);
            lastTwccLossNanos = nowNanos;
            twccLossSeen = true;
        }
        if (received.isEmpty()) {
            return recompute(nowNanos, List.of());
        }
        received.sort(Comparator.comparingLong(Received::arrivalNanos));
        var lastSent = received.stream().mapToLong(packet -> packet.packet().sendNanos()).max().orElseThrow();
        updateFeedbackRtt(nowNanos - lastSent);
        OptionalLong probeResult = OptionalLong.empty();
        for (var packet : received) {
            acknowledged.onPacket(packet.arrivalNanos(), packet.packet().sizeBytes());
            if (packet.packet().probe().isPresent()) {
                var estimate = probeEstimator.onProbePacket(packet.packet().probe().get(), packet.packet().sendNanos(),
                        packet.arrivalNanos(), packet.packet().sizeBytes(), nowNanos);
                if (estimate.isPresent()) {
                    probeResult = estimate;
                }
            }
            interArrival.onPacket(packet.packet().sendNanos(), packet.arrivalNanos(), packet.packet().sizeBytes())
                    .ifPresent(trendline::update);
        }
        var usage = trendline.state();
        if (probeResult.isPresent() && usage != BandwidthUsage.OVERUSING) {
            delayBased.setEstimate(probeResult.getAsLong(), nowNanos);
            lossBased.raiseTo(probeResult.getAsLong());
        } else {
            delayBased.update(usage, acknowledged.estimate(), rttNanos, nowNanos);
        }
        lossBased.capAt(delayBased.estimate());
        var probes = new ArrayList<>(probeController.onEstimate(delayBased.estimate(), nowNanos));
        probes.addAll(probeController.onProcess(pacer.alrStartNanos(), nowNanos));
        return recompute(nowNanos, probes);
    }

    private void updateFeedbackRtt(long sampleNanos) {
        if (reportedRtt || sampleNanos <= 0) {
            return;
        }
        rttNanos = feedbackRttKnown ? (long) (RTT_SMOOTHING * rttNanos + (1 - RTT_SMOOTHING) * sampleNanos) : sampleNanos;
        feedbackRttKnown = true;
    }

    /// {@return the congestion window in bytes for an estimate}
    private long window(long bitrateBps) {
        var nanos = rttNanos + WINDOW_QUEUE_ALLOWANCE.toNanos();
        return Math.max(MIN_WINDOW_BYTES, bitrateBps / 8 * nanos / 1_000_000_000L);
    }

    /// {@return whether the window is full now}; updates [#congested]. Called under the lock.
    private boolean updateCongestion(long nowNanos) {
        congested = config.congestionWindow() && transportFeedbackSeen
                && nowNanos - lastFeedbackNanos < WINDOW_FEEDBACK_TIMEOUT_NANOS
                && history.bytesInFlight() > window(estimate());
        return congested;
    }

    /// {@return the estimate before the congestion window pushback}
    private long estimate() {
        var delay = transportFeedbackSeen ? delayBased.estimate() : Long.MAX_VALUE;
        var bitrate = Math.min(Math.min(delay, lossBased.estimate()), rembLimitBps);
        return Math.clamp(bitrate, config.minBitrateBps(), maxBitrateBps);
    }

    /// Steps the pushback ratio with the window's fill, as libwebrtc's congestion window pushback does. Called under
    /// the lock with feedback.
    private void updatePushback(long bitrate, long nowNanos) {
        if (!config.congestionWindow() || !transportFeedbackSeen
                || nowNanos - lastFeedbackNanos >= WINDOW_FEEDBACK_TIMEOUT_NANOS) {
            pushbackRatio = 1;
            return;
        }
        var fill = (double) history.bytesInFlight() / window(bitrate);
        if (fill > 1.5) {
            pushbackRatio *= 0.9;
        } else if (fill > 1) {
            pushbackRatio *= 0.95;
        } else if (fill < 0.1) {
            pushbackRatio = 1;
        } else {
            pushbackRatio = Math.min(1, pushbackRatio * 1.05);
        }
        pushbackRatio = Math.max(MIN_PUSHBACK_RATIO, pushbackRatio);
    }

    private Update recompute(long nowNanos, List<ProbeCluster> probes) {
        var estimate = estimate();
        updatePushback(estimate, nowNanos);
        var bitrate = Math.max(config.minBitrateBps(), (long) (estimate * pushbackRatio));
        var stable = Math.min(bitrate, delayBased.linkCapacity().orElse(bitrate));
        stable = Math.max(stable, Math.min(config.minBitrateBps(), bitrate));
        var pacing = Math.max(1, (long) (estimate * config.pacingFactor()));
        Optional<TargetBitrate> changed = Optional.empty();
        if (bitrate != target.bitsPerSecond() || stable != target.stableBitsPerSecond()) {
            target = new TargetBitrate(bitrate, stable, lossBased.lossRatio(), Duration.ofNanos(rttNanos), nowNanos);
            targetSequence++;
            changed = Optional.of(target);
        }
        var congestedNow = updateCongestion(nowNanos);
        return new Update(List.copyOf(probes), pacing, bitrate, congestedNow, changed, targetSequence, listener);
    }

    private void apply(Update update) {
        pacer.setRates(update.pacingRateBps(), update.targetBps());
        pacer.setCongested(update.congested());
        update.probes().forEach(pacer::addProbe);
        if (update.target().isEmpty()) {
            return;
        }
        listenerLock.lock();
        try {
            if (update.sequence() <= deliveredSequence) {
                return;
            }
            deliveredSequence = update.sequence();
            update.listener().accept(update.target().get());
        } catch (RuntimeException exception) {
            LOGGER.log(System.Logger.Level.WARNING, "Target listener failed", exception);
        } finally {
            listenerLock.unlock();
        }
    }
}
