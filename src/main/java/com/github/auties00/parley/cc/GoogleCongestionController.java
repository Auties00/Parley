package com.github.auties00.parley.cc;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.function.Consumer;
import java.util.concurrent.locks.ReentrantLock;

/// The Google Congestion Control estimator of draft-ietf-rmcat-gcc-02, in its send-side form driven by
/// transport-wide congestion control feedback.
///
/// The target is the smallest of three estimates, clamped to the configured bounds:
///
/// - the delay-based estimate: packet groups' inter-arrival delay variation is filtered into a trend, an over-use
///   detector with an adaptive threshold classifies it, and an AIMD controller raises or lowers the rate, using the
///   acknowledged throughput as the base of a decrease and the result of probes as a direct measurement;
/// - the loss-based estimate, from the loss transport feedback reports (or, when no transport feedback arrives,
///   from receiver reports), capped at the delay-based one;
/// - the most recent REMB, the receiver's own limit.
///
/// The pacer runs at the target times the configured pacing factor. Probing starts with the first sent packet:
/// two initial probes and exponential probing, then periodic probes while the sender is application-limited.
///
/// Without any transport feedback (a peer that only sends REMB and receiver reports) the delay-based estimate is
/// absent and the target follows the loss-based estimate capped at the REMB.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 RTP Extensions for Transport-wide Congestion Control
/// @spec https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03 RTCP message for Receiver Estimated Maximum Bitrate
public final class GoogleCongestionController implements CongestionController {
    private static final System.Logger LOGGER = System.getLogger(GoogleCongestionController.class.getName());

    /// The round-trip time assumed before any measurement: 200 ms.
    static final long DEFAULT_RTT_NANOS = 200_000_000L;

    /// Receiver-report loss is used only when no transport feedback reported loss for this long.
    static final long TWCC_LOSS_FRESHNESS_NANOS = 2_000_000_000L;

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
    private Consumer<TargetBitrate> listener;
    private TargetBitrate target;
    private long targetSequence;
    private long deliveredSequence;
    private long maxBitrateBps;
    private long rembLimitBps;
    private long rttNanos;
    private boolean reportedRtt;
    private boolean feedbackRttKnown;
    private boolean transportFeedbackSeen;
    private long lastTwccLossNanos;
    private boolean twccLossSeen;
    private boolean probingStarted;
    private long referenceTime;
    private boolean referenceTimeKnown;

    /// Creates a controller.
    ///
    /// @param config      the configuration
    /// @param startThread whether the pacer runs its own thread; tests drive it through [Pacer#process(long)]
    GoogleCongestionController(CongestionConfig config, boolean startThread) {
        this.config = Objects.requireNonNull(config, "config");
        this.clock = config.clock();
        var startPacing = (long) (config.startBitrateBps() * config.pacingFactor());
        this.pacer = new Pacer(clock, startPacing, config.maxQueueTime().toNanos(), config.paceAudio(),
                startThread ? config.threadFactory() : null);
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
        this.listener = _ -> {
        };
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
    public void setTargetListener(Consumer<TargetBitrate> listener) {
        Objects.requireNonNull(listener, "listener");
        lock.lock();
        try {
            this.listener = listener;
        } finally {
            lock.unlock();
        }
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
    /// @param transportSequence the 16-bit transport-wide sequence number the packet carries
    /// @param sizeBytes         the packet size on the wire, before SRTP
    /// @param sendNanos         when it was sent, on this controller's clock
    /// @param priority          its priority class
    /// @param probe             whether the session knows it is a probe
    @Override
    public void onPacketSent(int transportSequence, int sizeBytes, long sendNanos,
                             OutgoingPacketScheduler.Priority priority, boolean probe) {
        Objects.requireNonNull(priority, "priority");
        var cluster = Pacer.PROBE.isBound() ? Optional.of(Pacer.PROBE.get()) : Optional.<ProbeCluster>empty();
        List<ProbeCluster> initialProbes = List.of();
        lock.lock();
        try {
            history.add(transportSequence, sizeBytes, sendNanos, priority, cluster);
            if (!probingStarted) {
                probingStarted = true;
                initialProbes = probeController.onStart(target.bitsPerSecond(), sendNanos);
            }
        } finally {
            lock.unlock();
        }
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
                lossBased.onLoss(expected, lost, this.rttNanos, arrivalNanos);
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

    private record Received(SendHistory.SentPacket packet, long arrivalNanos) {
    }

    private record Update(List<ProbeCluster> probes, long pacingRateBps, long targetBps,
                          Optional<TargetBitrate> target, long sequence, Consumer<TargetBitrate> listener) {
    }

    private Update handleTransportFeedback(TransportFeedback feedback, long nowNanos) {
        transportFeedbackSeen = true;
        var reference = feedback.referenceTime64ms() & 0xFFFFFF;
        referenceTime = referenceTimeKnown ? SequenceUnwrapper.nearest(referenceTime, reference, 1 << 24) : reference;
        referenceTimeKnown = true;
        var arrivalNanos = referenceTime * 64_000_000L;
        var received = new ArrayList<Received>();
        long expected = 0;
        long lost = 0;
        for (var result : feedback.results()) {
            var sent = history.get(history.unwrap(result.transportSequence()));
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

    private Update recompute(long nowNanos, List<ProbeCluster> probes) {
        var delay = transportFeedbackSeen ? delayBased.estimate() : Long.MAX_VALUE;
        var bitrate = Math.min(Math.min(delay, lossBased.estimate()), rembLimitBps);
        bitrate = Math.clamp(bitrate, config.minBitrateBps(), maxBitrateBps);
        var stable = Math.min(bitrate, delayBased.linkCapacity().orElse(bitrate));
        stable = Math.max(stable, Math.min(config.minBitrateBps(), bitrate));
        var pacing = Math.max(1, (long) (bitrate * config.pacingFactor()));
        Optional<TargetBitrate> changed = Optional.empty();
        if (bitrate != target.bitsPerSecond() || stable != target.stableBitsPerSecond()) {
            target = new TargetBitrate(bitrate, stable, lossBased.lossRatio(), Duration.ofNanos(rttNanos), nowNanos);
            targetSequence++;
            changed = Optional.of(target);
        }
        return new Update(List.copyOf(probes), pacing, bitrate, changed, targetSequence, listener);
    }

    private void apply(Update update) {
        pacer.setRates(update.pacingRateBps(), update.targetBps());
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
