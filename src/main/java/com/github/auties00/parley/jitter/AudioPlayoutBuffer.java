package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.AudioFrameMetadata;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.ComfortNoiseFormat;
import com.github.auties00.parley.payload.Depacketizer;
import com.github.auties00.parley.payload.OpusFormat;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.payload.PayloadFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.session.NtpRtpMapping;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/// An adaptive playout buffer for one incoming audio stream: it absorbs network jitter and hands out exactly one
/// outcome per frame duration, at the instant that audio should play.
///
/// The receiving thread [inserts][#insert(RtpPacket,long)] packets as they arrive; the playing thread calls
/// [#next()], which blocks until the next playout instant and returns the frame due then, or says the frame is
/// [missing][AudioPlayout.Missing] (lost or late, to conceal) or that the sender is [silent][AudioPlayout.Silence]
/// (discontinuous transmission). The buffer never decodes or time-stretches audio: it tells the application when to
/// conceal and when frames were dropped.
///
/// {@snippet lang = java :
/// var buffer = AudioPlayoutBuffer.create(OpusFormat.defaults(), 48000, AudioPlayoutConfig.defaults());
/// receiveStream.setPacketReceiver(packet -> buffer.insert(packet, clock.nanos()));
/// Thread.ofVirtual().start(() -> {
///     while (true) {
///         play(buffer.next());
///     }
/// });
/// }
///
/// # Delay
///
/// The buffer delays each frame by a target delay: the 95th percentile of the recent packet delays (each packet's
/// transit time above the fastest recent one) or twice the RFC 3550 interarrival jitter, whichever is larger, kept
/// between the configured minimum and maximum, never below the `jitterBufferTarget`, and within the bounds of the
/// `playout-delay` header extension when the stream carries it. At the start of each
/// talkspurt (a packet with the marker bit after silence or loss) the schedule restarts at the current target. While
/// audio plays and the actual delay drifts more than a frame away from the target, the buffer conceals one extra
/// frame to grow the delay ([AudioPlayoutStatistics#insertedSamplesForDeceleration()]) or skips one frame to shrink
/// it ([AudioPlayoutStatistics#removedSamplesForAcceleration()]), at most once per ten frames. A [SyncGroup] the
/// buffer belongs to adds its share of lip-sync delay to the target.
///
/// # Capture time
///
/// Each frame handed out carries its capture time on the sender's clock ([EncodedFrame#captureTime()]): from the
/// `abs-capture-time` header extension when the stream carries it, else from the RTP to NTP mapping of the latest
/// sender report, which the receiving side passes in with [#setSenderClock(NtpRtpMapping)].
///
/// # Threading
///
/// All methods are safe to call from any thread. [#next()] is meant for one consumer thread.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html#appendix-A.8 RFC 3550 appendix A.8: Estimating the Interarrival Jitter
/// @spec https://www.w3.org/TR/webrtc-extensions/#dom-rtcrtpreceiver-jitterbuffertarget W3C WebRTC Extensions: jitterBufferTarget
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/playout-delay/README.md WebRTC: Playout Delay
public final class AudioPlayoutBuffer implements AutoCloseable {
    /// The number of recent packet delays the percentile is taken over: about two seconds of 20 ms frames.
    private static final int HISTORY = 100;

    /// The percentile of the packet delays the target covers.
    private static final double PERCENTILE = 0.95;

    /// The frames between two delay adaptations while audio plays.
    private static final int ADAPTATION_SPACING = 10;

    /// The longest a blocked [#next()] waits before checking the clock again, in nanoseconds.
    private static final long MAX_WAIT_NANOS = TimeUnit.MILLISECONDS.toNanos(20);

    /// The payload format.
    private final PayloadFormat format;

    /// The RTP clock rate.
    private final int clockRate;

    /// The clock.
    private final MonotonicClock clock;

    /// The settings.
    private final AudioPlayoutConfig config;

    /// The depacketizer.
    private final Depacketizer depacketizer;

    /// Whether the format's payloads are comfort noise or DTX by nature.
    private final boolean comfortNoiseFormat;

    /// The lock that guards every field below.
    private final ReentrantLock lock = new ReentrantLock();

    /// Signalled on every insert and on close.
    private final Condition changed = lock.newCondition();

    /// The buffered packets by unwrapped timestamp.
    private final TreeMap<Long, Slot> packets = new TreeMap<>();

    /// The recent transit times in nanoseconds, oldest first.
    private final ArrayDeque<Long> transits = new ArrayDeque<>();

    /// The unwrapper of RTP timestamps.
    private final Unwrapper timestamps = new Unwrapper(32);

    /// The unwrapper of sequence numbers.
    private final Unwrapper sequences = new Unwrapper(16);

    /// The capture clock and playout delay bounds of the stream.
    private final CaptureClock captureClock;

    /// The lip-sync state.
    private final SyncState sync = new SyncState();

    /// The capture time of the last frame played, or `null`.
    private Instant lastCaptureTime;

    /// When the last frame with a capture time played, in clock nanoseconds.
    private long lastCapturePlayoutNanos;

    /// The audio level of the last frame played, `0` to `1`, or `NaN` when unknown.
    private double audioLevel = Double.NaN;

    /// The sum over frames of the squared audio level times their duration in seconds.
    private double totalAudioEnergy;

    /// The application's preferred delay.
    private Optional<Duration> jitterBufferTarget;

    /// The RFC 3550 jitter estimate, in timestamp units.
    private double jitter;

    /// The previous transit time in timestamp units, or `NaN` before the first packet.
    private double previousTransit = Double.NaN;

    /// Whether the playout schedule runs.
    private boolean running;

    /// The unwrapped timestamp of the next outcome.
    private long nextTimestamp;

    /// The playout instant of the next outcome, in clock nanoseconds.
    private long nextPlayoutNanos;

    /// The duration of the last frame, in timestamp units.
    private long frameUnits;

    /// The unwrapped sequence number of the last frame played, or `-1`.
    private long lastPlayedSequence = -1;

    /// Whether the last frame played was a silence frame (DTX or comfort noise).
    private boolean lastPlayedSilent;

    /// The length of the current run of missing outcomes, in timestamp units.
    private long missingRunUnits;

    /// Frames played since the last adaptation.
    private int framesSinceAdaptation = ADAPTATION_SPACING;

    /// Whether the buffer is closed.
    private boolean closed;

    /// The packets inserted.
    private long packetsReceived;

    /// The packets that arrived after their playout instant.
    private long packetsLate;

    /// The packets dropped.
    private long packetsDiscarded;

    /// The summed time from arrival to playout, in nanoseconds.
    private long jitterBufferDelayNanos;

    /// The summed target delay at each playout, in nanoseconds.
    private long jitterBufferTargetDelayNanos;

    /// The summed network delay at each playout, in nanoseconds.
    private long jitterBufferMinimumDelayNanos;

    /// The frames emitted.
    private long emittedCount;

    /// The samples emitted or concealed.
    private long totalSamples;

    /// The samples concealed or filled with silence.
    private long concealedSamples;

    /// The samples filled with silence.
    private long silentConcealedSamples;

    /// The runs of missing outcomes.
    private long concealmentEvents;

    /// The samples concealed to grow the delay.
    private long insertedSamples;

    /// The samples skipped to shrink the delay.
    private long removedSamples;

    /// One buffered packet.
    ///
    /// @param packet   the packet, a copy that owns its bytes
    /// @param sequence the unwrapped sequence number
    /// @param arrival  the arrival time in clock nanoseconds
    private record Slot(RtpPacket packet, long sequence, long arrival) {
    }

    /// Creates a buffer.
    private AudioPlayoutBuffer(PayloadFormat format, int clockRate, AudioPlayoutConfig config) {
        this.format = format;
        this.clockRate = clockRate;
        this.clock = config.clock();
        this.config = config;
        this.depacketizer = format.depacketizer(config.depacketizer());
        this.comfortNoiseFormat = format instanceof ComfortNoiseFormat;
        this.jitterBufferTarget = config.jitterBufferTarget();
        this.frameUnits = Math.max(1, toUnits(config.defaultFrameDuration().toNanos()));
        this.captureClock = new CaptureClock(clockRate, config.depacketizer().absCaptureTimeExtensionId(),
                config.depacketizer().playoutDelayExtensionId());
    }

    /// Creates a playout buffer for one incoming audio stream.
    ///
    /// @param format    the stream's payload format, an audio format
    /// @param clockRate the RTP clock rate of the stream, positive
    /// @param config    the settings
    /// @return the buffer
    /// @throws IllegalArgumentException if `format` is not an audio format or `clockRate` is not positive
    public static AudioPlayoutBuffer create(PayloadFormat format, int clockRate, AudioPlayoutConfig config) {
        Objects.requireNonNull(format, "format cannot be null");
        Objects.requireNonNull(config, "config cannot be null");
        if (format.kind() != MediaKind.AUDIO) {
            throw new IllegalArgumentException("not an audio format: " + format);
        }
        if (clockRate <= 0) {
            throw new IllegalArgumentException("clock rate must be positive: " + clockRate);
        }
        return new AudioPlayoutBuffer(format, clockRate, config);
    }

    /// Inserts a packet of the stream.
    ///
    /// The buffer keeps a copy, so the packet's buffer may be reused once this returns. A malformed, duplicate or
    /// late packet, or one beyond the packet limit, is counted and dropped.
    ///
    /// @param packet       the packet
    /// @param arrivalNanos the arrival time, from the buffer's clock
    public void insert(RtpPacket packet, long arrivalNanos) {
        Objects.requireNonNull(packet, "packet cannot be null");
        if (!depacketizer.inspect(packet).valid()) {
            lock.lock();
            try {
                packetsReceived++;
                packetsDiscarded++;
            } finally {
                lock.unlock();
            }
            return;
        }
        var copy = packet.copy();
        lock.lock();
        try {
            if (closed) {
                return;
            }
            packetsReceived++;
            captureClock.observe(copy);
            var timestamp = timestamps.unwrap(copy.timestamp());
            var sequence = sequences.unwrap(copy.sequence());
            updateJitter(timestamp, arrivalNanos);
            if (running && timestamp < nextTimestamp) {
                packetsLate++;
                packetsDiscarded++;
                return;
            }
            if (packets.containsKey(timestamp)) {
                packetsDiscarded++;
                return;
            }
            if (running && copy.marker() && packets.isEmpty() && (lastPlayedSilent || missingRunUnits > 0)) {
                running = false;
            }
            if (running && timestamp - nextTimestamp > toUnits(config.maximumDelay().toNanos()) + frameUnits
                    && packets.isEmpty()) {
                running = false;
            }
            packets.put(timestamp, new Slot(copy, sequence, arrivalNanos));
            while (packets.size() > config.maxPackets()) {
                packets.pollFirstEntry();
                packetsDiscarded++;
            }
            if (!running) {
                start(arrivalNanos);
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Blocks until the next playout instant and returns its outcome.
    ///
    /// Before the first packet, and after an outage longer than the maximum delay, the buffer has no schedule; the
    /// call then waits for a packet.
    ///
    /// @return the outcome due at the playout instant
    /// @throws InterruptedException  if the thread is interrupted while waiting
    /// @throws IllegalStateException if the buffer is closed
    public AudioPlayout next() throws InterruptedException {
        AudioPlayout result;
        lock.lockInterruptibly();
        try {
            while (true) {
                var outcome = due();
                if (outcome.isPresent()) {
                    result = outcome.get();
                    break;
                }
                changed.awaitNanos(waitNanos(MAX_WAIT_NANOS));
            }
        } finally {
            lock.unlock();
        }
        return played(result);
    }

    /// Waits up to a timeout for the next playout instant and returns its outcome.
    ///
    /// @param timeout the longest to wait
    /// @return the outcome, or an empty optional when none was due within the timeout
    /// @throws InterruptedException  if the thread is interrupted while waiting
    /// @throws IllegalStateException if the buffer is closed
    public Optional<AudioPlayout> next(Duration timeout) throws InterruptedException {
        var deadline = System.nanoTime() + timeout.toNanos();
        Optional<AudioPlayout> result;
        lock.lockInterruptibly();
        try {
            while (true) {
                var outcome = due();
                if (outcome.isPresent()) {
                    result = outcome;
                    break;
                }
                var remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    return Optional.empty();
                }
                changed.awaitNanos(waitNanos(Math.min(remaining, MAX_WAIT_NANOS)));
            }
        } finally {
            lock.unlock();
        }
        return result.map(this::played);
    }

    /// {@return the outcome whose playout instant has come by the buffer's clock, without waiting, or an empty
    /// optional when none is due yet}
    ///
    /// @throws IllegalStateException if the buffer is closed
    public Optional<AudioPlayout> poll() {
        Optional<AudioPlayout> result;
        lock.lock();
        try {
            result = due();
        } finally {
            lock.unlock();
        }
        return result.map(this::played);
    }

    /// {@return an outcome, after telling the synchronization group a frame played}
    private AudioPlayout played(AudioPlayout outcome) {
        if (outcome instanceof AudioPlayout.Frame) {
            sync.notifyPlayout();
        }
        return outcome;
    }

    /// Sets the application's preferred delay, the W3C `jitterBufferTarget`; it applies from the next adaptation.
    ///
    /// @param target the preferred delay, `0..4000` ms
    /// @throws IllegalArgumentException if `target` is out of range
    public void setJitterBufferTarget(Duration target) {
        var wrapped = Optional.of(target);
        AudioPlayoutConfig.checkTarget(wrapped);
        lock.lock();
        try {
            jitterBufferTarget = wrapped;
        } finally {
            lock.unlock();
        }
    }

    /// Removes the application's preferred delay, letting the buffer decide; it applies from the next adaptation.
    public void clearJitterBufferTarget() {
        lock.lock();
        try {
            jitterBufferTarget = Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    /// Sets the RTP to NTP mapping of the stream's latest RTCP sender report, which dates the frames that carry no
    /// `abs-capture-time`; call it on every sender report.
    ///
    /// @param mapping the mapping
    /// @spec https://www.rfc-editor.org/rfc/rfc3550.html#section-6.4.1 RFC 3550 section 6.4.1: SR: Sender Report RTCP Packet
    public void setSenderClock(NtpRtpMapping mapping) {
        Objects.requireNonNull(mapping, "mapping cannot be null");
        lock.lock();
        try {
            captureClock.setSenderClock(mapping);
        } finally {
            lock.unlock();
        }
    }

    /// {@return the synchronization state, for [SyncGroup]}
    SyncState syncMember() {
        return sync;
    }

    /// {@return the current target delay}
    public Duration targetDelay() {
        lock.lock();
        try {
            return Duration.ofNanos(targetNanos());
        } finally {
            lock.unlock();
        }
    }

    /// {@return a snapshot of the buffer's counters}
    public AudioPlayoutStatistics statistics() {
        lock.lock();
        try {
            var estimated = lastCaptureTime == null ? Optional.<Instant>empty()
                    : Optional.of(lastCaptureTime.plusNanos(Math.max(0, clock.nanos() - lastCapturePlayoutNanos)));
            return new AudioPlayoutStatistics(packetsReceived, packetsLate, packetsDiscarded,
                    Duration.ofNanos(toNanos((long) jitter)), Duration.ofNanos(jitterBufferDelayNanos),
                    Duration.ofNanos(jitterBufferTargetDelayNanos), Duration.ofNanos(jitterBufferMinimumDelayNanos),
                    emittedCount, totalSamples, concealedSamples, silentConcealedSamples, concealmentEvents,
                    insertedSamples, removedSamples, Duration.ofNanos(targetNanos()), clockRate, estimated,
                    Double.isNaN(audioLevel) ? OptionalDouble.empty() : OptionalDouble.of(audioLevel),
                    totalAudioEnergy, Duration.ofNanos(sync.syncDelayNanos()));
        } finally {
            lock.unlock();
        }
    }

    /// Closes the buffer: buffered packets are dropped, later inserts are ignored, and a blocked [#next()] throws
    /// [IllegalStateException]. Closing twice has no effect.
    @Override
    public void close() {
        lock.lock();
        try {
            closed = true;
            packets.clear();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        sync.leave();
    }

    /// Starts the schedule at a packet arriving now.
    private void start(long arrivalNanos) {
        var first = packets.firstEntry();
        nextTimestamp = first.getKey();
        nextPlayoutNanos = Math.max(arrivalNanos, clock.nanos()) + targetNanos();
        running = true;
        missingRunUnits = 0;
        framesSinceAdaptation = ADAPTATION_SPACING;
    }

    /// {@return how long to wait for the next playout instant, at most `cap`}
    private long waitNanos(long cap) {
        if (!running) {
            return cap;
        }
        return Math.max(1, Math.min(cap, nextPlayoutNanos - clock.nanos()));
    }

    /// {@return the outcome due now, advancing the schedule}
    private Optional<AudioPlayout> due() {
        if (closed) {
            throw new IllegalStateException("playout buffer closed");
        }
        if (!running) {
            return Optional.empty();
        }
        var now = clock.nanos();
        if (now < nextPlayoutNanos) {
            return Optional.empty();
        }
        var target = targetNanos();
        var slot = packets.get(nextTimestamp);
        if (slot != null && framesSinceAdaptation >= ADAPTATION_SPACING && !packets.isEmpty()) {
            var excess = bufferedDelayNanos(now) - target;
            if (excess > toNanos(frameUnits) && packets.size() > 1) {
                var units = durationOf(nextTimestamp, slot);
                packets.remove(nextTimestamp);
                removedSamples += units;
                packetsDiscarded++;
                nextTimestamp += units;
                framesSinceAdaptation = 0;
                slot = packets.get(nextTimestamp);
            } else if (-excess > toNanos(frameUnits) && !lastPlayedSilent) {
                framesSinceAdaptation = 0;
                insertedSamples += frameUnits;
                return Optional.of(conceal(frameUnits, false));
            }
        }
        if (slot != null) {
            var units = durationOf(nextTimestamp, slot);
            packets.remove(nextTimestamp);
            return Optional.of(play(slot, units, now, target));
        }
        var later = packets.ceilingEntry(nextTimestamp);
        if (later != null) {
            var gap = later.getKey() - nextTimestamp;
            if (lastPlayedSequence >= 0 && later.getValue().sequence() == lastPlayedSequence + 1) {
                nextTimestamp = later.getKey();
                nextPlayoutNanos += toNanos(gap);
                return Optional.of(silence(gap));
            }
            return Optional.of(conceal(Math.min(gap, frameUnits), true));
        }
        if (lastPlayedSilent) {
            nextTimestamp += frameUnits;
            nextPlayoutNanos += toNanos(frameUnits);
            return Optional.of(silence(frameUnits));
        }
        if (missingRunUnits >= toUnits(config.maximumDelay().toNanos())) {
            running = false;
            return Optional.empty();
        }
        return Optional.of(conceal(frameUnits, true));
    }

    /// {@return the outcome of a buffered frame played now}
    private AudioPlayout play(Slot slot, long units, long now, long target) {
        frameUnits = units;
        var frame = assemble(slot);
        lastPlayedSequence = slot.sequence();
        lastPlayedSilent = comfortNoiseFormat || format instanceof OpusFormat && OpusFormat.isDtx(slot.packet().payload());
        missingRunUnits = 0;
        framesSinceAdaptation++;
        emittedCount++;
        totalSamples += units;
        jitterBufferDelayNanos += Math.max(0, now - slot.arrival());
        jitterBufferTargetDelayNanos += target;
        jitterBufferMinimumDelayNanos += networkDelayNanos();
        nextTimestamp += units;
        nextPlayoutNanos += toNanos(units);
        if (frame.isEmpty()) {
            packetsDiscarded++;
            concealedSamples += units;
            return new AudioPlayout.Missing(slot.packet().timestamp(), Duration.ofNanos(toNanos(units)));
        }
        var played = frame.get();
        if (played.captureTime().isEmpty()) {
            var capture = captureClock.captureTimeOf(slot.packet().timestamp());
            if (capture.isPresent()) {
                played = played.withCaptureTime(capture.get());
            }
        }
        if (played.captureTime().isPresent()) {
            lastCaptureTime = played.captureTime().get();
            lastCapturePlayoutNanos = now;
            sync.record(now, lastCaptureTime);
        }
        if (played.metadata() instanceof AudioFrameMetadata audio && audio.audioLevelDbov().isPresent()) {
            audioLevel = Math.pow(10, -audio.audioLevelDbov().getAsInt() / 20.0);
            totalAudioEnergy += audioLevel * audioLevel * units / clockRate;
        }
        return new AudioPlayout.Frame(played, Duration.ofNanos(toNanos(units)));
    }

    /// {@return a missing outcome; `advance` false keeps the timestamp to grow the delay}
    private AudioPlayout conceal(long units, boolean advance) {
        if (missingRunUnits == 0) {
            concealmentEvents++;
        }
        missingRunUnits += units;
        concealedSamples += units;
        totalSamples += units;
        var timestamp = nextTimestamp & 0xFFFFFFFFL;
        if (advance) {
            nextTimestamp += units;
        }
        nextPlayoutNanos += toNanos(units);
        return new AudioPlayout.Missing(timestamp, Duration.ofNanos(toNanos(units)));
    }

    /// {@return a silence outcome, counting it; the caller moves the schedule}
    private AudioPlayout silence(long units) {
        missingRunUnits = 0;
        silentConcealedSamples += units;
        concealedSamples += units;
        totalSamples += units;
        return new AudioPlayout.Silence(Duration.ofNanos(toNanos(units)));
    }

    /// {@return the assembled frame of a slot, or empty when its payload does not parse}
    private Optional<EncodedFrame> assemble(Slot slot) {
        try {
            return Optional.of(depacketizer.assemble(List.of(slot.packet())));
        } catch (PayloadFormatException exception) {
            return Optional.empty();
        }
    }

    /// {@return the duration of a buffered packet in timestamp units: what its payload says, else the gap to the next
    /// buffered packet when that is plausible, else the last frame duration}
    private long durationOf(long timestamp, Slot slot) {
        var duration = format.timestampDuration(slot.packet().payload());
        if (duration.isPresent() && duration.getAsInt() > 0) {
            return duration.getAsInt();
        }
        var next = packets.higherKey(timestamp);
        if (next != null && next - timestamp > 0 && next - timestamp <= 4 * frameUnits) {
            return next - timestamp;
        }
        return frameUnits;
    }

    /// {@return how long the buffered audio delays playout now: from the newest arrival's ideal playout to its
    /// scheduled one}
    private long bufferedDelayNanos(long now) {
        if (packets.isEmpty()) {
            return 0;
        }
        var last = packets.lastEntry();
        var scheduled = nextPlayoutNanos + toNanos(last.getKey() - nextTimestamp);
        return scheduled - last.getValue().arrival();
    }

    /// {@return the target delay in nanoseconds: the estimate within the configured bounds, the playout delay bounds
    /// the stream carries and the `jitterBufferTarget`, plus the lip-sync delay, never above the maximum}
    private long targetNanos() {
        var estimate = Math.max(percentileNanos(), toNanos((long) (2 * jitter)));
        var maximum = config.maximumDelay().toNanos();
        if (captureClock.maximumDelayNanos() >= 0) {
            maximum = Math.min(maximum, captureClock.maximumDelayNanos());
        }
        var minimum = Math.max(config.minimumDelay().toNanos(), captureClock.minimumDelayNanos());
        if (jitterBufferTarget.isPresent()) {
            minimum = Math.max(minimum, jitterBufferTarget.get().toNanos());
        }
        minimum = Math.min(minimum, maximum);
        return Math.min(Math.max(estimate, minimum) + sync.syncDelayNanos(), maximum);
    }

    /// {@return the delay the network required for the recent packets: their transit range}
    private long networkDelayNanos() {
        return percentileNanos();
    }

    /// {@return the 95th percentile of the recent transit times above the fastest one}
    private long percentileNanos() {
        if (transits.size() < 2) {
            return 0;
        }
        var values = new long[transits.size()];
        var i = 0;
        var minimum = Long.MAX_VALUE;
        for (var transit : transits) {
            values[i++] = transit;
            minimum = Math.min(minimum, transit);
        }
        Arrays.sort(values);
        var index = (int) Math.ceil(PERCENTILE * values.length) - 1;
        return values[Math.max(0, Math.min(index, values.length - 1))] - minimum;
    }

    /// Feeds the jitter estimators with one packet.
    private void updateJitter(long timestamp, long arrivalNanos) {
        var transitNanos = arrivalNanos - toNanos(timestamp);
        transits.addLast(transitNanos);
        while (transits.size() > HISTORY) {
            transits.removeFirst();
        }
        var transit = (double) arrivalNanos * clockRate / 1_000_000_000.0 - timestamp;
        if (!Double.isNaN(previousTransit)) {
            var difference = Math.abs(transit - previousTransit);
            jitter += (difference - jitter) / 16;
        }
        previousTransit = transit;
    }

    /// {@return a span in timestamp units as nanoseconds}
    private long toNanos(long units) {
        return units * 1_000_000_000L / clockRate;
    }

    /// {@return a span in nanoseconds as timestamp units}
    private long toUnits(long nanos) {
        return nanos * clockRate / 1_000_000_000L;
    }
}
