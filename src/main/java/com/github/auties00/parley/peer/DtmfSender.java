package com.github.auties00.parley.peer;

import com.github.auties00.parley.event.EventSource;
import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.net.MonotonicClock;

import java.lang.System.Logger.Level;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadFactory;

/// Sends DTMF tones as RFC 4733 telephone events on an audio sender, the W3C `RTCDTMFSender`.
///
/// [#insertDtmf(String, Duration, Duration)] queues tones and returns at once; a thread of the connection's
/// configured factory plays them one by one, each for its duration followed by the gap, timed by the configured
/// clock, and raises a [ToneChange] as each starts and once the buffer is empty. A comma pauses for two seconds.
/// Calling it again replaces the tones not yet played; the tones left are dropped when the sender stops sending or
/// the connection closes.
///
/// {@snippet lang = java :
/// var dtmf = sender.dtmf().orElseThrow();
/// if (dtmf.canInsertDtmf()) {
///     dtmf.insertDtmf("1234#", Duration.ofMillis(100), Duration.ofMillis(70));
/// }
/// }
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
public final class DtmfSender {
    private static final System.Logger LOGGER = System.getLogger(DtmfSender.class.getName());

    /// The shortest tone duration the W3C algorithm allows.
    public static final Duration MIN_DURATION = Duration.ofMillis(40);
    /// The longest tone duration the W3C algorithm allows.
    public static final Duration MAX_DURATION = Duration.ofMillis(6000);
    /// The shortest gap between tones the W3C algorithm allows.
    public static final Duration MIN_GAP = Duration.ofMillis(30);
    /// The pause a comma stands for.
    public static final Duration COMMA_PAUSE = Duration.ofSeconds(2);
    /// How often a player whose tones wait for the audio stream checks whether it was wired.
    private static final Duration SINK_POLL = Duration.ofMillis(20);

    /// A tone starting, or the buffer running empty, the W3C `RTCDTMFToneChangeEvent`.
    ///
    /// @param tone the tone that starts, or an empty optional when every queued tone was played
    public record ToneChange(Optional<Character> tone) {
        /// Creates the event.
        ///
        /// @param tone the tone, or an empty optional
        public ToneChange {
            Objects.requireNonNull(tone, "tone cannot be null");
        }
    }

    /// Plays one tone on the wire, blocking for its duration.
    @FunctionalInterface
    interface ToneSink {
        /// Sends the RFC 4733 packets of one event for `duration` and returns after its end packets.
        void play(char tone, Duration duration) throws InterruptedException;
    }

    /// The sender this DTMF sender belongs to.
    private final RtpSender sender;
    /// The factory of the player thread.
    private final ThreadFactory threadFactory;
    /// The clock tones and gaps are timed with.
    private final MonotonicClock clock;
    /// Guards [#buffer], [#duration], [#gap] and [#player].
    private final Object lock = new Object();
    /// The tone events.
    private final EventSource<ToneChange> events = new EventSource<>();
    /// The tones not yet played.
    private String buffer = "";
    /// The duration of each tone.
    private Duration duration = Duration.ofMillis(100);
    /// The gap after each tone.
    private Duration gap = Duration.ofMillis(70);
    /// The thread playing the buffer, or `null`.
    private Thread player;
    /// The wire side, installed once the audio stream is wired; tones wait for it.
    private volatile ToneSink sink;

    /// Creates the DTMF sender of `sender`, whose player threads `threadFactory` creates and `clock` times.
    DtmfSender(RtpSender sender, ThreadFactory threadFactory, MonotonicClock clock) {
        this.sender = sender;
        this.threadFactory = Objects.requireNonNull(threadFactory);
        this.clock = Objects.requireNonNull(clock);
    }

    /// {@return whether tones can be queued: the transceiver's current direction sends and the negotiation agreed on
    /// telephone-event}
    ///
    /// Tones queued while the transport is still connecting are played once the audio stream is wired.
    ///
    /// @spec https://www.w3.org/TR/webrtc/#dom-rtcdtmfsender-caninsertdtmf WebRTC: Real-Time Communication in Browsers, canInsertDTMF
    public boolean canInsertDtmf() {
        return sender.connection().isSending(sender) && sender.connection().negotiatedTelephoneEvent(sender);
    }

    /// {@return the tones not yet played}
    public String toneBuffer() {
        synchronized (lock) {
            return buffer;
        }
    }

    /// Queues tones with the default duration of 100 ms and gap of 70 ms.
    ///
    /// @param tones the tones, as for [#insertDtmf(String, Duration, Duration)]
    /// @throws IllegalArgumentException as [#insertDtmf(String, Duration, Duration)] does
    /// @throws InvalidStateException    as [#insertDtmf(String, Duration, Duration)] does
    public void insertDtmf(String tones) {
        insertDtmf(tones, Duration.ofMillis(100), Duration.ofMillis(70));
    }

    /// Replaces the queued tones with `tones` and starts playing them.
    ///
    /// The duration is clamped to 40 to 6000 ms and the gap raised to at least 30 ms, as the W3C algorithm does. An
    /// empty string cancels the tones not yet played.
    ///
    /// @param tones        the tones: digits, `A` to `D` in either case, `*`, `#`, and `,` for a two-second pause
    /// @param toneDuration the duration of each tone
    /// @param interToneGap the gap after each tone
    /// @throws IllegalArgumentException if `tones` holds another character
    /// @throws InvalidStateException    if the transceiver does not send or telephone-event is not negotiated
    public void insertDtmf(String tones, Duration toneDuration, Duration interToneGap) {
        Objects.requireNonNull(tones, "tones cannot be null");
        Objects.requireNonNull(toneDuration, "toneDuration cannot be null");
        Objects.requireNonNull(interToneGap, "interToneGap cannot be null");
        var normalized = tones.toUpperCase(Locale.ROOT);
        for (var index = 0; index < normalized.length(); index++) {
            if ("0123456789ABCD#*,".indexOf(normalized.charAt(index)) < 0) {
                throw new IllegalArgumentException("not a DTMF tone: '" + tones.charAt(index) + "'");
            }
        }
        if (!canInsertDtmf()) {
            throw new InvalidStateException("the sender cannot send DTMF now");
        }
        synchronized (lock) {
            buffer = normalized;
            duration = clamp(toneDuration, MIN_DURATION, MAX_DURATION);
            gap = interToneGap.compareTo(MIN_GAP) < 0 ? MIN_GAP : interToneGap;
            if (player == null && !buffer.isEmpty()) {
                var thread = threadFactory.newThread(this::play);
                if (thread == null) {
                    buffer = "";
                    throw new OperationErrorException("the thread factory refused to create the DTMF player");
                }
                player = thread;
                thread.start();
            }
        }
    }

    /// {@return a stream of the tone changes}
    ///
    /// The first stream opened also gets the changes raised since the sender was created; the streams end when the
    /// connection closes.
    public EventStream<ToneChange> events() {
        return events.open();
    }

    /// Plays the buffer until it is empty.
    private void play() {
        var self = Thread.currentThread();
        try {
            while (true) {
                char tone;
                Duration toneDuration;
                Duration toneGap;
                synchronized (lock) {
                    if (player != self) {
                        return;
                    }
                    if (buffer.isEmpty()) {
                        player = null;
                        events.publish(new ToneChange(Optional.empty()));
                        return;
                    }
                    tone = buffer.charAt(0);
                    if (tone != ',' && sink == null) {
                        tone = 0;
                    } else {
                        buffer = buffer.substring(1);
                    }
                    toneDuration = duration;
                    toneGap = gap;
                }
                if (tone == 0) {
                    sleep(clock, SINK_POLL);
                    continue;
                }
                events.publish(new ToneChange(Optional.of(tone)));
                if (tone == ',') {
                    sleep(clock, COMMA_PAUSE);
                    continue;
                }
                var current = sink;
                if (current == null) {
                    continue;
                }
                current.play(tone, toneDuration);
                sleep(clock, toneGap);
            }
        } catch (InterruptedException exception) {
            release(self);
        } catch (RuntimeException exception) {
            LOGGER.log(Level.WARNING, "DTMF playout failed", exception);
            release(self);
        }
    }

    /// Forgets the player and its tones, unless another player replaced it.
    private void release(Thread self) {
        synchronized (lock) {
            if (player == self) {
                player = null;
                buffer = "";
            }
        }
    }

    /// Drops the tones not yet played and stops the player, as when the sender stops sending.
    void cancel() {
        synchronized (lock) {
            buffer = "";
            if (player != null) {
                player.interrupt();
                player = null;
            }
        }
    }

    /// Cancels the tones and ends the event streams, as when the connection closes.
    void close() {
        cancel();
        events.end();
    }

    /// Sleeps until `duration` has elapsed on `clock`, waking at most every 20 ms to read it again, so a clock
    /// other than the system's still paces the tones.
    static void sleep(MonotonicClock clock, Duration duration) throws InterruptedException {
        var deadline = clock.nanos() + duration.toNanos();
        while (true) {
            var left = deadline - clock.nanos();
            if (left <= 0) {
                return;
            }
            Thread.sleep(Duration.ofNanos(Math.min(left, 20_000_000L)));
        }
    }

    /// Installs or removes the wire side.
    void setSink(ToneSink newSink) {
        sink = newSink;
    }

    /// {@return `value` clamped to `min..max`}
    private static Duration clamp(Duration value, Duration min, Duration max) {
        return value.compareTo(min) < 0 ? min : value.compareTo(max) > 0 ? max : value;
    }
}
