package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.AudioFrameMetadata;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/// A string of DTMF tones with the timing of the W3C `insertDTMF` method, and the RFC 4733 packets that play it.
///
/// The tones are the characters `0-9`, `A-D` (either case, stored in upper case), `#` and `*`; a `,` pauses for two
/// seconds. Each tone lasts [#duration()], and the next starts [#interToneGap()] after it ends. The constructor
/// clamps the times as `insertDTMF` does: the duration to `40..6000` ms and the gap to `30..6000` ms.
///
/// [#packets(int,Duration,int)] lays the sequence out as telephone-event packets: each tone is sent every packet
/// interval from its start, each packet carrying the tone's start timestamp, the marker bit on its first one, and the
/// duration so far; its final packet, with the end flag, is sent three times. A tone longer than the 16-bit duration
/// field allows (at 48 kHz, longer than about 1.36 s) is split into segments with consecutive timestamps.
///
/// {@snippet lang = java :
/// var tones = DtmfToneSequence.of("1234#");
/// for (var packet : tones.packets(8000, Duration.ofMillis(50), 10)) {
///     sleepUntil(start.plus(packet.sendTime()));
///     sendStream.send(packet.toFrame(baseTimestamp));
/// }
/// }
///
/// @param tones        the tones, validated and in upper case
/// @param duration     the duration of each tone, `40..6000` ms
/// @param interToneGap the silence between tones, `30..6000` ms
/// @spec https://www.w3.org/TR/webrtc/#rtcdtmfsender-interface W3C WebRTC: RTCDTMFSender interface
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
public record DtmfToneSequence(String tones, Duration duration, Duration interToneGap) {
    /// The default duration of a tone, 100 ms.
    public static final Duration DEFAULT_DURATION = Duration.ofMillis(100);

    /// The default gap between tones, 70 ms.
    public static final Duration DEFAULT_INTER_TONE_GAP = Duration.ofMillis(70);

    /// The pause a `,` stands for, two seconds.
    public static final Duration COMMA_PAUSE = Duration.ofSeconds(2);

    /// The default interval between the packets of a tone, 50 ms, as RFC 4733 suggests.
    public static final Duration DEFAULT_PACKET_INTERVAL = Duration.ofMillis(50);

    /// The default volume of a tone, 10 (-10 dBm0).
    public static final int DEFAULT_VOLUME = 10;

    /// How many times the final packet of a tone is sent, as RFC 4733 recommends.
    public static final int END_PACKET_COPIES = 3;

    /// The shortest and longest tone.
    private static final Duration MIN_DURATION = Duration.ofMillis(40);

    /// The shortest gap.
    private static final Duration MIN_GAP = Duration.ofMillis(30);

    /// The longest tone and gap.
    private static final Duration MAX_TIME = Duration.ofMillis(6000);

    /// The largest value of the duration field.
    private static final int MAX_SEGMENT = 0xFFFF;

    /// Creates a sequence, normalising it as `insertDTMF` does.
    ///
    /// @param tones        the tones; letters may be in either case
    /// @param duration     the duration of each tone, clamped to `40..6000` ms
    /// @param interToneGap the gap between tones, clamped to `30..6000` ms
    /// @throws IllegalArgumentException if `tones` has a character other than `0-9`, `A-D`, `a-d`, `#`, `*` and `,`
    public DtmfToneSequence {
        Objects.requireNonNull(tones, "tones cannot be null");
        Objects.requireNonNull(duration, "duration cannot be null");
        Objects.requireNonNull(interToneGap, "interToneGap cannot be null");
        tones = tones.toUpperCase(Locale.ROOT);
        for (var i = 0; i < tones.length(); i++) {
            var tone = tones.charAt(i);
            if (tone != ',' && TelephoneEvent.eventOf(tone).isEmpty()) {
                throw new IllegalArgumentException("invalid DTMF character at " + i + ": " + tone);
            }
        }
        duration = clamp(duration, MIN_DURATION);
        interToneGap = clamp(interToneGap, MIN_GAP);
    }

    /// {@return a sequence with the default duration and gap}
    ///
    /// @param tones the tones
    /// @throws IllegalArgumentException if `tones` has an invalid character
    public static DtmfToneSequence of(String tones) {
        return new DtmfToneSequence(tones, DEFAULT_DURATION, DEFAULT_INTER_TONE_GAP);
    }

    /// {@return the time from the start of the first tone to the end of the gap after the last}
    public Duration totalDuration() {
        var total = Duration.ZERO;
        for (var i = 0; i < tones.length(); i++) {
            total = total.plus(tones.charAt(i) == ',' ? COMMA_PAUSE : duration.plus(interToneGap));
        }
        return total;
    }

    /// {@return the offset of each character's start from the start of the sequence, in order}
    public List<Duration> startTimes() {
        var result = new ArrayList<Duration>(tones.length());
        var time = Duration.ZERO;
        for (var i = 0; i < tones.length(); i++) {
            result.add(time);
            time = time.plus(tones.charAt(i) == ',' ? COMMA_PAUSE : duration.plus(interToneGap));
        }
        return List.copyOf(result);
    }

    /// Lays the sequence out as telephone-event packets.
    ///
    /// @param clockRate      the clock rate of the telephone-event codec, the rate of the audio it accompanies
    /// @param packetInterval the time between the packets of one tone, positive, usually the audio packet time or
    ///                       [#DEFAULT_PACKET_INTERVAL]
    /// @param volume         the volume of the tones in -dBm0, `0..63`, usually [#DEFAULT_VOLUME]
    /// @return the packets in send order
    /// @throws IllegalArgumentException if `clockRate` or `packetInterval` is not positive, or `volume` is outside
    ///                                  `0..63`
    public List<Packet> packets(int clockRate, Duration packetInterval, int volume) {
        Objects.requireNonNull(packetInterval, "packetInterval cannot be null");
        if (clockRate <= 0 || !packetInterval.isPositive()) {
            throw new IllegalArgumentException("clock rate and packet interval must be positive");
        }
        if (volume < 0 || volume > 63) {
            throw new IllegalArgumentException("volume out of range: " + volume);
        }
        var intervalUnits = Math.max(1, units(packetInterval, clockRate));
        var toneUnits = units(duration, clockRate);
        var result = new ArrayList<Packet>();
        var starts = startTimes();
        for (var i = 0; i < tones.length(); i++) {
            var tone = tones.charAt(i);
            if (tone == ',') {
                continue;
            }
            var event = TelephoneEvent.eventOf(tone).orElseThrow();
            var start = starts.get(i);
            var startUnits = units(start, clockRate);
            for (var k = 0L; k * intervalUnits < toneUnits; k++) {
                var elapsed = Math.min((k + 1) * intervalUnits, toneUnits);
                var segment = (elapsed - 1) / MAX_SEGMENT;
                var segmentDuration = (int) (elapsed - segment * MAX_SEGMENT);
                var sendTime = start.plus(packetInterval.multipliedBy(k));
                result.add(new Packet(sendTime, tone, startUnits + segment * MAX_SEGMENT, k == 0,
                        new TelephoneEvent(event, false, volume, segmentDuration)));
            }
            var lastSegment = (toneUnits - 1) / MAX_SEGMENT;
            var endEvent = new TelephoneEvent(event, true, volume, (int) (toneUnits - lastSegment * MAX_SEGMENT));
            for (var copy = 0; copy < END_PACKET_COPIES; copy++) {
                result.add(new Packet(start.plus(duration), tone, startUnits + lastSegment * MAX_SEGMENT, false,
                        endEvent));
            }
        }
        return List.copyOf(result);
    }

    /// {@return the packets of [#packets(int,Duration,int)] with the default interval and volume}
    ///
    /// @param clockRate the clock rate of the telephone-event codec
    /// @throws IllegalArgumentException if `clockRate` is not positive
    public List<Packet> packets(int clockRate) {
        return packets(clockRate, DEFAULT_PACKET_INTERVAL, DEFAULT_VOLUME);
    }

    /// {@return a time clamped to `min..6000` ms}
    private static Duration clamp(Duration value, Duration min) {
        return value.compareTo(min) < 0 ? min : value.compareTo(MAX_TIME) > 0 ? MAX_TIME : value;
    }

    /// {@return a time in clock units, rounded to the nearest unit}
    private static long units(Duration time, int clockRate) {
        return (time.toNanos() * clockRate + 500_000_000L) / 1_000_000_000L;
    }

    /// One telephone-event packet of a tone sequence.
    ///
    /// @param sendTime        when to send the packet, from the start of the sequence
    /// @param tone            the DTMF character the packet plays
    /// @param timestampOffset the RTP timestamp of the packet, from the RTP timestamp of the start of the sequence, in
    ///                        clock units: the start of the tone (or of its segment)
    /// @param marker          whether the packet is the first of its tone, which carries the RTP marker bit
    /// @param event           the event block of the payload
    public record Packet(Duration sendTime, char tone, long timestampOffset, boolean marker, TelephoneEvent event) {
        /// Creates a packet.
        ///
        /// @param sendTime        the send time
        /// @param tone            the tone
        /// @param timestampOffset the timestamp offset, non-negative
        /// @param marker          the marker bit
        /// @param event           the event block
        /// @throws IllegalArgumentException if `sendTime` or `timestampOffset` is negative
        public Packet {
            Objects.requireNonNull(sendTime, "sendTime cannot be null");
            Objects.requireNonNull(event, "event cannot be null");
            if (sendTime.isNegative() || timestampOffset < 0) {
                throw new IllegalArgumentException("negative send time or timestamp offset");
            }
        }

        /// {@return the packet as a telephone-event frame for a [TelephoneEventFormat] packetizer}
        ///
        /// @param baseTimestamp the RTP timestamp of the start of the sequence, an unsigned 32-bit value
        /// @throws IllegalArgumentException if `baseTimestamp` is out of range
        public EncodedFrame toFrame(long baseTimestamp) {
            if (baseTimestamp < 0 || baseTimestamp > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("RTP timestamp out of range: " + baseTimestamp);
            }
            return new EncodedFrame(MediaKind.AUDIO, event.toBuffer(), (baseTimestamp + timestampOffset) & 0xFFFFFFFFL,
                    true, Optional.empty(), AudioFrameMetadata.none());
        }
    }
}
