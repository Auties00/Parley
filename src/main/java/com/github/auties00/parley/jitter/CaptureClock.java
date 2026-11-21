package com.github.auties00.parley.jitter;

import com.github.auties00.parley.rtp.NtpTime;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.session.NtpRtpMapping;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.OptionalInt;

/// Maps the RTP timestamps of one received stream to the sender's capture clock, and reads the playout delay bounds
/// the sender asks for.
///
/// The capture time of a timestamp comes from the latest `abs-capture-time` value the stream carried, extrapolated
/// along the RTP clock for up to [#INTERPOLATION_LIMIT] (the extension is sent only on some packets), else from the
/// RTP to NTP mapping of the latest RTCP sender report. Not thread-safe: the owning buffer calls it under its lock.
///
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/abs-capture-time/README.md WebRTC: Absolute Capture Time
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/playout-delay/README.md WebRTC: Playout Delay
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html#section-6.4.1 RFC 3550 section 6.4.1: SR: Sender Report RTCP Packet
final class CaptureClock {
    /// How far along the RTP clock an `abs-capture-time` value is extrapolated, the interpolation limit webrtc.org
    /// uses.
    static final Duration INTERPOLATION_LIMIT = Duration.ofSeconds(5);
    /// The unit of the `playout-delay` values, 10 ms.
    private static final long PLAYOUT_DELAY_UNIT_NANOS = 10_000_000L;

    /// The RTP clock rate of the stream.
    private final int clockRate;
    /// The id of the `abs-capture-time` extension, when negotiated.
    private final OptionalInt absCaptureTimeId;
    /// The id of the `playout-delay` extension, when negotiated.
    private final OptionalInt playoutDelayId;
    /// The RTP timestamp of the latest `abs-capture-time` value, or `-1`.
    private long absTimestamp = -1;
    /// The capture time of the latest `abs-capture-time` value, or `null`.
    private Instant absCapture;
    /// The mapping of the latest sender report, or `null`.
    private NtpRtpMapping senderClock;
    /// The latest playout delay bounds in nanoseconds, `{minimum, maximum}`, or `null` when the stream sent none.
    private long[] playoutDelay;

    /// Creates the clock of a stream.
    CaptureClock(int clockRate, OptionalInt absCaptureTimeId, OptionalInt playoutDelayId) {
        this.clockRate = clockRate;
        this.absCaptureTimeId = absCaptureTimeId;
        this.playoutDelayId = playoutDelayId;
    }

    /// Reads the timing extensions a packet carries; malformed values are ignored.
    void observe(RtpPacket packet) {
        if (absCaptureTimeId.isPresent()) {
            packet.extension(absCaptureTimeId.getAsInt()).ifPresent(value -> {
                if (value.remaining() == 8 || value.remaining() == 16) {
                    absCapture = NtpTime.toInstant(value.getLong(value.position()));
                    absTimestamp = packet.timestamp();
                }
            });
        }
        if (playoutDelayId.isPresent()) {
            packet.extension(playoutDelayId.getAsInt()).ifPresent(this::readPlayoutDelay);
        }
    }

    /// Reads a 3-byte `playout-delay` value: a 12-bit minimum and a 12-bit maximum in units of 10 ms.
    private void readPlayoutDelay(ByteBuffer value) {
        if (value.remaining() != 3) {
            return;
        }
        var start = value.position();
        var bits = (value.get(start) & 0xFF) << 16 | (value.get(start + 1) & 0xFF) << 8 | value.get(start + 2) & 0xFF;
        var minimum = (bits >>> 12) * PLAYOUT_DELAY_UNIT_NANOS;
        var maximum = (bits & 0xFFF) * PLAYOUT_DELAY_UNIT_NANOS;
        if (minimum <= maximum) {
            playoutDelay = new long[]{minimum, maximum};
        }
    }

    /// Replaces the sender report mapping.
    void setSenderClock(NtpRtpMapping mapping) {
        senderClock = mapping;
    }

    /// {@return the capture time of an RTP timestamp, or an empty optional when the stream gave no clock}
    Optional<Instant> captureTimeOf(long rtpTimestamp) {
        if (absCapture != null) {
            var ticks = (int) (rtpTimestamp - absTimestamp);
            var nanos = (long) ticks * 1_000_000_000L / clockRate;
            if (Math.abs(nanos) <= INTERPOLATION_LIMIT.toNanos()) {
                return Optional.of(absCapture.plusNanos(nanos));
            }
        }
        var mapping = senderClock;
        return mapping == null ? Optional.empty() : Optional.of(mapping.senderTimeOf(rtpTimestamp));
    }

    /// {@return the minimum playout delay the sender asks for, in nanoseconds, or `-1` when it set none}
    long minimumDelayNanos() {
        return playoutDelay == null ? -1 : playoutDelay[0];
    }

    /// {@return the maximum playout delay the sender asks for, in nanoseconds, or `-1` when it set none}
    long maximumDelayNanos() {
        return playoutDelay == null ? -1 : playoutDelay[1];
    }

    /// {@return an instant as nanoseconds since the epoch}
    static long epochNanos(Instant instant) {
        return instant.getEpochSecond() * 1_000_000_000L + instant.getNano();
    }
}
