package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;

/// The playout delay limits the sender asks the receiver's jitter buffer to respect: `0/0` asks for rendering as
/// soon as possible (game streaming, remote desktop), larger values for smoother playback.
///
/// Both limits travel as 12-bit counts of 10 milliseconds, so a written value is rounded down to 10 ms.
///
/// @param minimum the minimum delay, `0..40950` milliseconds
/// @param maximum the maximum delay, `0..40950` milliseconds, at least `minimum`
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/playout-delay/README.md WebRTC: Playout Delay
public record PlayoutDelay(Duration minimum, Duration maximum) implements HeaderExtension {
    /// The encoded length.
    public static final int LENGTH = 3;

    /// The largest representable delay: 4095 units of 10 milliseconds.
    public static final Duration MAXIMUM = Duration.ofMillis(4095 * 10);

    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if a limit is negative or above [#MAXIMUM], or the minimum exceeds the
    ///                                  maximum
    public PlayoutDelay {
        Objects.requireNonNull(minimum, "minimum cannot be null");
        Objects.requireNonNull(maximum, "maximum cannot be null");
        if (minimum.isNegative() || maximum.isNegative() || minimum.compareTo(MAXIMUM) > 0
                || maximum.compareTo(MAXIMUM) > 0) {
            throw new IllegalArgumentException("delays must be in 0.." + MAXIMUM.toMillis() + " ms");
        }
        if (minimum.compareTo(maximum) > 0) {
            throw new IllegalArgumentException("minimum exceeds maximum: " + minimum + " > " + maximum);
        }
    }

    /// Parses an element value.
    ///
    /// @param value the element value; the position is advanced past the three bytes read
    /// @return the limits
    /// @throws RtpFormatException if the value is shorter than three bytes or the minimum exceeds the maximum
    public static PlayoutDelay parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, LENGTH, "playout-delay");
        var raw = (value.get() & 0xFF) << 16 | (value.get() & 0xFF) << 8 | value.get() & 0xFF;
        var minimum = (raw >>> 12) * 10;
        var maximum = (raw & 0xFFF) * 10;
        if (minimum > maximum) {
            throw new RtpFormatException("playout-delay minimum exceeds maximum");
        }
        return new PlayoutDelay(Duration.ofMillis(minimum), Duration.ofMillis(maximum));
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.PLAYOUT_DELAY;
    }

    @Override
    public int encodedLength() {
        return LENGTH;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, LENGTH);
        var raw = (int) (minimum.toMillis() / 10) << 12 | (int) (maximum.toMillis() / 10);
        destination.put((byte) (raw >>> 16)).put((byte) (raw >>> 8)).put((byte) raw);
    }
}
