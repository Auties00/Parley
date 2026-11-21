package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The playout delay limits the sender asks the receiver's jitter buffer to respect: `0/0` asks for rendering as
/// soon as possible (game streaming, remote desktop), larger values for smoother playback.
///
/// Both limits travel as 12-bit counts of 10 milliseconds, so a written value is rounded down to 10 ms.
///
/// @param minimumMillis the minimum delay in milliseconds, `0..40950`
/// @param maximumMillis the maximum delay in milliseconds, `0..40950`
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/playout-delay/README.md WebRTC: Playout Delay
public record PlayoutDelay(int minimumMillis, int maximumMillis) implements HeaderExtension {
    /// The encoded length.
    public static final int LENGTH = 3;

    /// The largest representable delay in milliseconds.
    public static final int MAXIMUM_MILLIS = 4095 * 10;

    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if a limit is out of range or the minimum exceeds the maximum
    public PlayoutDelay {
        if (minimumMillis < 0 || minimumMillis > MAXIMUM_MILLIS || maximumMillis < 0
                || maximumMillis > MAXIMUM_MILLIS) {
            throw new IllegalArgumentException("delays must be in 0.." + MAXIMUM_MILLIS);
        }
        if (minimumMillis > maximumMillis) {
            throw new IllegalArgumentException("minimum exceeds maximum: " + minimumMillis + " > " + maximumMillis);
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
        return new PlayoutDelay(minimum, maximum);
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
        var raw = (minimumMillis / 10) << 12 | maximumMillis / 10;
        destination.put((byte) (raw >>> 16)).put((byte) (raw >>> 8)).put((byte) raw);
    }
}
