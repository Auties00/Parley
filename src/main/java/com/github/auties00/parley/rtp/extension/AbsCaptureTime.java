package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.OptionalLong;

/// The absolute capture time of the frame a packet belongs to, on the capturing system's NTP clock, and optionally
/// the offset between that clock and the sender's, so receivers and mixers can synchronize and measure end-to-end
/// delay across hops.
///
/// @param captureTimestamp            the capture time as a 64-bit NTP timestamp (UQ32.32 seconds)
/// @param estimatedCaptureClockOffset the estimated offset of the capture system's clock from the sender's NTP clock,
///                                    a signed Q32.32 number of seconds; empty when the sender did not include it
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/abs-capture-time/README.md WebRTC: Absolute Capture Time
public record AbsCaptureTime(long captureTimestamp, OptionalLong estimatedCaptureClockOffset)
        implements HeaderExtension {
    /// Checks `estimatedCaptureClockOffset` is not `null`.
    public AbsCaptureTime {
        Objects.requireNonNull(estimatedCaptureClockOffset, "estimatedCaptureClockOffset cannot be null");
    }

    /// Parses an element value of 8 bytes, or 16 with the clock offset.
    ///
    /// @param value the element value; the position is advanced past the bytes read
    /// @return the capture time
    /// @throws RtpFormatException if the value is neither 8 nor 16 bytes long
    public static AbsCaptureTime parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, 8, "abs-capture-time");
        if (value.remaining() != 8 && value.remaining() != 16) {
            throw new RtpFormatException("abs-capture-time value is neither 8 nor 16 bytes: " + value.remaining());
        }
        var timestamp = value.getLong();
        var offset = value.remaining() >= 8 ? OptionalLong.of(value.getLong()) : OptionalLong.empty();
        return new AbsCaptureTime(timestamp, offset);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.ABS_CAPTURE_TIME;
    }

    @Override
    public int encodedLength() {
        return estimatedCaptureClockOffset.isPresent() ? 16 : 8;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, encodedLength());
        destination.putLong(captureTimestamp);
        if (estimatedCaptureClockOffset.isPresent()) {
            destination.putLong(estimatedCaptureClockOffset.getAsLong());
        }
    }
}
