package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The absolute send time of a packet: a 24-bit, 6.18 fixed-point number of seconds that wraps every 64 seconds,
/// stamped when the packet leaves the sender, from which a receiver estimates queuing delay (REMB).
///
/// @param value the 24-bit fixed-point value, `0..0xFFFFFF`
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/abs-send-time/README.md WebRTC: Absolute Send Time
public record AbsSendTime(int value) implements HeaderExtension {
    /// The encoded length.
    public static final int LENGTH = 3;

    /// Validates the range.
    ///
    /// @throws IllegalArgumentException if `value` does not fit 24 bits
    public AbsSendTime {
        if (value < 0 || value > 0xFFFFFF) {
            throw new IllegalArgumentException("value must fit 24 bits: " + value);
        }
    }

    /// {@return the send time of a clock reading, modulo 64 seconds}
    ///
    /// @param nanos a non-negative time in nanoseconds of any monotonic clock
    public static AbsSendTime ofNanos(long nanos) {
        var seconds = Math.floorDiv(nanos, 1_000_000_000L);
        var fraction = Math.floorMod(nanos, 1_000_000_000L);
        return new AbsSendTime((int) (((seconds << 18) + (fraction << 18) / 1_000_000_000L) & 0xFFFFFF));
    }

    /// {@return the value in nanoseconds, `0..64` seconds}
    public long toNanos() {
        return ((long) value * 1_000_000_000L) >>> 18;
    }

    /// Parses an element value.
    ///
    /// @param value the element value; the position is advanced past the three bytes read
    /// @return the send time
    /// @throws RtpFormatException if the value is shorter than three bytes
    public static AbsSendTime parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, LENGTH, "abs-send-time");
        return new AbsSendTime((value.get() & 0xFF) << 16 | (value.get() & 0xFF) << 8 | value.get() & 0xFF);
    }

    /// Writes a send time into three bytes of a buffer at an absolute index, without moving its position.
    ///
    /// @param destination the buffer, usually a packet whose element was reserved at packetization
    /// @param index       the index of the first value byte
    /// @param nanos       the send time in nanoseconds
    public static void stamp(ByteBuffer destination, int index, long nanos) {
        var value = ofNanos(nanos).value;
        destination.put(index, (byte) (value >>> 16));
        destination.put(index + 1, (byte) (value >>> 8));
        destination.put(index + 2, (byte) value);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.ABS_SEND_TIME;
    }

    @Override
    public int encodedLength() {
        return LENGTH;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, LENGTH);
        destination.put((byte) (value >>> 16)).put((byte) (value >>> 8)).put((byte) value);
    }
}
