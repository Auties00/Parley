package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The offset between a packet's actual transmission time and its RTP timestamp, which lets a receiver tell sender
/// pacing apart from network jitter.
///
/// @param offset the offset in RTP timestamp units, a signed 24-bit value
/// @spec https://www.rfc-editor.org/rfc/rfc5450.html RFC 5450: Transmission Time Offsets in RTP Streams
public record TransmissionTimeOffset(int offset) implements HeaderExtension {
    /// The encoded length.
    public static final int LENGTH = 3;

    /// Validates the range.
    ///
    /// @throws IllegalArgumentException if `offset` does not fit 24 signed bits
    public TransmissionTimeOffset {
        if (offset < -0x800000 || offset > 0x7FFFFF) {
            throw new IllegalArgumentException("offset must be a signed 24-bit value: " + offset);
        }
    }

    /// Parses an element value.
    ///
    /// @param value the element value; the position is advanced past the three bytes read
    /// @return the offset
    /// @throws RtpFormatException if the value is shorter than three bytes
    public static TransmissionTimeOffset parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, LENGTH, "toffset");
        var raw = (value.get() & 0xFF) << 16 | (value.get() & 0xFF) << 8 | value.get() & 0xFF;
        return new TransmissionTimeOffset(raw << 8 >> 8);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.TOFFSET;
    }

    @Override
    public int encodedLength() {
        return LENGTH;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, LENGTH);
        destination.put((byte) (offset >>> 16)).put((byte) (offset >>> 8)).put((byte) offset);
    }
}
