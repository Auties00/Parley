package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.Objects;

/// An RTCP packet of a type, or a feedback message of a format, that Parley does not interpret, kept byte for byte
/// so a compound packet round-trips.
///
/// @param packetType the packet type, `0..255`
/// @param count      the five-bit count or feedback format field, `0..31`
/// @param body       the bytes after the 4-byte common header, padding removed, a multiple of four bytes; kept as a
///                   read-only copy
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record UnknownRtcp(int packetType, int count, ByteBuffer body) implements RtcpPacket {
    /// Validates the fields and copies `body`.
    ///
    /// @throws IllegalArgumentException if a field is out of range or `body` is not a multiple of four bytes
    public UnknownRtcp {
        if (packetType < 0 || packetType > 255) {
            throw new IllegalArgumentException("packetType must be in 0..255: " + packetType);
        }
        if (count < 0 || count > 31) {
            throw new IllegalArgumentException("count must be in 0..31: " + count);
        }
        body = RtcpCodec.copyOf(Objects.requireNonNull(body, "body cannot be null"));
        if (body.remaining() % 4 != 0) {
            throw new IllegalArgumentException("body length must be a multiple of four: " + body.remaining());
        }
    }

    @Override
    public ByteBuffer body() {
        return body.duplicate();
    }

    /// Wraps an unpadded body, padding it with zeros to a multiple of four bytes if padding was stripped.
    static UnknownRtcp of(int type, int count, ByteBuffer body) {
        var length = body.remaining();
        if (length % 4 == 0) {
            return new UnknownRtcp(type, count, body);
        }
        var padded = ByteBuffer.allocate(RtcpCodec.padTo4(length));
        padded.put(body.duplicate()).position(0);
        return new UnknownRtcp(type, count, padded);
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + body.remaining();
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, count, packetType, length);
        destination.put(body.duplicate());
        return length;
    }
}
