package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/// Application-defined RTCP data (`APP`).
///
/// @param subtype the application subtype, `0..31`
/// @param ssrc    the sender, an unsigned 32-bit value
/// @param name    the four ASCII characters naming the application
/// @param data    the application data, a multiple of four bytes; the record keeps a read-only copy and returns a
///                read-only duplicate
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record App(int subtype, long ssrc, String name, ByteBuffer data) implements RtcpPacket {
    /// Validates the fields and copies `data`.
    ///
    /// @throws IllegalArgumentException if `subtype` is out of range, `name` is not four ASCII characters, or the
    ///                                  length of `data` is not a multiple of four
    public App {
        if (subtype < 0 || subtype > 31) {
            throw new IllegalArgumentException("subtype must be in 0..31: " + subtype);
        }
        RtcpCodec.checkUint32(ssrc, "ssrc");
        Objects.requireNonNull(name, "name cannot be null");
        if (name.length() != 4 || !StandardCharsets.US_ASCII.newEncoder().canEncode(name)) {
            throw new IllegalArgumentException("name must be four ASCII characters: " + name);
        }
        data = RtcpCodec.copyOf(Objects.requireNonNull(data, "data cannot be null"));
        if (data.remaining() % 4 != 0) {
            throw new IllegalArgumentException("data length must be a multiple of four: " + data.remaining());
        }
    }

    @Override
    public ByteBuffer data() {
        return data.duplicate();
    }

    static App parse(int subtype, ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 8, "APP");
        var ssrc = RtcpCodec.uint32(body);
        var name = new byte[4];
        body.get(name);
        for (var b : name) {
            if (b < 0) {
                throw new RtcpFormatException("APP name is not ASCII");
            }
        }
        var rest = body.slice();
        if (rest.remaining() % 4 != 0) {
            throw new RtcpFormatException("APP data is not a multiple of four bytes");
        }
        return new App(subtype, ssrc, new String(name, StandardCharsets.ISO_8859_1), rest);
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + 8 + data.remaining();
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, subtype, APP, length);
        destination.putInt((int) ssrc);
        destination.put(name.getBytes(StandardCharsets.US_ASCII));
        destination.put(data.duplicate());
        return length;
    }
}
