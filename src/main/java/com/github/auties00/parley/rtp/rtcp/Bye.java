package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// A goodbye (`BYE`): the listed sources are leaving the session.
///
/// @param ssrcs  the leaving sources, at most 31 unsigned 32-bit values
/// @param reason the reason for leaving, at most 255 UTF-8 bytes when written; empty when none was given
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record Bye(List<Long> ssrcs, Optional<String> reason) implements RtcpPacket {
    /// Validates and copies `ssrcs`.
    ///
    /// @throws IllegalArgumentException if there are more than 31 sources or one is out of range
    public Bye {
        ssrcs = List.copyOf(Objects.requireNonNull(ssrcs, "ssrcs cannot be null"));
        Objects.requireNonNull(reason, "reason cannot be null");
        if (ssrcs.size() > 31) {
            throw new IllegalArgumentException("at most 31 BYE sources: " + ssrcs.size());
        }
        RtcpCodec.checkSsrcs(ssrcs, "ssrc");
    }

    static Bye parse(int count, ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 4 * count, "BYE");
        var ssrcs = new ArrayList<Long>(count);
        for (var i = 0; i < count; i++) {
            ssrcs.add(RtcpCodec.uint32(body));
        }
        var reason = Optional.<String>empty();
        if (body.hasRemaining()) {
            var length = body.get() & 0xFF;
            RtcpCodec.requireRemaining(body, length, "BYE reason");
            var bytes = new byte[length];
            body.get(bytes);
            reason = Optional.of(new String(bytes, StandardCharsets.UTF_8));
        }
        return new Bye(ssrcs, reason);
    }

    private byte[] reasonBytes() {
        if (reason.isEmpty()) {
            return null;
        }
        return new SourceDescription.Item(SourceDescription.Item.NOTE, reason.get()).encodedValue();
    }

    @Override
    public int encodedLength() {
        var length = RtcpCodec.HEADER_LENGTH + 4 * ssrcs.size();
        var bytes = reasonBytes();
        if (bytes != null) {
            length += RtcpCodec.padTo4(1 + bytes.length);
        }
        return length;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        var start = destination.position();
        RtcpCodec.writeHeader(destination, ssrcs.size(), BYE, length);
        for (var ssrc : ssrcs) {
            destination.putInt(ssrc.intValue());
        }
        var bytes = reasonBytes();
        if (bytes != null) {
            destination.put((byte) bytes.length);
            destination.put(bytes);
        }
        while (destination.position() < start + length) {
            destination.put((byte) 0);
        }
        return length;
    }
}
