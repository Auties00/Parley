package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// The checks and buffer helpers the packetizers and depacketizers share.
final class Payloads {
    private Payloads() {
        throw new AssertionError("Payloads cannot be instantiated");
    }

    /// Checks that a frame is of the kind a format carries.
    ///
    /// @throws IllegalArgumentException if it is not
    static void checkKind(EncodedFrame frame, MediaKind kind) {
        Objects.requireNonNull(frame, "frame cannot be null");
        if (frame.kind() != kind) {
            throw new IllegalArgumentException("expected a " + kind + " frame, got " + frame.kind());
        }
    }

    /// Checks that packets form a contiguous run of one frame: not empty, one timestamp, consecutive sequence numbers.
    ///
    /// @throws PayloadFormatException  if they do not
    /// @throws IllegalArgumentException if the list is empty
    static void checkRun(List<RtpPacket> packets) throws PayloadFormatException {
        if (packets.isEmpty()) {
            throw new IllegalArgumentException("no packets");
        }
        var first = packets.getFirst();
        var expected = first.sequence();
        for (var packet : packets) {
            if (packet.timestamp() != first.timestamp()) {
                throw new PayloadFormatException("packets of one frame carry different timestamps");
            }
            if (packet.sequence() != expected) {
                throw new PayloadFormatException("gap in the sequence numbers of one frame");
            }
            expected = (expected + 1) & 0xFFFF;
        }
    }

    /// {@return a heap buffer holding a copy of the remaining bytes of `source`, without moving its position}
    static ByteBuffer copy(ByteBuffer source) {
        var bytes = new byte[source.remaining()];
        source.get(source.position(), bytes);
        return ByteBuffer.wrap(bytes);
    }

    /// {@return the unsigned byte at an absolute index}
    static int u8(ByteBuffer buffer, int index) {
        return buffer.get(index) & 0xFF;
    }

    /// {@return the fragments of a body (a NAL unit without its header, a frame), as slices balanced so they differ
    /// in size by at most one byte}
    ///
    /// @param body     the bytes to split, from position to limit
    /// @param capacity the largest fragment
    static List<ByteBuffer> split(ByteBuffer body, int capacity) {
        var length = body.remaining();
        var count = (length + capacity - 1) / capacity;
        var result = new ArrayList<ByteBuffer>(count);
        var offset = body.position();
        for (var k = 0; k < count; k++) {
            var size = length / count + (k < length % count ? 1 : 0);
            result.add(body.slice(offset, size));
            offset += size;
        }
        return result;
    }
}
