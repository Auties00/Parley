package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// A full intra request (payload-specific feedback, format 4): the receiver asks each listed media sender for a
/// decoder refresh point, a keyframe.
///
/// Each request carries a command sequence number the requester increments for every new request to that source, so
/// the sender can tell a retransmitted request from a new one. The media source field of the common feedback header
/// is unused and written as `0`.
///
/// @param senderSsrc the feedback sender, an unsigned 32-bit value
/// @param entries    the requests, one per media source, at least one
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
public record FullIntraRequest(long senderSsrc, List<Entry> entries) implements RtcpPacket {
    /// The feedback message type of a FIR.
    public static final int FORMAT = 4;

    /// Validates the fields and copies `entries`.
    ///
    /// @throws IllegalArgumentException if `senderSsrc` is out of range or `entries` is empty
    public FullIntraRequest {
        RtcpCodec.checkUint32(senderSsrc, "senderSsrc");
        entries = List.copyOf(Objects.requireNonNull(entries, "entries cannot be null"));
        if (entries.isEmpty()) {
            throw new IllegalArgumentException("entries cannot be empty");
        }
    }

    /// One request of a FIR.
    ///
    /// @param ssrc     the media source asked for a keyframe, an unsigned 32-bit value
    /// @param sequence the command sequence number, `0..255`
    public record Entry(long ssrc, int sequence) {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field is out of range
        public Entry {
            RtcpCodec.checkUint32(ssrc, "ssrc");
            if (sequence < 0 || sequence > 255) {
                throw new IllegalArgumentException("sequence must be in 0..255: " + sequence);
            }
        }
    }

    static FullIntraRequest parse(ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 16, "FIR");
        if (body.remaining() % 8 != 0) {
            throw new RtcpFormatException("FIR entries are not 8 bytes each");
        }
        var sender = RtcpCodec.uint32(body);
        body.getInt();
        var entries = new ArrayList<Entry>();
        while (body.hasRemaining()) {
            var ssrc = RtcpCodec.uint32(body);
            var sequence = body.get() & 0xFF;
            body.position(body.position() + 3);
            entries.add(new Entry(ssrc, sequence));
        }
        return new FullIntraRequest(sender, entries);
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + 8 + 8 * entries.size();
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, FORMAT, PAYLOAD_FEEDBACK, length);
        destination.putInt((int) senderSsrc);
        destination.putInt(0);
        for (var entry : entries) {
            destination.putInt((int) entry.ssrc());
            destination.putInt(entry.sequence() << 24);
        }
        return length;
    }
}
