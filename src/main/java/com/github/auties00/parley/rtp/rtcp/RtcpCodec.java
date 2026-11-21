package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/// The RTCP common header codec and the dispatch from packet type and format to the packet records.
final class RtcpCodec {
    /// The size of the common header: version, padding, count or format, packet type and length.
    static final int HEADER_LENGTH = 4;

    private RtcpCodec() {
        throw new AssertionError("RtcpCodec cannot be instantiated");
    }

    static List<RtcpPacket> parseCompound(ByteBuffer buffer) throws RtcpFormatException {
        var out = new ArrayList<RtcpPacket>(2);
        var cursor = buffer.position();
        var end = buffer.limit();
        if (cursor == end) {
            throw new RtcpFormatException("empty RTCP packet");
        }
        while (cursor < end) {
            if (end - cursor < HEADER_LENGTH) {
                throw new RtcpFormatException("trailing bytes shorter than an RTCP header: " + (end - cursor));
            }
            var first = buffer.get(cursor) & 0xFF;
            if ((first & 0xC0) != 0x80) {
                throw new RtcpFormatException("RTCP version is not 2");
            }
            var count = first & 0x1F;
            var type = buffer.get(cursor + 1) & 0xFF;
            var length = 4 * ((buffer.getShort(cursor + 2) & 0xFFFF) + 1);
            if (cursor + length > end) {
                throw new RtcpFormatException("RTCP packet of type " + type + " overruns the compound packet");
            }
            var bodyEnd = cursor + length;
            if ((first & 0x20) != 0) {
                var padding = buffer.get(bodyEnd - 1) & 0xFF;
                if (padding == 0 || padding > length - HEADER_LENGTH) {
                    throw new RtcpFormatException("RTCP padding count out of range: " + padding);
                }
                bodyEnd -= padding;
            }
            var body = buffer.slice(cursor + HEADER_LENGTH, bodyEnd - cursor - HEADER_LENGTH);
            out.add(parse(type, count, body));
            cursor += length;
        }
        return List.copyOf(out);
    }

    private static RtcpPacket parse(int type, int count, ByteBuffer body) throws RtcpFormatException {
        return switch (type) {
            case RtcpPacket.SENDER_REPORT -> SenderReport.parse(count, body);
            case RtcpPacket.RECEIVER_REPORT -> ReceiverReport.parse(count, body);
            case RtcpPacket.SOURCE_DESCRIPTION -> SourceDescription.parse(count, body);
            case RtcpPacket.BYE -> Bye.parse(count, body);
            case RtcpPacket.APP -> App.parse(count, body);
            case RtcpPacket.EXTENDED_REPORT -> ExtendedReport.parse(body);
            case RtcpPacket.TRANSPORT_FEEDBACK -> switch (count) {
                case Nack.FORMAT -> Nack.parse(body);
                case CongestionControlFeedback.FORMAT -> CongestionControlFeedback.parse(body);
                case TransportFeedback.FORMAT -> TransportFeedback.parse(body);
                default -> UnknownRtcp.of(type, count, body);
            };
            case RtcpPacket.PAYLOAD_FEEDBACK -> switch (count) {
                case PictureLossIndication.FORMAT -> PictureLossIndication.parse(body);
                case FullIntraRequest.FORMAT -> FullIntraRequest.parse(body);
                case Remb.FORMAT -> Remb.isRemb(body) ? Remb.parse(body) : UnknownRtcp.of(type, count, body);
                default -> UnknownRtcp.of(type, count, body);
            };
            default -> UnknownRtcp.of(type, count, body);
        };
    }

    /// Writes the common header of a packet of `totalLength` bytes (header included, a multiple of four).
    static void writeHeader(ByteBuffer destination, int count, int type, int totalLength) {
        destination.put((byte) (0x80 | count));
        destination.put((byte) type);
        destination.putShort((short) (totalLength / 4 - 1));
    }

    static void requireRemaining(ByteBuffer body, int needed, String what) throws RtcpFormatException {
        if (body.remaining() < needed) {
            throw new RtcpFormatException(what + " truncated: " + body.remaining() + " bytes, " + needed + " needed");
        }
    }

    static long uint32(ByteBuffer body) {
        return body.getInt() & 0xFFFFFFFFL;
    }

    static void checkUint32(long value, String name) {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(name + " must be an unsigned 32-bit value: " + value);
        }
    }

    static void checkSsrcs(List<Long> ssrcs, String name) {
        for (var ssrc : ssrcs) {
            checkUint32(ssrc, name);
        }
    }

    /// {@return a read-only heap copy of the remaining bytes of `source`, positioned at zero}
    static ByteBuffer copyOf(ByteBuffer source) {
        var bytes = new byte[source.remaining()];
        source.duplicate().get(bytes);
        return ByteBuffer.wrap(bytes).asReadOnlyBuffer();
    }

    static int padTo4(int length) {
        return (length + 3) & ~3;
    }
}
