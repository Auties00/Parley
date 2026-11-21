package com.github.auties00.parley.rtp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/// Builds the compound RTCP packets that a sender of a single RTP stream emits.
///
/// Each compound packet is a sender report, or a receiver report while nothing has been sent, followed by a source
/// description with the `CNAME` item: the two parts RFC 3550 section 6.1 requires in every compound packet. At most
/// one reception report block is written, for the one remote source. The class is stateless: the caller keeps the
/// counters and the reception statistics and schedules the reports.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public final class RtcpPackets {
    /// The seconds between 1900-01-01, the NTP epoch, and 1970-01-01.
    private static final long NTP_UNIX_OFFSET_SECONDS = 2_208_988_800L;

    private RtcpPackets() {
        throw new AssertionError("RtcpPackets cannot be instantiated");
    }

    /// Builds a compound packet with a sender report and a source description.
    ///
    /// @param ssrc            the local synchronization source, an unsigned 32-bit value
    /// @param wallClockMillis the wall clock time of the report, in Unix milliseconds; it is written as an NTP
    ///                        timestamp
    /// @param rtpTimestamp    the RTP timestamp that corresponds to `wallClockMillis`
    /// @param packetCount     the number of RTP packets sent since the stream started
    /// @param octetCount      the number of payload octets sent since the stream started
    /// @param reception       the reception report of the remote source, or `null` for none
    /// @param cname           the canonical name; its UTF-8 encoding is cut to 255 bytes
    /// @param tailroom        the number of spare zero bytes to leave after the packet, such as the SRTCP index and
    ///                        authentication tag
    /// @return a buffer whose first [#compoundLength(byte\[\])] bytes are the compound packet, followed by `tailroom`
    ///         spare bytes
    public static byte[] senderReport(long ssrc, long wallClockMillis, long rtpTimestamp, long packetCount,
                                      long octetCount, ReceptionReport reception, String cname, int tailroom) {
        var out = new ByteArrayOutputStream();
        var blocks = reception == null ? 0 : 1;
        writeHeader(out, blocks, 200, 6 + 6 * blocks);
        writeUint32(out, ssrc);
        var seconds = wallClockMillis / 1000 + NTP_UNIX_OFFSET_SECONDS;
        var fraction = ((wallClockMillis % 1000) << 32) / 1000;
        writeUint32(out, seconds);
        writeUint32(out, fraction);
        writeUint32(out, rtpTimestamp);
        writeUint32(out, packetCount);
        writeUint32(out, octetCount);
        if (reception != null) {
            writeReceptionBlock(out, reception);
        }
        writeSourceDescription(out, ssrc, cname);
        return withTailroom(out, tailroom);
    }

    /// Builds a compound packet with a receiver report and a source description.
    ///
    /// @param ssrc      the local synchronization source, an unsigned 32-bit value
    /// @param reception the reception report of the remote source, or `null` for none
    /// @param cname     the canonical name; its UTF-8 encoding is cut to 255 bytes
    /// @param tailroom  the number of spare zero bytes to leave after the packet
    /// @return a buffer whose first [#compoundLength(byte\[\])] bytes are the compound packet, followed by `tailroom`
    ///         spare bytes
    public static byte[] receiverReport(long ssrc, ReceptionReport reception, String cname, int tailroom) {
        var out = new ByteArrayOutputStream();
        var blocks = reception == null ? 0 : 1;
        writeHeader(out, blocks, 201, 1 + 6 * blocks);
        writeUint32(out, ssrc);
        if (reception != null) {
            writeReceptionBlock(out, reception);
        }
        writeSourceDescription(out, ssrc, cname);
        return withTailroom(out, tailroom);
    }

    /// {@return the length of the compound packet at the start of a buffer built by this class: the summed lengths
    /// of its RTCP packets, the tailroom excluded}
    ///
    /// The walk stops at the first word that is not an RTCP version 2 header, so it works only on a buffer whose
    /// tailroom is still zero.
    ///
    /// @param packet the buffer
    public static int compoundLength(byte[] packet) {
        var offset = 0;
        while (offset + 4 <= packet.length && (packet[offset] & 0xC0) == 0x80) {
            var words = (packet[offset + 2] & 0xFF) << 8 | (packet[offset + 3] & 0xFF);
            offset += 4 * (words + 1);
        }
        return Math.min(offset, packet.length);
    }

    /// Writes an RTCP common header.
    ///
    /// @param count  the report or source count
    /// @param type   the packet type
    /// @param length the length in 32-bit words minus one
    private static void writeHeader(ByteArrayOutputStream out, int count, int type, int length) {
        out.write(0x80 | count);
        out.write(type);
        out.write(length >>> 8);
        out.write(length);
    }

    /// Writes one reception report block, clamping the cumulative loss to its signed 24-bit field and leaving the
    /// last sender report fields zero.
    private static void writeReceptionBlock(ByteArrayOutputStream out, ReceptionReport report) {
        writeUint32(out, report.ssrc());
        var lost = Math.max(-0x800000, Math.min(0x7FFFFF, report.cumulativeLost()));
        writeUint32(out, ((long) (report.fractionLost() & 0xFF) << 24) | (lost & 0xFFFFFF));
        writeUint32(out, report.highestSequence());
        writeUint32(out, report.jitter());
        writeUint32(out, 0);
        writeUint32(out, 0);
    }

    /// Writes a source description with one `CNAME` item, padded to a word boundary with at least one zero byte.
    private static void writeSourceDescription(ByteArrayOutputStream out, long ssrc, String cname) {
        var name = cname.getBytes(StandardCharsets.UTF_8);
        var nameLength = Math.min(name.length, 255);
        var chunkLength = 4 + 2 + nameLength + 1;
        var padded = (chunkLength + 3) & ~3;
        writeHeader(out, 1, 202, padded / 4);
        writeUint32(out, ssrc);
        out.write(1);
        out.write(nameLength);
        out.write(name, 0, nameLength);
        for (var i = chunkLength - 1; i < padded; i++) {
            out.write(0);
        }
    }

    /// {@return the bytes of `out` followed by `tailroom` zero bytes}
    private static byte[] withTailroom(ByteArrayOutputStream out, int tailroom) {
        var packet = out.toByteArray();
        var result = new byte[packet.length + tailroom];
        System.arraycopy(packet, 0, result, 0, packet.length);
        return result;
    }

    /// Writes the low 32 bits of `value` big-endian.
    private static void writeUint32(ByteArrayOutputStream out, long value) {
        out.write((int) (value >>> 24));
        out.write((int) (value >>> 16));
        out.write((int) (value >>> 8));
        out.write((int) value);
    }

    /// The reception statistics of one remote source, as a report block carries them.
    ///
    /// The last-sender-report fields of the block are written as zero.
    ///
    /// @param ssrc            the remote source, an unsigned 32-bit value
    /// @param fractionLost    the fraction lost since the previous report, in 1/256 units; only the low eight bits
    ///                        are encoded
    /// @param cumulativeLost  the cumulative number of packets lost, clamped to a signed 24-bit value
    /// @param highestSequence the extended highest sequence number received
    /// @param jitter          the interarrival jitter, in timestamp units
    /// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
    public record ReceptionReport(long ssrc, int fractionLost, int cumulativeLost, long highestSequence, long jitter) {
    }
}
