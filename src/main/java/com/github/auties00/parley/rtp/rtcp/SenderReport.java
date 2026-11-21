package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// A sender report (`SR`): the transmission statistics of an active sender, the wall clock to RTP timestamp mapping
/// receivers synchronize streams with, and up to 31 reception report blocks.
///
/// A profile-specific extension after the report blocks is skipped when parsing and never written.
///
/// @param ssrc         the sender, an unsigned 32-bit value
/// @param ntpTimestamp the wall clock time of the report as a 64-bit NTP timestamp (see `NtpTime`)
/// @param rtpTimestamp the RTP timestamp corresponding to `ntpTimestamp`, an unsigned 32-bit value
/// @param packetCount  the RTP packets sent since transmission started, modulo `2^32`
/// @param octetCount   the payload octets sent since transmission started, modulo `2^32`
/// @param reports      the reception report blocks, at most 31
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record SenderReport(long ssrc, long ntpTimestamp, long rtpTimestamp, long packetCount, long octetCount,
                           List<ReceptionReport> reports) implements RtcpPacket {
    /// Validates the ranges and copies `reports`.
    ///
    /// @throws IllegalArgumentException if a field is out of its range or there are more than 31 reports
    public SenderReport {
        RtcpCodec.checkUint32(ssrc, "ssrc");
        RtcpCodec.checkUint32(rtpTimestamp, "rtpTimestamp");
        RtcpCodec.checkUint32(packetCount, "packetCount");
        RtcpCodec.checkUint32(octetCount, "octetCount");
        reports = List.copyOf(Objects.requireNonNull(reports, "reports cannot be null"));
        if (reports.size() > 31) {
            throw new IllegalArgumentException("at most 31 reception reports: " + reports.size());
        }
    }

    static SenderReport parse(int count, ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 24 + count * ReceptionReport.LENGTH, "sender report");
        var ssrc = RtcpCodec.uint32(body);
        var ntp = body.getLong();
        var rtp = RtcpCodec.uint32(body);
        var packets = RtcpCodec.uint32(body);
        var octets = RtcpCodec.uint32(body);
        var reports = new ArrayList<ReceptionReport>(count);
        for (var i = 0; i < count; i++) {
            reports.add(ReceptionReport.read(body));
        }
        return new SenderReport(ssrc, ntp, rtp, packets, octets, reports);
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + 24 + reports.size() * ReceptionReport.LENGTH;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, reports.size(), SENDER_REPORT, length);
        destination.putInt((int) ssrc);
        destination.putLong(ntpTimestamp);
        destination.putInt((int) rtpTimestamp);
        destination.putInt((int) packetCount);
        destination.putInt((int) octetCount);
        for (var report : reports) {
            report.write(destination);
        }
        return length;
    }
}
