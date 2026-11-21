package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// A receiver report (`RR`): the reception report blocks of a participant that has not sent RTP since its previous
/// report.
///
/// A profile-specific extension after the report blocks is skipped when parsing and never written.
///
/// @param ssrc    the reporter, an unsigned 32-bit value
/// @param reports the reception report blocks, at most 31; an empty receiver report opens a compound packet that
///                carries only feedback or a source description
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record ReceiverReport(long ssrc, List<ReceptionReport> reports) implements RtcpPacket {
    /// Validates the ranges and copies `reports`.
    ///
    /// @throws IllegalArgumentException if `ssrc` is out of range or there are more than 31 reports
    public ReceiverReport {
        RtcpCodec.checkUint32(ssrc, "ssrc");
        reports = List.copyOf(Objects.requireNonNull(reports, "reports cannot be null"));
        if (reports.size() > 31) {
            throw new IllegalArgumentException("at most 31 reception reports: " + reports.size());
        }
    }

    static ReceiverReport parse(int count, ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 4 + count * ReceptionReport.LENGTH, "receiver report");
        var ssrc = RtcpCodec.uint32(body);
        var reports = new ArrayList<ReceptionReport>(count);
        for (var i = 0; i < count; i++) {
            reports.add(ReceptionReport.read(body));
        }
        return new ReceiverReport(ssrc, reports);
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + 4 + reports.size() * ReceptionReport.LENGTH;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, reports.size(), RECEIVER_REPORT, length);
        destination.putInt((int) ssrc);
        for (var report : reports) {
            report.write(destination);
        }
        return length;
    }
}
