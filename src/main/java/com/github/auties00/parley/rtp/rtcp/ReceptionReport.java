package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;

/// One reception report block of a sender or receiver report: what the reporter received from one source.
///
/// @param ssrc                       the source the block reports on, an unsigned 32-bit value
/// @param fractionLost               the fraction of packets lost since the previous report, in units of `1/256`,
///                                   `0..255`
/// @param cumulativeLost             the packets lost since reception started (expected minus received), a signed
///                                   24-bit value: duplicates can make it negative
/// @param extendedHighestSequence    the highest sequence number received, extended with the count of wraps in its
///                                   high 16 bits, an unsigned 32-bit value
/// @param jitter                     the interarrival jitter estimate in RTP timestamp units, an unsigned 32-bit
///                                   value
/// @param lastSenderReport           the middle 32 bits of the NTP timestamp of the last sender report received from
///                                   the source (`LSR`), or `0` if none
/// @param delaySinceLastSenderReport the delay between receiving that sender report and sending this block, in
///                                   units of `1/65536` second (`DLSR`), or `0` if none
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record ReceptionReport(long ssrc, int fractionLost, int cumulativeLost, long extendedHighestSequence,
                              long jitter, long lastSenderReport, long delaySinceLastSenderReport) {
    /// The encoded size of a block.
    public static final int LENGTH = 24;

    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if a field is out of its range
    public ReceptionReport {
        RtcpCodec.checkUint32(ssrc, "ssrc");
        if (fractionLost < 0 || fractionLost > 255) {
            throw new IllegalArgumentException("fractionLost must be in 0..255: " + fractionLost);
        }
        if (cumulativeLost < -0x800000 || cumulativeLost > 0x7FFFFF) {
            throw new IllegalArgumentException("cumulativeLost must be a signed 24-bit value: " + cumulativeLost);
        }
        RtcpCodec.checkUint32(extendedHighestSequence, "extendedHighestSequence");
        RtcpCodec.checkUint32(jitter, "jitter");
        RtcpCodec.checkUint32(lastSenderReport, "lastSenderReport");
        RtcpCodec.checkUint32(delaySinceLastSenderReport, "delaySinceLastSenderReport");
    }

    static ReceptionReport read(ByteBuffer body) {
        var ssrc = RtcpCodec.uint32(body);
        var lost = body.getInt();
        var fraction = lost >>> 24;
        var cumulative = (lost << 8) >> 8;
        return new ReceptionReport(ssrc, fraction, cumulative, RtcpCodec.uint32(body), RtcpCodec.uint32(body),
                RtcpCodec.uint32(body), RtcpCodec.uint32(body));
    }

    void write(ByteBuffer destination) {
        destination.putInt((int) ssrc);
        destination.putInt(fractionLost << 24 | (cumulativeLost & 0xFFFFFF));
        destination.putInt((int) extendedHighestSequence);
        destination.putInt((int) jitter);
        destination.putInt((int) lastSenderReport);
        destination.putInt((int) delaySinceLastSenderReport);
    }
}
