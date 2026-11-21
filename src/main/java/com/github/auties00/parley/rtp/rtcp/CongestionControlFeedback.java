package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// RTP congestion control feedback (transport-layer feedback, format 11): for each reported stream, whether each
/// packet of a sequence range arrived, its ECN marking, and how long before the report timestamp it arrived.
///
/// @param senderSsrc      the feedback sender, an unsigned 32-bit value
/// @param reports         the per-stream reports
/// @param reportTimestamp the time the report was generated, the middle 32 bits of an NTP timestamp (units of
///                        `1/65536` second)
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
public record CongestionControlFeedback(long senderSsrc, List<StreamReport> reports, long reportTimestamp)
        implements RtcpPacket {
    /// The feedback message type of congestion control feedback.
    public static final int FORMAT = 11;

    /// Validates the fields and copies `reports`.
    ///
    /// @throws IllegalArgumentException if a field is out of range
    public CongestionControlFeedback {
        RtcpCodec.checkUint32(senderSsrc, "senderSsrc");
        reports = List.copyOf(Objects.requireNonNull(reports, "reports cannot be null"));
        RtcpCodec.checkUint32(reportTimestamp, "reportTimestamp");
    }

    /// The metrics of one stream.
    ///
    /// @param ssrc          the reported stream, an unsigned 32-bit value
    /// @param beginSequence the RTP sequence number of the first metric, `0..65535`
    /// @param metrics       one metric per sequence number from `beginSequence`, at most 65535
    public record StreamReport(long ssrc, int beginSequence, List<Metric> metrics) {
        /// Validates the fields and copies `metrics`.
        ///
        /// @throws IllegalArgumentException if a field is out of range
        public StreamReport {
            RtcpCodec.checkUint32(ssrc, "ssrc");
            if (beginSequence < 0 || beginSequence > 0xFFFF) {
                throw new IllegalArgumentException("beginSequence must be in 0..65535: " + beginSequence);
            }
            metrics = List.copyOf(Objects.requireNonNull(metrics, "metrics cannot be null"));
            if (metrics.size() > 0xFFFF) {
                throw new IllegalArgumentException("at most 65535 metrics: " + metrics.size());
            }
        }

        int encodedLength() {
            return 8 + RtcpCodec.padTo4(2 * metrics.size());
        }
    }

    /// The fate of one packet.
    ///
    /// @param received          whether the packet arrived
    /// @param ecn               the ECN bits of the arrived packet, `0..3`
    /// @param arrivalTimeOffset the report timestamp minus the arrival time, in units of `1/1024` second, `0..8191`;
    ///                          [#OVER_RANGE] when larger than representable, [#UNAVAILABLE] when unknown
    public record Metric(boolean received, int ecn, int arrivalTimeOffset) {
        /// The offset value of an arrival too long before the report to represent.
        public static final int OVER_RANGE = 0x1FFE;
        /// The offset value of an unknown arrival time.
        public static final int UNAVAILABLE = 0x1FFF;

        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field is out of range
        public Metric {
            if (ecn < 0 || ecn > 3) {
                throw new IllegalArgumentException("ecn must be in 0..3: " + ecn);
            }
            if (arrivalTimeOffset < 0 || arrivalTimeOffset > 0x1FFF) {
                throw new IllegalArgumentException("arrivalTimeOffset must be in 0..8191: " + arrivalTimeOffset);
            }
        }

        /// {@return the metric of a packet that did not arrive}
        public static Metric lost() {
            return new Metric(false, 0, 0);
        }
    }

    static CongestionControlFeedback parse(ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 8, "congestion control feedback");
        var sender = RtcpCodec.uint32(body);
        var reports = new ArrayList<StreamReport>();
        while (body.remaining() > 4) {
            RtcpCodec.requireRemaining(body, 8, "congestion control feedback stream");
            var ssrc = RtcpCodec.uint32(body);
            var begin = body.getShort() & 0xFFFF;
            var count = body.getShort() & 0xFFFF;
            var bytes = RtcpCodec.padTo4(2 * count);
            RtcpCodec.requireRemaining(body, bytes + 4, "congestion control feedback metrics");
            var metrics = new ArrayList<Metric>(count);
            for (var i = 0; i < count; i++) {
                var value = body.getShort() & 0xFFFF;
                metrics.add(new Metric((value & 0x8000) != 0, (value >>> 13) & 0x3, value & 0x1FFF));
            }
            if (count % 2 != 0) {
                body.getShort();
            }
            reports.add(new StreamReport(ssrc, begin, metrics));
        }
        RtcpCodec.requireRemaining(body, 4, "congestion control feedback timestamp");
        return new CongestionControlFeedback(sender, reports, RtcpCodec.uint32(body));
    }

    @Override
    public int encodedLength() {
        var length = RtcpCodec.HEADER_LENGTH + 8;
        for (var report : reports) {
            length += report.encodedLength();
        }
        return length;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, FORMAT, TRANSPORT_FEEDBACK, length);
        destination.putInt((int) senderSsrc);
        for (var report : reports) {
            destination.putInt((int) report.ssrc());
            destination.putShort((short) report.beginSequence());
            destination.putShort((short) report.metrics().size());
            for (var metric : report.metrics()) {
                destination.putShort((short) ((metric.received() ? 0x8000 : 0) | metric.ecn() << 13
                        | metric.arrivalTimeOffset()));
            }
            if (report.metrics().size() % 2 != 0) {
                destination.putShort((short) 0);
            }
        }
        destination.putInt((int) reportTimestamp);
        return length;
    }
}
