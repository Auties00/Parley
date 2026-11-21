package com.github.auties00.parley.rtp.rtcp;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;

/// One RTCP packet: a report, a source description, a goodbye, application data, an extended report or a feedback
/// message.
///
/// RTCP packets travel stacked in compound packets ([#parseCompound(ByteBuffer)], [#encodeCompound(List, int)]); a
/// session that negotiated `a=rtcp-rsize` also sends and accepts reduced-size packets, a single feedback message
/// without the leading report. Parsing accepts both: the compound rules of RFC 3550 section 6.1 (a report first, a
/// `CNAME` in every compound packet) are the sender's duty and are not enforced on receipt.
///
/// Every implementation is an immutable record that knows its own wire size ([#encodedLength()]) and writes itself
/// ([#writeTo(ByteBuffer)]). Packet types or feedback formats Parley does not model are kept as [UnknownRtcp], so a
/// compound packet round-trips without loss.
///
/// | Packet | Type | Format | Specification |
/// |---|---|---|---|
/// | [SenderReport] | 200 | | RFC 3550 section 6.4.1 |
/// | [ReceiverReport] | 201 | | RFC 3550 section 6.4.2 |
/// | [SourceDescription] | 202 | | RFC 3550 section 6.5, RFC 8852, RFC 8843 |
/// | [Bye] | 203 | | RFC 3550 section 6.6 |
/// | [App] | 204 | | RFC 3550 section 6.7 |
/// | [Nack] | 205 | 1 | RFC 4585 section 6.2.1 |
/// | [CongestionControlFeedback] | 205 | 11 | RFC 8888 |
/// | [TransportFeedback] | 205 | 15 | draft-holmer-rmcat-transport-wide-cc-extensions-01 |
/// | [PictureLossIndication] | 206 | 1 | RFC 4585 section 6.3.1 |
/// | [FullIntraRequest] | 206 | 4 | RFC 5104 section 4.3.1 |
/// | [Remb] | 206 | 15 | draft-alvestrand-rmcat-remb-03 |
/// | [ExtendedReport] | 207 | | RFC 3611 |
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
public sealed interface RtcpPacket permits SenderReport, ReceiverReport, SourceDescription, Bye, App,
        ExtendedReport, Nack, PictureLossIndication, FullIntraRequest, Remb, TransportFeedback,
        CongestionControlFeedback, UnknownRtcp {
    /// The packet type of a sender report.
    int SENDER_REPORT = 200;
    /// The packet type of a receiver report.
    int RECEIVER_REPORT = 201;
    /// The packet type of a source description.
    int SOURCE_DESCRIPTION = 202;
    /// The packet type of a goodbye.
    int BYE = 203;
    /// The packet type of application-defined data.
    int APP = 204;
    /// The packet type of transport-layer feedback (`RTPFB`).
    int TRANSPORT_FEEDBACK = 205;
    /// The packet type of payload-specific feedback (`PSFB`).
    int PAYLOAD_FEEDBACK = 206;
    /// The packet type of an extended report.
    int EXTENDED_REPORT = 207;

    /// Parses every packet of a compound (or reduced-size) RTCP packet.
    ///
    /// The buffer's position and limit are not changed and nothing is retained: every parsed packet owns copies of
    /// the bytes it keeps.
    ///
    /// @param compound the packet bytes between position and limit
    /// @return the packets, in order
    /// @throws RtcpFormatException if a packet is not version 2, its length overruns the buffer, the buffer has
    ///                             trailing bytes shorter than a header, or a known packet type is malformed
    static List<RtcpPacket> parseCompound(ByteBuffer compound) throws RtcpFormatException {
        Objects.requireNonNull(compound, "compound cannot be null");
        return RtcpCodec.parseCompound(compound.duplicate());
    }

    /// Encodes packets as one compound packet into a new heap buffer.
    ///
    /// @param packets  the packets, in order; one packet is a reduced-size packet
    /// @param tailroom spare bytes to leave after the packet, such as the room SRTCP needs to protect it in place
    /// @return a buffer positioned at zero with its limit at the end of the compound packet and its capacity
    ///         `limit + tailroom`
    /// @throws IllegalArgumentException if `packets` is empty or `tailroom` is negative
    static ByteBuffer encodeCompound(List<? extends RtcpPacket> packets, int tailroom) {
        Objects.requireNonNull(packets, "packets cannot be null");
        if (packets.isEmpty()) {
            throw new IllegalArgumentException("packets cannot be empty");
        }
        if (tailroom < 0) {
            throw new IllegalArgumentException("tailroom cannot be negative: " + tailroom);
        }
        var length = 0;
        for (var packet : packets) {
            length += packet.encodedLength();
        }
        var buffer = ByteBuffer.allocate(length + tailroom);
        for (var packet : packets) {
            packet.writeTo(buffer);
        }
        return buffer.flip();
    }

    /// {@return the number of bytes [#writeTo(ByteBuffer)] writes, a multiple of four}
    int encodedLength();

    /// Writes the packet at the position of `destination` and advances the position past it.
    ///
    /// @param destination the buffer to write into
    /// @return the number of bytes written, [#encodedLength()]
    /// @throws BufferOverflowException if the packet does not fit in the remaining bytes
    int writeTo(ByteBuffer destination);
}
