package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;

/// The RTP retransmission payload format: a retransmitted packet travels on its own SSRC, sequence space and payload
/// type, with the original sequence number (`OSN`) prepended to the original payload.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         RTP Header                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            OSN                |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                  Original RTP Packet Payload                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
public final class Rtx {
    private Rtx() {
        throw new AssertionError("Rtx cannot be instantiated");
    }

    /// {@return a new heap buffer holding the RTX payload of a packet: its sequence number and its payload}
    ///
    /// @param original the packet to retransmit
    public static ByteBuffer payloadOf(RtpPacket original) {
        var payload = ByteBuffer.allocate(2 + original.payloadLength());
        payload.putShort((short) original.sequence());
        payload.put(original.payload());
        return payload.flip();
    }

    /// {@return the original sequence number an RTX packet carries}
    ///
    /// @param rtx the retransmission packet
    /// @throws RtpFormatException if the payload is shorter than the two-byte OSN
    public static int originalSequence(RtpPacket rtx) throws RtpFormatException {
        if (rtx.payloadLength() < 2) {
            throw new RtpFormatException("RTX payload shorter than its original sequence number");
        }
        return rtx.payload().getShort(0) & 0xFFFF;
    }

    /// Rebuilds the original packet from a retransmission.
    ///
    /// The rebuilt packet keeps the RTX packet's marker, timestamp, CSRCs and header extension block, takes the
    /// original sequence number, payload type and SSRC, and drops the padding.
    ///
    /// @param rtx                 the retransmission packet
    /// @param originalPayloadType the payload type the RTX payload type is associated with (`apt`)
    /// @param originalSsrc        the SSRC of the repaired stream
    /// @return a view of the rebuilt packet over a new heap buffer
    /// @throws RtpFormatException if the payload is shorter than the two-byte OSN
    public static RtpPacket restore(RtpPacket rtx, int originalPayloadType, long originalSsrc)
            throws RtpFormatException {
        var sequence = originalSequence(rtx);
        var header = rtx.headerLength();
        var payload = rtx.payloadLength() - 2;
        var out = ByteBuffer.allocate(header + payload);
        var source = rtx.buffer();
        out.put(source.slice(0, header));
        out.put(0, (byte) (out.get(0) & ~0x20));
        out.put(1, (byte) ((out.get(1) & 0x80) | originalPayloadType));
        out.putShort(2, (short) sequence);
        out.putInt(8, (int) originalSsrc);
        out.put(source.slice(header + 2, payload));
        return RtpPacket.parse(out.flip());
    }
}
