package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;

/// A picture loss indication (payload-specific feedback, format 1): the receiver lost an undefined amount of coded
/// video data and asks the sender of `mediaSsrc` for a decoder refresh, usually a keyframe.
///
/// @param senderSsrc the feedback sender, an unsigned 32-bit value
/// @param mediaSsrc  the media source to refresh, an unsigned 32-bit value
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
public record PictureLossIndication(long senderSsrc, long mediaSsrc) implements RtcpPacket {
    /// The feedback message type of a PLI.
    public static final int FORMAT = 1;

    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if an SSRC is out of range
    public PictureLossIndication {
        RtcpCodec.checkUint32(senderSsrc, "senderSsrc");
        RtcpCodec.checkUint32(mediaSsrc, "mediaSsrc");
    }

    static PictureLossIndication parse(ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 8, "PLI");
        return new PictureLossIndication(RtcpCodec.uint32(body), RtcpCodec.uint32(body));
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + 8;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, FORMAT, PAYLOAD_FEEDBACK, length);
        destination.putInt((int) senderSsrc);
        destination.putInt((int) mediaSsrc);
        return length;
    }
}
