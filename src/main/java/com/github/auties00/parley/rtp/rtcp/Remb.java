package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// A receiver estimated maximum bitrate (application-layer payload-specific feedback, format 15, identifier
/// `REMB`): the total bitrate the receiver estimates the listed media streams can share.
///
/// The bitrate travels as an 18-bit mantissa and a 6-bit exponent, so a written value keeps its 18 most significant
/// bits and is rounded down to them.
///
/// @param senderSsrc the feedback sender, an unsigned 32-bit value
/// @param bitrateBps the estimated maximum bitrate in bits per second, non-negative
/// @param ssrcs      the media sources the estimate applies to, at most 255
/// @spec https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03 RTCP message for Receiver Estimated Maximum Bitrate
public record Remb(long senderSsrc, long bitrateBps, List<Long> ssrcs) implements RtcpPacket {
    /// The feedback message type of application-layer feedback.
    public static final int FORMAT = 15;

    private static final int IDENTIFIER = 'R' << 24 | 'E' << 16 | 'M' << 8 | 'B';

    /// Validates the fields and copies `ssrcs`.
    ///
    /// @throws IllegalArgumentException if a field is out of range or there are more than 255 sources
    public Remb {
        RtcpCodec.checkUint32(senderSsrc, "senderSsrc");
        if (bitrateBps < 0) {
            throw new IllegalArgumentException("bitrateBps cannot be negative: " + bitrateBps);
        }
        ssrcs = List.copyOf(Objects.requireNonNull(ssrcs, "ssrcs cannot be null"));
        if (ssrcs.size() > 255) {
            throw new IllegalArgumentException("at most 255 SSRCs: " + ssrcs.size());
        }
        RtcpCodec.checkSsrcs(ssrcs, "ssrc");
    }

    static boolean isRemb(ByteBuffer body) {
        return body.remaining() >= 12 && body.getInt(body.position() + 8) == IDENTIFIER;
    }

    static Remb parse(ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 16, "REMB");
        var sender = RtcpCodec.uint32(body);
        body.getInt();
        body.getInt();
        var word = body.getInt();
        var count = word >>> 24;
        var exponent = (word >>> 18) & 0x3F;
        var mantissa = word & 0x3FFFF;
        RtcpCodec.requireRemaining(body, 4 * count, "REMB SSRC list");
        var ssrcs = new ArrayList<Long>(count);
        for (var i = 0; i < count; i++) {
            ssrcs.add(RtcpCodec.uint32(body));
        }
        var bitrate = exponent >= 46 ? Long.MAX_VALUE : (long) mantissa << exponent;
        if (exponent < 46 && bitrate >>> exponent != mantissa) {
            bitrate = Long.MAX_VALUE;
        }
        return new Remb(sender, bitrate, ssrcs);
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + 16 + 4 * ssrcs.size();
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        var exponent = 0;
        var mantissa = bitrateBps;
        while (mantissa >= (1 << 18)) {
            mantissa >>>= 1;
            exponent++;
        }
        RtcpCodec.writeHeader(destination, FORMAT, PAYLOAD_FEEDBACK, length);
        destination.putInt((int) senderSsrc);
        destination.putInt(0);
        destination.putInt(IDENTIFIER);
        destination.putInt(ssrcs.size() << 24 | exponent << 18 | (int) mantissa);
        for (var ssrc : ssrcs) {
            destination.putInt(ssrc.intValue());
        }
        return length;
    }
}
