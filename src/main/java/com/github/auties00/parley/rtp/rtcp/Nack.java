package com.github.auties00.parley.rtp.rtcp;

import com.github.auties00.parley.rtp.SequenceNumbers;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// A generic negative acknowledgement (transport-layer feedback, format 1): the receiver asks the sender of
/// `mediaSsrc` to retransmit the listed packets.
///
/// On the wire the sequence numbers are packed into `PID`/`BLP` pairs: a packet id plus a bitmask of the 16 that
/// follow it. [#sequences()] holds them unpacked, in wire order; writing packs them again, starting a new pair
/// whenever a number is not within 16 after the current pair's id.
///
/// @param senderSsrc the feedback sender, an unsigned 32-bit value
/// @param mediaSsrc  the media source whose packets are missing, an unsigned 32-bit value
/// @param sequences  the missing sequence numbers, `0..65535` each, at least one
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
public record Nack(long senderSsrc, long mediaSsrc, List<Integer> sequences) implements RtcpPacket {
    /// The feedback message type of a generic NACK.
    public static final int FORMAT = 1;

    /// Validates the fields and copies `sequences`.
    ///
    /// @throws IllegalArgumentException if an SSRC or a sequence number is out of range or `sequences` is empty
    public Nack {
        RtcpCodec.checkUint32(senderSsrc, "senderSsrc");
        RtcpCodec.checkUint32(mediaSsrc, "mediaSsrc");
        sequences = List.copyOf(Objects.requireNonNull(sequences, "sequences cannot be null"));
        if (sequences.isEmpty()) {
            throw new IllegalArgumentException("sequences cannot be empty");
        }
        for (var sequence : sequences) {
            if (sequence < 0 || sequence > 0xFFFF) {
                throw new IllegalArgumentException("sequence must be in 0..65535: " + sequence);
            }
        }
    }

    static Nack parse(ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 12, "NACK");
        if (body.remaining() % 4 != 0) {
            throw new RtcpFormatException("NACK body is not a multiple of four bytes");
        }
        var sender = RtcpCodec.uint32(body);
        var media = RtcpCodec.uint32(body);
        var sequences = new ArrayList<Integer>();
        while (body.hasRemaining()) {
            var pid = body.getShort() & 0xFFFF;
            var blp = body.getShort() & 0xFFFF;
            sequences.add(pid);
            for (var bit = 0; bit < 16; bit++) {
                if ((blp & (1 << bit)) != 0) {
                    sequences.add(SequenceNumbers.add(pid, bit + 1));
                }
            }
        }
        return new Nack(sender, media, sequences);
    }

    /// Packs the sequences into `PID`/`BLP` items, each an int holding `PID << 16 | BLP`.
    private int[] items() {
        var out = new int[sequences.size()];
        var count = 0;
        var pid = -1;
        var blp = 0;
        for (var sequence : sequences) {
            if (pid >= 0) {
                var distance = (sequence - pid) & 0xFFFF;
                if (distance == 0) {
                    continue;
                }
                if (distance <= 16) {
                    blp |= 1 << (distance - 1);
                    continue;
                }
                out[count++] = pid << 16 | blp;
            }
            pid = sequence;
            blp = 0;
        }
        out[count++] = pid << 16 | blp;
        var result = new int[count];
        System.arraycopy(out, 0, result, 0, count);
        return result;
    }

    @Override
    public int encodedLength() {
        return RtcpCodec.HEADER_LENGTH + 8 + 4 * items().length;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var items = items();
        var length = RtcpCodec.HEADER_LENGTH + 8 + 4 * items.length;
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, FORMAT, TRANSPORT_FEEDBACK, length);
        destination.putInt((int) senderSsrc);
        destination.putInt((int) mediaSsrc);
        for (var item : items) {
            destination.putInt(item);
        }
        return length;
    }
}
