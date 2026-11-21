package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/// The AV1 packetizer of the AV1 RTP payload format.
///
/// A frame is a temporal unit (or one layer frame of it) in low-overhead bitstream format. The packetizer drops the
/// temporal delimiter, tile list and padding OBUs, clears `obu_has_size_field` and removes the size of every OBU, and
/// packs the OBU elements greedily: each packet holds as many elements as fit, an element that does not fit is
/// fragmented across packets (`Z` and `Y`), and the last element of a packet with at most three omits its length
/// (`W`). The first packet of a keyframe that carries a sequence header sets `N`.
///
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
final class Av1Packetizer implements Packetizer {
    /// The largest payload.
    private final int maxPayloadSize;

    /// Creates a packetizer.
    Av1Packetizer(PacketizerConfig config) {
        this.maxPayloadSize = config.maxPayloadSize();
    }

    /// One piece of an OBU element in a packet.
    ///
    /// @param element the element's bytes
    /// @param offset  the offset of the piece in the element
    /// @param length  the length of the piece
    private record Piece(byte[] element, int offset, int length) {
    }

    @Override
    public List<PacketizedPayload> packetize(EncodedFrame frame) {
        Payloads.checkKind(frame, MediaKind.VIDEO);
        var elements = new ArrayList<byte[]>();
        var sequenceHeader = false;
        for (var obu : Obus.parseTemporalUnit(frame.data())) {
            if (obu.type() == Obus.TEMPORAL_DELIMITER || obu.type() == Obus.TILE_LIST || obu.type() == Obus.PADDING) {
                continue;
            }
            sequenceHeader |= obu.type() == Obus.SEQUENCE_HEADER;
            elements.add(obu.toElement());
        }
        if (elements.isEmpty()) {
            throw new IllegalArgumentException("AV1 temporal unit without OBUs to send");
        }
        var capacity = maxPayloadSize - 1;
        var packets = new ArrayList<List<Piece>>();
        var current = new ArrayList<Piece>();
        var used = 0;
        for (var element : elements) {
            var offset = 0;
            while (offset < element.length) {
                var space = capacity - used;
                var length = Math.min(element.length - offset, space - 1);
                while (length > 0 && length + Obus.leb128Size(length) > space) {
                    length--;
                }
                if (length <= 0) {
                    packets.add(current);
                    current = new ArrayList<>();
                    used = 0;
                    continue;
                }
                current.add(new Piece(element, offset, length));
                used += length + Obus.leb128Size(length);
                offset += length;
                if (offset < element.length) {
                    packets.add(current);
                    current = new ArrayList<>();
                    used = 0;
                }
            }
        }
        if (!current.isEmpty()) {
            packets.add(current);
        }
        var newSequence = frame.keyframe() && sequenceHeader;
        var result = new ArrayList<PacketizedPayload>(packets.size());
        for (var p = 0; p < packets.size(); p++) {
            var pieces = packets.get(p);
            var first = pieces.getFirst();
            var last = pieces.getLast();
            var continuation = first.offset() > 0;
            var continues = last.offset() + last.length() < last.element().length;
            var count = pieces.size() <= 3 ? pieces.size() : 0;
            var size = 1;
            for (var i = 0; i < pieces.size(); i++) {
                var length = pieces.get(i).length();
                size += length + (count != 0 && i == pieces.size() - 1 ? 0 : Obus.leb128Size(length));
            }
            var out = ByteBuffer.allocate(size);
            out.put((byte) ((continuation ? 0x80 : 0) | (continues ? 0x40 : 0) | count << 4
                    | (newSequence && p == 0 ? 0x08 : 0)));
            for (var i = 0; i < pieces.size(); i++) {
                var piece = pieces.get(i);
                if (count == 0 || i < pieces.size() - 1) {
                    Obus.writeLeb128(out, piece.length());
                }
                out.put(piece.element(), piece.offset(), piece.length());
            }
            result.add(PacketizedPayload.of(out.flip(), p == packets.size() - 1));
        }
        return List.copyOf(result);
    }
}
