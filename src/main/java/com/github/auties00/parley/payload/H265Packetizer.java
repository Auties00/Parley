package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/// The H.265 packetizer of RFC 7798: single NAL unit packets, aggregation packets (AP) and fragmentation units (FU),
/// without decoding order numbers (`sprop-max-don-diff` of `0`).
///
/// @spec https://www.rfc-editor.org/rfc/rfc7798.html RFC 7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
final class H265Packetizer extends NalPacketizer {
    /// The aggregation packet NAL unit type.
    static final int AP = 48;

    /// The fragmentation unit NAL unit type.
    static final int FU = 49;

    /// Creates a packetizer.
    H265Packetizer(PacketizerConfig config, List<ByteBuffer> initialSets) {
        super(config, true, initialSets);
    }

    @Override
    int type(ByteBuffer nal) {
        return (nal.get(nal.position()) >>> 1) & 0x3F;
    }

    @Override
    int[] parameterSetTypes() {
        return new int[]{32, 33, 34};
    }

    @Override
    boolean isRandomAccess(int type) {
        return type >= 16 && type <= 23;
    }

    @Override
    int headerSize() {
        return 2;
    }

    @Override
    ByteBuffer aggregate(List<ByteBuffer> nals) {
        var size = 2;
        var forbidden = 0;
        var layerId = 63;
        var tidPlus1 = 7;
        for (var nal : nals) {
            size += 2 + nal.remaining();
            var header = nal.getShort(nal.position()) & 0xFFFF;
            forbidden |= header & 0x8000;
            layerId = Math.min(layerId, (header >>> 3) & 0x3F);
            tidPlus1 = Math.min(tidPlus1, header & 0x07);
        }
        var out = ByteBuffer.allocate(size);
        out.putShort((short) (forbidden | AP << 9 | layerId << 3 | tidPlus1));
        for (var nal : nals) {
            out.putShort((short) nal.remaining());
            out.put(nal.duplicate());
        }
        return out.flip();
    }

    @Override
    void fragment(ByteBuffer nal, List<ByteBuffer> headers, List<ByteBuffer> bodies) {
        var header = nal.getShort(nal.position()) & 0xFFFF;
        var type = (header >>> 9) & 0x3F;
        var body = nal.slice(nal.position() + 2, nal.remaining() - 2);
        var fragments = Payloads.split(body, maxPayloadSize - 3);
        for (var k = 0; k < fragments.size(); k++) {
            var unit = ByteBuffer.allocate(3);
            unit.putShort((short) ((header & 0x81FF) | FU << 9));
            unit.put((byte) ((k == 0 ? 0x80 : 0) | (k == fragments.size() - 1 ? 0x40 : 0) | type));
            headers.add(unit.flip());
            bodies.add(fragments.get(k));
        }
    }
}
