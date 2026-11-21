package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/// The H.264 packetizer of RFC 6184: single NAL unit packets, STAP-A aggregation and FU-A fragmentation in
/// non-interleaved mode, single NAL unit packets only in packetization mode 0.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
final class H264Packetizer extends NalPacketizer {
    /// The STAP-A NAL unit type.
    static final int STAP_A = 24;

    /// The FU-A NAL unit type.
    static final int FU_A = 28;

    /// Creates a packetizer.
    H264Packetizer(PacketizerConfig config, boolean nonInterleaved, List<ByteBuffer> initialSets) {
        super(config, nonInterleaved, initialSets);
    }

    @Override
    int type(ByteBuffer nal) {
        return nal.get(nal.position()) & 0x1F;
    }

    @Override
    int[] parameterSetTypes() {
        return new int[]{7, 8};
    }

    @Override
    boolean isRandomAccess(int type) {
        return type == 5;
    }

    @Override
    int headerSize() {
        return 1;
    }

    @Override
    ByteBuffer aggregate(List<ByteBuffer> nals) {
        var size = 1;
        var forbidden = 0;
        var nri = 0;
        for (var nal : nals) {
            size += 2 + nal.remaining();
            var header = nal.get(nal.position()) & 0xFF;
            forbidden |= header & 0x80;
            nri = Math.max(nri, header & 0x60);
        }
        var out = ByteBuffer.allocate(size);
        out.put((byte) (forbidden | nri | STAP_A));
        for (var nal : nals) {
            out.putShort((short) nal.remaining());
            out.put(nal.duplicate());
        }
        return out.flip();
    }

    @Override
    List<ByteBuffer> fragment(ByteBuffer nal) {
        var header = nal.get(nal.position()) & 0xFF;
        var body = nal.slice(nal.position() + 1, nal.remaining() - 1);
        var fragments = Payloads.split(body, maxPayloadSize - 2);
        var result = new ArrayList<ByteBuffer>(fragments.size());
        for (var k = 0; k < fragments.size(); k++) {
            var fragment = fragments.get(k);
            var out = ByteBuffer.allocate(2 + fragment.remaining());
            out.put((byte) ((header & 0xE0) | FU_A));
            out.put((byte) ((k == 0 ? 0x80 : 0) | (k == fragments.size() - 1 ? 0x40 : 0) | (header & 0x1F)));
            out.put(fragment);
            result.add(out.flip());
        }
        return result;
    }
}
