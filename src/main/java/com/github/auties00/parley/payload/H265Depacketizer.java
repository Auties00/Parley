package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.FrameMetadata;
import com.github.auties00.parley.media.H265FrameMetadata;
import com.github.auties00.parley.media.Resolution;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/// The H.265 depacketizer of RFC 7798: single NAL unit packets, aggregation packets and fragmentation units, without
/// decoding order numbers. PACI packets are rejected.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7798.html RFC 7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
final class H265Depacketizer extends NalDepacketizer {
    /// Creates a depacketizer.
    H265Depacketizer(List<ByteBuffer> initialSets) {
        super(initialSets);
    }

    @Override
    List<Unit> units(ByteBuffer payload) throws PayloadFormatException {
        if (payload.remaining() < 3) {
            throw new PayloadFormatException("truncated H.265 payload");
        }
        var start = payload.position();
        var header = payload.getShort(start) & 0xFFFF;
        if ((header & 0x8000) != 0) {
            throw new PayloadFormatException("H.265 forbidden bit set");
        }
        var type = (header >>> 9) & 0x3F;
        if (type < H265Packetizer.AP) {
            return List.of(new Unit.Whole(payload.slice()));
        }
        return switch (type) {
            case H265Packetizer.AP -> {
                var units = new ArrayList<Unit>();
                var offset = start + 2;
                while (offset < payload.limit()) {
                    if (offset + 2 > payload.limit()) {
                        throw new PayloadFormatException("truncated aggregation packet size");
                    }
                    var size = payload.getShort(offset) & 0xFFFF;
                    offset += 2;
                    if (size < 2 || offset + size > payload.limit()) {
                        throw new PayloadFormatException("invalid aggregation packet NAL unit size");
                    }
                    units.add(new Unit.Whole(payload.slice(offset, size)));
                    offset += size;
                }
                if (units.size() < 2) {
                    throw new PayloadFormatException("aggregation packet with fewer than two NAL units");
                }
                yield units;
            }
            case H265Packetizer.FU -> {
                var fuHeader = Payloads.u8(payload, start + 2);
                var first = (fuHeader & 0x80) != 0;
                var last = (fuHeader & 0x40) != 0;
                if (first && last) {
                    throw new PayloadFormatException("fragmentation unit with both start and end bits");
                }
                if (payload.remaining() == 3) {
                    throw new PayloadFormatException("empty fragmentation unit");
                }
                var nalHeader = (header & 0x81FF) | (fuHeader & 0x3F) << 9;
                yield List.of(new Unit.Fragment(new byte[]{(byte) (nalHeader >>> 8), (byte) nalHeader}, first, last,
                        payload.slice(start + 3, payload.remaining() - 3)));
            }
            default -> throw new PayloadFormatException("unsupported H.265 packet type " + type);
        };
    }

    @Override
    int type(ByteBuffer nal) {
        return (nal.get(nal.position()) >>> 1) & 0x3F;
    }

    @Override
    int headerSize() {
        return 2;
    }

    @Override
    int[] parameterSetTypes() {
        return new int[]{32, 33, 34};
    }

    @Override
    int spsType() {
        return 33;
    }

    @Override
    boolean isRandomAccess(int type) {
        return type >= 16 && type <= 23;
    }

    /// {@return whether a NAL unit begins an access unit: a parameter set, an access unit delimiter or a prefix SEI,
    /// or a slice segment with `first_slice_segment_in_pic_flag` set}
    @Override
    boolean startsAccessUnit(ByteBuffer nal) {
        var type = type(nal);
        if (type == 32 || type == 33 || type == 34 || type == 35 || type == 39) {
            return true;
        }
        return type <= 31 && nal.remaining() >= 3 && (nal.get(nal.position() + 2) & 0x80) != 0;
    }

    @Override
    Optional<Resolution> resolution(ByteBuffer sps) {
        return NalUnits.h265Resolution(sps);
    }

    @Override
    int temporalId(ByteBuffer nal) {
        return nal.remaining() < 2 ? 0 : Math.max(0, (nal.get(nal.position() + 1) & 0x07) - 1);
    }

    @Override
    FrameMetadata metadata(boolean randomAccess, int temporalId, List<Integer> types,
                           Optional<Resolution> resolution) {
        return new H265FrameMetadata(randomAccess, Math.min(temporalId, 6), types, resolution, OptionalLong.empty(),
                List.of());
    }
}
