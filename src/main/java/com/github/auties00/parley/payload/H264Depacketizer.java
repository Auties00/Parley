package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.FrameMetadata;
import com.github.auties00.parley.media.H264FrameMetadata;
import com.github.auties00.parley.media.Resolution;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/// The H.264 depacketizer of RFC 6184: single NAL unit packets, STAP-A and FU-A. The interleaved mode's STAP-B, MTAP
/// and FU-B are rejected.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
final class H264Depacketizer extends NalDepacketizer {
    /// Creates a depacketizer.
    H264Depacketizer(List<ByteBuffer> initialSets) {
        super(initialSets);
    }

    @Override
    List<Unit> units(ByteBuffer payload) throws PayloadFormatException {
        if (!payload.hasRemaining()) {
            throw new PayloadFormatException("empty H.264 payload");
        }
        var start = payload.position();
        var header = Payloads.u8(payload, start);
        var type = header & 0x1F;
        if (type >= 1 && type <= 23) {
            return List.of(new Unit.Whole(payload.slice()));
        }
        return switch (type) {
            case H264Packetizer.STAP_A -> {
                var units = new ArrayList<Unit>();
                var offset = start + 1;
                while (offset < payload.limit()) {
                    if (offset + 2 > payload.limit()) {
                        throw new PayloadFormatException("truncated STAP-A size");
                    }
                    var size = payload.getShort(offset) & 0xFFFF;
                    offset += 2;
                    if (size == 0 || offset + size > payload.limit()) {
                        throw new PayloadFormatException("invalid STAP-A NAL unit size");
                    }
                    units.add(new Unit.Whole(payload.slice(offset, size)));
                    offset += size;
                }
                if (units.isEmpty()) {
                    throw new PayloadFormatException("empty STAP-A");
                }
                yield units;
            }
            case H264Packetizer.FU_A -> {
                if (payload.remaining() < 3) {
                    throw new PayloadFormatException("truncated FU-A");
                }
                var fuHeader = Payloads.u8(payload, start + 1);
                var first = (fuHeader & 0x80) != 0;
                var last = (fuHeader & 0x40) != 0;
                if (first && last) {
                    throw new PayloadFormatException("FU-A with both start and end bits");
                }
                var nalHeader = new byte[]{(byte) ((header & 0xE0) | (fuHeader & 0x1F))};
                yield List.of(new Unit.Fragment(nalHeader, first, last,
                        payload.slice(start + 2, payload.remaining() - 2)));
            }
            default -> throw new PayloadFormatException("unsupported H.264 packet type " + type);
        };
    }

    @Override
    int type(ByteBuffer nal) {
        return nal.get(nal.position()) & 0x1F;
    }

    @Override
    int headerSize() {
        return 1;
    }

    @Override
    int[] parameterSetTypes() {
        return new int[]{7, 8};
    }

    @Override
    int spsType() {
        return 7;
    }

    @Override
    boolean isRandomAccess(int type) {
        return type == 5;
    }

    /// {@return whether a NAL unit begins an access unit: an access unit delimiter, SEI or parameter set, or a slice
    /// whose `first_mb_in_slice` is zero}
    @Override
    boolean startsAccessUnit(ByteBuffer nal) {
        var type = type(nal);
        return switch (type) {
            case 6, 7, 8, 9, 14, 15 -> true;
            case 1, 5 -> nal.remaining() >= 2 && (nal.get(nal.position() + 1) & 0x80) != 0;
            default -> false;
        };
    }

    @Override
    Optional<Resolution> resolution(ByteBuffer sps) {
        return NalUnits.h264Resolution(sps);
    }

    @Override
    int temporalId(ByteBuffer nal) {
        return 0;
    }

    @Override
    FrameMetadata metadata(boolean randomAccess, int temporalId, List<Integer> types,
                           Optional<Resolution> resolution) {
        return new H264FrameMetadata(randomAccess, types, resolution, OptionalLong.empty(), List.of());
    }
}
