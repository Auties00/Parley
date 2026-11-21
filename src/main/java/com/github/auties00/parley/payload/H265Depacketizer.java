package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.FrameMetadata;
import com.github.auties00.parley.media.H265FrameMetadata;
import com.github.auties00.parley.media.Resolution;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// The H.265 depacketizer of RFC 7798: single NAL unit packets, aggregation packets, fragmentation units and PACI
/// packets, with or without decoding order numbers.
///
/// With decoding order numbers (a stream whose `sprop-max-don-diff` is above zero) every NAL unit carries its
/// `DONL`, or in an aggregation packet a `DOND` after the first, and the NAL units of an access unit are put back in
/// decoding order. A PACI packet's payload header extension is skipped and its payload parsed as the packet it wraps.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7798.html RFC 7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
final class H265Depacketizer extends NalDepacketizer {
    /// The packet type of a PACI packet.
    static final int PACI = 50;

    /// Whether every NAL unit carries a decoding order number.
    private final boolean decodingOrderNumbers;

    /// Creates a depacketizer.
    ///
    /// @param initialSets          the parameter sets the format parameters declare
    /// @param decodingOrderNumbers whether the stream carries decoding order numbers
    H265Depacketizer(List<ByteBuffer> initialSets, boolean decodingOrderNumbers) {
        super(initialSets);
        this.decodingOrderNumbers = decodingOrderNumbers;
    }

    @Override
    List<Unit> units(ByteBuffer payload) throws PayloadFormatException {
        return units(payload, true);
    }

    /// {@return the units of a payload; `allowPaci` is `false` inside a PACI packet, which cannot nest}
    private List<Unit> units(ByteBuffer payload, boolean allowPaci) throws PayloadFormatException {
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
            if (!decodingOrderNumbers) {
                return List.of(new Unit.Whole(payload.slice()));
            }
            if (payload.remaining() < 5) {
                throw new PayloadFormatException("truncated H.265 DONL");
            }
            var don = payload.getShort(start + 2) & 0xFFFF;
            var nal = ByteBuffer.allocate(payload.remaining() - 2);
            nal.putShort((short) header).put(payload.slice(start + 4, payload.remaining() - 4));
            return List.of(new Unit.Whole(nal.flip().asReadOnlyBuffer(), OptionalInt.of(don)));
        }
        return switch (type) {
            case H265Packetizer.AP -> aggregation(payload, start);
            case H265Packetizer.FU -> {
                var fuHeader = Payloads.u8(payload, start + 2);
                var first = (fuHeader & 0x80) != 0;
                var last = (fuHeader & 0x40) != 0;
                if (first && last) {
                    throw new PayloadFormatException("fragmentation unit with both start and end bits");
                }
                var dataOffset = start + 3;
                var don = OptionalInt.empty();
                if (decodingOrderNumbers && first) {
                    if (payload.remaining() < 5) {
                        throw new PayloadFormatException("truncated H.265 DONL");
                    }
                    don = OptionalInt.of(payload.getShort(dataOffset) & 0xFFFF);
                    dataOffset += 2;
                }
                if (dataOffset >= payload.limit()) {
                    throw new PayloadFormatException("empty fragmentation unit");
                }
                var nalHeader = (header & 0x81FF) | (fuHeader & 0x3F) << 9;
                yield List.of(new Unit.Fragment(new byte[]{(byte) (nalHeader >>> 8), (byte) nalHeader}, first, last,
                        payload.slice(dataOffset, payload.limit() - dataOffset), don));
            }
            case PACI -> {
                if (!allowPaci) {
                    throw new PayloadFormatException("nested H.265 PACI packet");
                }
                yield units(paciPayload(payload, start, header), false);
            }
            default -> throw new PayloadFormatException("unsupported H.265 packet type " + type);
        };
    }

    /// {@return the NAL units of an aggregation packet}
    private List<Unit> aggregation(ByteBuffer payload, int start) throws PayloadFormatException {
        var units = new ArrayList<Unit>();
        var offset = start + 2;
        var don = -1;
        while (offset < payload.limit()) {
            var number = OptionalInt.empty();
            if (decodingOrderNumbers) {
                if (don < 0) {
                    if (offset + 2 > payload.limit()) {
                        throw new PayloadFormatException("truncated aggregation packet DONL");
                    }
                    don = payload.getShort(offset) & 0xFFFF;
                    offset += 2;
                } else {
                    if (offset + 1 > payload.limit()) {
                        throw new PayloadFormatException("truncated aggregation packet DOND");
                    }
                    don = (don + Payloads.u8(payload, offset) + 1) & 0xFFFF;
                    offset++;
                }
                number = OptionalInt.of(don);
            }
            if (offset + 2 > payload.limit()) {
                throw new PayloadFormatException("truncated aggregation packet size");
            }
            var size = payload.getShort(offset) & 0xFFFF;
            offset += 2;
            if (size < 2 || offset + size > payload.limit()) {
                throw new PayloadFormatException("invalid aggregation packet NAL unit size");
            }
            units.add(new Unit.Whole(payload.slice(offset, size), number));
            offset += size;
        }
        if (units.size() < 2) {
            throw new PayloadFormatException("aggregation packet with fewer than two NAL units");
        }
        return units;
    }

    /// {@return the packet a PACI packet wraps: its payload header with the `F` bit from `A` and the type from
    /// `cType`, followed by the PACI payload after the payload header extension}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc7798.html#section-4.4.4 RFC 7798 section 4.4.4: PACI Packets
    private static ByteBuffer paciPayload(ByteBuffer payload, int start, int header) throws PayloadFormatException {
        if (payload.remaining() < 4) {
            throw new PayloadFormatException("truncated H.265 PACI header");
        }
        var fields = payload.getShort(start + 2) & 0xFFFF;
        var a = fields >>> 15;
        var cType = (fields >>> 9) & 0x3F;
        var extensionSize = (fields >>> 4) & 0x1F;
        if (cType == PACI) {
            throw new PayloadFormatException("nested H.265 PACI packet");
        }
        var payloadStart = start + 4 + extensionSize;
        if (payloadStart >= payload.limit()) {
            throw new PayloadFormatException("H.265 PACI packet without a payload");
        }
        var inner = ByteBuffer.allocate(2 + payload.limit() - payloadStart);
        inner.putShort((short) (a << 15 | cType << 9 | header & 0x01FF));
        inner.put(payload.slice(payloadStart, payload.limit() - payloadStart));
        return inner.flip();
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
