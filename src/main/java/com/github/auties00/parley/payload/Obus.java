package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Resolution;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/// The AV1 open bitstream unit (OBU) plumbing of the AV1 payload format: OBU headers, `leb128` sizes, the
/// low-overhead bitstream format, and the sequence header fields the format reads.
///
/// @spec https://aomediacodec.github.io/av1-spec/ AV1 Bitstream and Decoding Process Specification
final class Obus {
    /// `OBU_SEQUENCE_HEADER`.
    static final int SEQUENCE_HEADER = 1;

    /// `OBU_TEMPORAL_DELIMITER`.
    static final int TEMPORAL_DELIMITER = 2;

    /// `OBU_FRAME_HEADER`.
    static final int FRAME_HEADER = 3;

    /// `OBU_FRAME`.
    static final int FRAME = 6;

    /// `OBU_TILE_LIST`.
    static final int TILE_LIST = 8;

    /// `OBU_PADDING`.
    static final int PADDING = 15;

    private Obus() {
        throw new AssertionError("Obus cannot be instantiated");
    }

    /// One OBU.
    ///
    /// @param type       the `obu_type`
    /// @param extension  whether the header has its extension byte
    /// @param temporalId the `temporal_id`, `0` without extension
    /// @param spatialId  the `spatial_id`, `0` without extension
    /// @param header     the header bytes with `obu_has_size_field` cleared, one or two
    /// @param payload    the payload, without size field
    record Obu(int type, boolean extension, int temporalId, int spatialId, byte[] header, ByteBuffer payload) {
        /// {@return the OBU as an RTP OBU element: the header without size field, then the payload}
        byte[] toElement() {
            var element = new byte[header.length + payload.remaining()];
            System.arraycopy(header, 0, element, 0, header.length);
            payload.get(payload.position(), element, header.length, payload.remaining());
            return element;
        }

        /// Appends the OBU in low-overhead format, with `obu_has_size_field` set.
        void writeLowOverhead(ByteArrayOutputStream out) {
            out.write(header[0] | 0x02);
            if (header.length > 1) {
                out.write(header[1]);
            }
            writeLeb128(out, payload.remaining());
            var bytes = new byte[payload.remaining()];
            payload.get(payload.position(), bytes);
            out.writeBytes(bytes);
        }
    }

    /// Parses one OBU from `[offset, end)`, using its size field when present and the whole range otherwise.
    ///
    /// @param sizeRequired whether the OBU must carry a size field
    /// @return the OBU, whose payload ends where the size field says
    /// @throws PayloadFormatException if the header is malformed or the size overruns the range
    static Obu parse(ByteBuffer buffer, int offset, int end, boolean sizeRequired) throws PayloadFormatException {
        if (offset >= end) {
            throw new PayloadFormatException("empty OBU");
        }
        var first = buffer.get(offset) & 0xFF;
        if ((first & 0x80) != 0) {
            throw new PayloadFormatException("OBU forbidden bit set");
        }
        var type = (first >>> 3) & 0x0F;
        var extension = (first & 0x04) != 0;
        var hasSize = (first & 0x02) != 0;
        var position = offset + 1;
        var temporalId = 0;
        var spatialId = 0;
        byte[] header;
        if (extension) {
            if (position >= end) {
                throw new PayloadFormatException("truncated OBU extension header");
            }
            var ext = buffer.get(position++) & 0xFF;
            temporalId = ext >>> 5;
            spatialId = (ext >>> 3) & 0x03;
            header = new byte[]{(byte) (first & ~0x02), (byte) ext};
        } else {
            header = new byte[]{(byte) (first & ~0x02)};
        }
        int payloadEnd;
        if (hasSize) {
            var size = readLeb128(buffer, position, end);
            position += leb128Size(size);
            if (size > end - position) {
                throw new PayloadFormatException("OBU size overruns its buffer");
            }
            payloadEnd = position + (int) size;
        } else if (sizeRequired) {
            throw new PayloadFormatException("OBU without size field in low-overhead format");
        } else {
            payloadEnd = end;
        }
        return new Obu(type, extension, temporalId, spatialId, header, buffer.slice(position, payloadEnd - position));
    }

    /// Splits a temporal unit in low-overhead bitstream format into its OBUs; the last one may omit its size field.
    ///
    /// @throws IllegalArgumentException if an OBU does not parse
    static List<Obu> parseTemporalUnit(ByteBuffer unit) {
        var result = new ArrayList<Obu>();
        var offset = unit.position();
        try {
            while (offset < unit.limit()) {
                var first = unit.get(offset) & 0xFF;
                var obu = parse(unit, offset, unit.limit(), false);
                result.add(obu);
                var headerLength = obu.header().length;
                var sizeLength = (first & 0x02) != 0 ? leb128Size(obu.payload().remaining()) : 0;
                offset += headerLength + sizeLength + obu.payload().remaining();
            }
        } catch (PayloadFormatException exception) {
            throw new IllegalArgumentException("malformed AV1 temporal unit: " + exception.getMessage(), exception);
        }
        return result;
    }

    /// {@return the `leb128` value at `offset`}
    ///
    /// @throws PayloadFormatException if it is truncated, longer than eight bytes or above 2^32 - 1
    static long readLeb128(ByteBuffer buffer, int offset, int end) throws PayloadFormatException {
        var value = 0L;
        for (var i = 0; i < 8; i++) {
            if (offset + i >= end) {
                throw new PayloadFormatException("truncated leb128");
            }
            var b = buffer.get(offset + i) & 0xFF;
            value |= (long) (b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) {
                if (value > 0xFFFFFFFFL) {
                    throw new PayloadFormatException("leb128 value too large");
                }
                if (leb128Size(value) != i + 1) {
                    throw new PayloadFormatException("non-minimal leb128 encoding");
                }
                return value;
            }
        }
        throw new PayloadFormatException("leb128 longer than eight bytes");
    }

    /// {@return the encoded size of a `leb128` value in its minimal form}
    static int leb128Size(long value) {
        var size = 1;
        while (value >= 0x80) {
            value >>>= 7;
            size++;
        }
        return size;
    }

    /// Writes a `leb128` value in its minimal form.
    static void writeLeb128(ByteArrayOutputStream out, long value) {
        while (value >= 0x80) {
            out.write((int) (value & 0x7F) | 0x80);
            value >>>= 7;
        }
        out.write((int) value);
    }

    /// Writes a `leb128` value in its minimal form.
    static void writeLeb128(ByteBuffer out, long value) {
        while (value >= 0x80) {
            out.put((byte) ((value & 0x7F) | 0x80));
            value >>>= 7;
        }
        out.put((byte) value);
    }

    /// The fields of a sequence header the payload format reads.
    ///
    /// @param reducedStillPictureHeader whether frame headers omit `show_existing_frame` and `frame_type`
    /// @param maxResolution             the maximum frame size
    record SequenceInfo(boolean reducedStillPictureHeader, Optional<Resolution> maxResolution) {
    }

    /// Reads a sequence header OBU payload.
    ///
    /// @return the fields, or empty when the payload does not parse
    static Optional<SequenceInfo> parseSequenceHeader(ByteBuffer payload) {
        try {
            var bytes = new byte[payload.remaining()];
            payload.get(payload.position(), bytes);
            var reader = new BitReader(bytes, 0, bytes.length);
            reader.skip(3);
            reader.skip(1);
            var reduced = reader.flag();
            if (reduced) {
                reader.skip(5);
            } else {
                var decoderModelInfoPresent = false;
                var bufferDelayLength = 0;
                if (reader.flag()) {
                    reader.skip(64);
                    if (reader.flag()) {
                        reader.uvlc();
                    }
                    decoderModelInfoPresent = reader.flag();
                    if (decoderModelInfoPresent) {
                        bufferDelayLength = reader.bitsInt(5) + 1;
                        reader.skip(32);
                        reader.skip(10);
                    }
                }
                var initialDisplayDelayPresent = reader.flag();
                var operatingPoints = reader.bitsInt(5) + 1;
                for (var i = 0; i < operatingPoints; i++) {
                    reader.skip(12);
                    var level = reader.bitsInt(5);
                    if (level > 7) {
                        reader.skip(1);
                    }
                    if (decoderModelInfoPresent && reader.flag()) {
                        reader.skip(2L * bufferDelayLength + 1);
                    }
                    if (initialDisplayDelayPresent && reader.flag()) {
                        reader.skip(4);
                    }
                }
            }
            var widthBits = reader.bitsInt(4) + 1;
            var heightBits = reader.bitsInt(4) + 1;
            var width = reader.bits(widthBits) + 1;
            var height = reader.bits(heightBits) + 1;
            return Optional.of(new SequenceInfo(reduced, NalUnits.resolution(width, height)));
        } catch (IndexOutOfBoundsException exception) {
            return Optional.empty();
        }
    }

    /// {@return whether a frame or frame header OBU payload starts a shown key frame; `false` when it cannot tell}
    ///
    /// @param reducedStillPictureHeader the flag of the stream's sequence header
    static boolean isKeyFrame(ByteBuffer payload, boolean reducedStillPictureHeader) {
        if (reducedStillPictureHeader) {
            return true;
        }
        if (!payload.hasRemaining()) {
            return false;
        }
        var first = payload.get(payload.position()) & 0xFF;
        return (first & 0x80) == 0 && (first & 0x60) == 0;
    }
}
