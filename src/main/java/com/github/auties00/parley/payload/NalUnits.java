package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Resolution;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/// The NAL unit plumbing H.264 and H.265 share: Annex B byte streams, emulation prevention, parameter sets.
///
/// @spec https://www.itu.int/rec/T-REC-H.264 ITU-T H.264: Advanced video coding for generic audiovisual services
/// @spec https://www.itu.int/rec/T-REC-H.265 ITU-T H.265: High efficiency video coding
final class NalUnits {
    /// The four-byte start code the depacketizers write before each NAL unit.
    static final byte[] START_CODE = {0, 0, 0, 1};

    private NalUnits() {
        throw new AssertionError("NalUnits cannot be instantiated");
    }

    /// Splits an Annex B byte stream into its NAL units.
    ///
    /// Each NAL unit is a slice of `stream` without its start code, its leading `zero_byte` or its trailing zero
    /// bytes.
    ///
    /// @throws IllegalArgumentException if the stream does not begin with a start code, or a NAL unit is empty
    static List<ByteBuffer> splitAnnexB(ByteBuffer stream) {
        var start = stream.position();
        var limit = stream.limit();
        var first = nextStartCode(stream, start, limit);
        var leading = first < 0 ? limit : first;
        for (var i = start; i < leading; i++) {
            if (stream.get(i) != 0) {
                throw new IllegalArgumentException("frame is not an Annex B byte stream: no leading start code");
            }
        }
        if (first < 0) {
            throw new IllegalArgumentException("frame is not an Annex B byte stream: no start code");
        }
        var result = new ArrayList<ByteBuffer>();
        var nalStart = first + 3;
        while (nalStart < limit) {
            var next = nextStartCode(stream, nalStart, limit);
            var nalEnd = next < 0 ? limit : next;
            while (nalEnd > nalStart && stream.get(nalEnd - 1) == 0) {
                nalEnd--;
            }
            if (nalEnd == nalStart) {
                throw new IllegalArgumentException("empty NAL unit in Annex B byte stream");
            }
            result.add(stream.slice(nalStart, nalEnd - nalStart));
            if (next < 0) {
                break;
            }
            nalStart = next + 3;
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("Annex B byte stream without NAL units");
        }
        return result;
    }

    /// {@return the absolute index of the next `00 00 01` at or after `from`, or `-1`}
    private static int nextStartCode(ByteBuffer stream, int from, int limit) {
        for (var i = from; i + 2 < limit; i++) {
            if ((stream.get(i + 2) & 0xFF) > 1) {
                i += 2;
                continue;
            }
            if (stream.get(i) == 0 && stream.get(i + 1) == 0 && stream.get(i + 2) == 1) {
                return i;
            }
        }
        return -1;
    }

    /// Removes the emulation prevention bytes (the `03` of `00 00 03`) from the first `maxLength` bytes of a NAL unit.
    ///
    /// @return the raw byte sequence payload, header included
    static byte[] unescape(ByteBuffer nal, int maxLength) {
        var length = Math.min(nal.remaining(), maxLength);
        var out = new byte[length];
        var count = 0;
        var zeros = 0;
        for (var i = 0; i < length; i++) {
            var b = nal.get(nal.position() + i);
            if (zeros >= 2 && b == 3) {
                zeros = 0;
                continue;
            }
            out[count++] = b;
            zeros = b == 0 ? zeros + 1 : 0;
        }
        return count == length ? out : Arrays.copyOf(out, count);
    }

    /// Appends a NAL unit with a four-byte start code.
    static void appendAnnexB(ByteArrayOutputStream out, ByteBuffer nal) {
        out.writeBytes(START_CODE);
        var bytes = new byte[nal.remaining()];
        nal.get(nal.position(), bytes);
        out.writeBytes(bytes);
    }

    /// {@return a copy of a NAL unit as its own buffer}
    static ByteBuffer copy(ByteBuffer nal) {
        return Payloads.copy(nal).asReadOnlyBuffer();
    }

    /// Decodes a comma-separated list of base64 NAL units, the form of `sprop-parameter-sets` and `sprop-sps`.
    ///
    /// @return the NAL units; malformed entries are skipped
    static List<ByteBuffer> decodeParameterSets(String value) {
        var result = new ArrayList<ByteBuffer>();
        for (var part : value.split(",")) {
            var trimmed = part.strip();
            if (trimmed.isEmpty()) {
                continue;
            }
            try {
                var bytes = Base64.getDecoder().decode(trimmed);
                if (bytes.length > 0) {
                    result.add(ByteBuffer.wrap(bytes).asReadOnlyBuffer());
                }
            } catch (IllegalArgumentException ignored) {
                // A malformed entry describes nothing usable; the in-band parameter sets still apply.
            }
        }
        return List.copyOf(result);
    }

    /// Reads the picture size of an H.264 sequence parameter set.
    ///
    /// @param sps the NAL unit, header included
    /// @return the cropped size, or an empty optional when the unit does not parse
    static Optional<Resolution> h264Resolution(ByteBuffer sps) {
        try {
            var rbsp = unescape(sps, 512);
            var reader = new BitReader(rbsp, 1, rbsp.length - 1);
            var profileIdc = reader.bitsInt(8);
            reader.skip(16);
            reader.ue();
            var chromaFormatIdc = 1L;
            var separateColourPlane = false;
            if (profileIdc == 100 || profileIdc == 110 || profileIdc == 122 || profileIdc == 244 || profileIdc == 44
                    || profileIdc == 83 || profileIdc == 86 || profileIdc == 118 || profileIdc == 128
                    || profileIdc == 138 || profileIdc == 139 || profileIdc == 134 || profileIdc == 135) {
                chromaFormatIdc = reader.ue();
                if (chromaFormatIdc == 3) {
                    separateColourPlane = reader.flag();
                }
                reader.ue();
                reader.ue();
                reader.skip(1);
                if (reader.flag()) {
                    var lists = chromaFormatIdc != 3 ? 8 : 12;
                    for (var i = 0; i < lists; i++) {
                        if (reader.flag()) {
                            skipScalingList(reader, i < 6 ? 16 : 64);
                        }
                    }
                }
            }
            reader.ue();
            var picOrderCntType = reader.ue();
            if (picOrderCntType == 0) {
                reader.ue();
            } else if (picOrderCntType == 1) {
                reader.skip(1);
                reader.se();
                reader.se();
                var cycle = reader.ue();
                for (var i = 0L; i < cycle; i++) {
                    reader.se();
                }
            }
            reader.ue();
            reader.skip(1);
            var widthInMbs = reader.ue() + 1;
            var heightInMapUnits = reader.ue() + 1;
            var frameMbsOnly = reader.flag();
            if (!frameMbsOnly) {
                reader.skip(1);
            }
            reader.skip(1);
            long cropLeft = 0;
            long cropRight = 0;
            long cropTop = 0;
            long cropBottom = 0;
            if (reader.flag()) {
                cropLeft = reader.ue();
                cropRight = reader.ue();
                cropTop = reader.ue();
                cropBottom = reader.ue();
            }
            var chromaArrayType = separateColourPlane ? 0 : chromaFormatIdc;
            long cropUnitX;
            long cropUnitY;
            if (chromaArrayType == 0) {
                cropUnitX = 1;
                cropUnitY = frameMbsOnly ? 1 : 2;
            } else {
                var subWidth = chromaArrayType == 3 ? 1 : 2;
                var subHeight = chromaArrayType == 1 ? 2 : 1;
                cropUnitX = subWidth;
                cropUnitY = subHeight * (frameMbsOnly ? 1 : 2);
            }
            var width = widthInMbs * 16 - cropUnitX * (cropLeft + cropRight);
            var height = (frameMbsOnly ? 1 : 2) * heightInMapUnits * 16 - cropUnitY * (cropTop + cropBottom);
            return resolution(width, height);
        } catch (IndexOutOfBoundsException exception) {
            return Optional.empty();
        }
    }

    /// Skips one H.264 scaling list.
    private static void skipScalingList(BitReader reader, int size) {
        var last = 8L;
        var next = 8L;
        for (var j = 0; j < size; j++) {
            if (next != 0) {
                next = (last + reader.se() + 256) % 256;
            }
            last = next == 0 ? last : next;
        }
    }

    /// Reads the picture size of an H.265 sequence parameter set.
    ///
    /// @param sps the NAL unit, its two-byte header included
    /// @return the size inside the conformance window, or an empty optional when the unit does not parse
    static Optional<Resolution> h265Resolution(ByteBuffer sps) {
        try {
            var rbsp = unescape(sps, 512);
            var reader = new BitReader(rbsp, 2, rbsp.length - 2);
            reader.skip(4);
            var maxSubLayersMinus1 = reader.bitsInt(3);
            reader.skip(1);
            reader.skip(96);
            var profilePresent = new boolean[maxSubLayersMinus1];
            var levelPresent = new boolean[maxSubLayersMinus1];
            for (var i = 0; i < maxSubLayersMinus1; i++) {
                profilePresent[i] = reader.flag();
                levelPresent[i] = reader.flag();
            }
            if (maxSubLayersMinus1 > 0) {
                reader.skip(2L * (8 - maxSubLayersMinus1));
            }
            for (var i = 0; i < maxSubLayersMinus1; i++) {
                if (profilePresent[i]) {
                    reader.skip(88);
                }
                if (levelPresent[i]) {
                    reader.skip(8);
                }
            }
            reader.ue();
            var chromaFormatIdc = reader.ue();
            var separateColourPlane = chromaFormatIdc == 3 && reader.flag();
            var width = reader.ue();
            var height = reader.ue();
            if (reader.flag()) {
                var chromaArrayType = separateColourPlane ? 0 : chromaFormatIdc;
                var subWidth = chromaArrayType == 1 || chromaArrayType == 2 ? 2 : 1;
                var subHeight = chromaArrayType == 1 ? 2 : 1;
                width -= subWidth * (reader.ue() + reader.ue());
                height -= subHeight * (reader.ue() + reader.ue());
            }
            return resolution(width, height);
        } catch (IndexOutOfBoundsException exception) {
            return Optional.empty();
        }
    }

    /// {@return a resolution, or empty when a dimension is not a plausible size}
    static Optional<Resolution> resolution(long width, long height) {
        return width > 0 && height > 0 && width <= 65536 && height <= 65536
                ? Optional.of(new Resolution((int) width, (int) height))
                : Optional.empty();
    }
}
