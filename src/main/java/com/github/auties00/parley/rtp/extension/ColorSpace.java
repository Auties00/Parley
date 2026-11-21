package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;

/// The color space of a video frame and, for HDR content, its mastering display and light level metadata.
///
/// The first four fields use the code points of ITU-T H.273 (the values of the AV1 and VP9 bitstreams). The value is
/// 4 bytes, or 28 with HDR metadata.
///
/// @param primaries              the color primaries, H.273 `ColourPrimaries`, `0..255`
/// @param transfer               the transfer characteristics, H.273 `TransferCharacteristics`, `0..255`
/// @param matrix                 the matrix coefficients, H.273 `MatrixCoefficients`, `0..255`
/// @param range                  the range: `0` invalid, `1` limited, `2` full, `3` derived; `0..3`
/// @param chromaSitingHorizontal the horizontal chroma siting: `0` unspecified, `1` collocated with luma, `2` half
///                               way; `0..3`
/// @param chromaSitingVertical   the vertical chroma siting, with the values of the horizontal one; `0..3`
/// @param hdrMetadata            the HDR metadata, when present
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/color-space/README.md WebRTC: Color Space
/// @spec https://www.itu.int/rec/T-REC-H.273 ITU-T H.273: Coding-independent code points for video signal type identification
public record ColorSpace(int primaries, int transfer, int matrix, int range, int chromaSitingHorizontal,
                         int chromaSitingVertical, Optional<HdrMetadata> hdrMetadata) implements HeaderExtension {
    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if a field is out of range
    public ColorSpace {
        if (primaries < 0 || primaries > 255 || transfer < 0 || transfer > 255 || matrix < 0 || matrix > 255) {
            throw new IllegalArgumentException("primaries, transfer and matrix must be in 0..255");
        }
        if (range < 0 || range > 3 || chromaSitingHorizontal < 0 || chromaSitingHorizontal > 3
                || chromaSitingVertical < 0 || chromaSitingVertical > 3) {
            throw new IllegalArgumentException("range and chroma siting must be in 0..3");
        }
        Objects.requireNonNull(hdrMetadata, "hdrMetadata cannot be null");
    }

    /// HDR mastering display and content light level metadata.
    ///
    /// Chromaticity coordinates are in units of `0.00002`, as in SMPTE ST 2086 and HEVC SEI messages.
    ///
    /// @param redX                      the red primary x chromaticity, `0..65535`
    /// @param redY                      the red primary y chromaticity, `0..65535`
    /// @param greenX                    the green primary x chromaticity, `0..65535`
    /// @param greenY                    the green primary y chromaticity, `0..65535`
    /// @param blueX                     the blue primary x chromaticity, `0..65535`
    /// @param blueY                     the blue primary y chromaticity, `0..65535`
    /// @param whitePointX               the white point x chromaticity, `0..65535`
    /// @param whitePointY               the white point y chromaticity, `0..65535`
    /// @param maximumLuminance          the maximum mastering luminance in candelas per square meter, `0..65535`
    /// @param minimumLuminance          the minimum mastering luminance in units of `0.0001` candela per square meter,
    ///                                  `0..65535`
    /// @param maximumContentLightLevel  the maximum content light level in candelas per square meter, `0..65535`
    /// @param maximumFrameAverageLightLevel the maximum frame-average light level in candelas per square meter,
    ///                                  `0..65535`
    public record HdrMetadata(int redX, int redY, int greenX, int greenY, int blueX, int blueY, int whitePointX,
                              int whitePointY, int maximumLuminance, int minimumLuminance,
                              int maximumContentLightLevel, int maximumFrameAverageLightLevel) {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field does not fit 16 unsigned bits
        public HdrMetadata {
            for (var v : new int[]{redX, redY, greenX, greenY, blueX, blueY, whitePointX, whitePointY,
                    maximumLuminance, minimumLuminance, maximumContentLightLevel, maximumFrameAverageLightLevel}) {
                if (v < 0 || v > 0xFFFF) {
                    throw new IllegalArgumentException("HDR metadata values must be in 0..65535: " + v);
                }
            }
        }
    }

    /// Parses an element value of 4 bytes, or 28 with HDR metadata.
    ///
    /// @param value the element value; the position is advanced past the bytes read
    /// @return the color space
    /// @throws RtpFormatException if the value is shorter than 4 bytes, or longer but shorter than 28
    public static ColorSpace parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, 4, "color-space");
        var primaries = value.get() & 0xFF;
        var transfer = value.get() & 0xFF;
        var matrix = value.get() & 0xFF;
        var packed = value.get() & 0xFF;
        var hdr = Optional.<HdrMetadata>empty();
        if (value.hasRemaining()) {
            ExtensionCodec.require(value, 24, "color-space HDR metadata");
            var v = new int[12];
            for (var i = 0; i < v.length; i++) {
                v[i] = value.getShort() & 0xFFFF;
            }
            hdr = Optional.of(new HdrMetadata(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10],
                    v[11]));
        }
        return new ColorSpace(primaries, transfer, matrix, (packed >>> 4) & 0x3, (packed >>> 2) & 0x3, packed & 0x3,
                hdr);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.COLOR_SPACE;
    }

    @Override
    public int encodedLength() {
        return hdrMetadata.isPresent() ? 28 : 4;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, encodedLength());
        destination.put((byte) primaries).put((byte) transfer).put((byte) matrix);
        destination.put((byte) (range << 4 | chromaSitingHorizontal << 2 | chromaSitingVertical));
        if (hdrMetadata.isPresent()) {
            var h = hdrMetadata.get();
            for (var v : new int[]{h.redX(), h.redY(), h.greenX(), h.greenY(), h.blueX(), h.blueY(),
                    h.whitePointX(), h.whitePointY(), h.maximumLuminance(), h.minimumLuminance(),
                    h.maximumContentLightLevel(), h.maximumFrameAverageLightLevel()}) {
                destination.putShort((short) v);
            }
        }
    }
}
