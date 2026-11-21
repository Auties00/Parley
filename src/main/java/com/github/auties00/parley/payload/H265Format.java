package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;

/// The H.265 (HEVC) payload format of RFC 7798.
///
/// A frame is one access unit in Annex B byte-stream format, in and out. The packetizer sends single NAL unit
/// packets, aggregation packets (AP) for small NAL units and fragmentation units (FU) for large ones, never decoding
/// order numbers or PACI packets. The depacketizer accepts all four packet types, and decoding order numbers when
/// `sprop-max-don-diff` is above zero, reordering the NAL units of each access unit by them.
///
/// The parameter sets of `sprop-vps`, `sprop-sps` and `sprop-pps` seed both directions, as `sprop-parameter-sets`
/// does for [H264Format].
///
/// @param codec the codec, `video/H265`
/// @spec https://www.rfc-editor.org/rfc/rfc7798.html RFC 7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
public record H265Format(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not `video/H265`
    public H265Format {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.mimeType().equalsIgnoreCase("video/H265")) {
            throw new IllegalArgumentException("not video/H265: " + codec);
        }
    }

    /// {@return the `profile-id`, `1` (Main) when absent or malformed}
    public int profileId() {
        return number("profile-id", 1);
    }

    /// {@return the `tier-flag`, `0` (Main tier) when absent or malformed}
    public int tierFlag() {
        return number("tier-flag", 0);
    }

    /// {@return the `level-id`, `93` (level 3.1) when absent or malformed}
    public int levelId() {
        return number("level-id", 93);
    }

    /// {@return the NAL units of `sprop-vps`, `sprop-sps` and `sprop-pps`, in that order, each read-only}
    public List<ByteBuffer> spropParameterSets() {
        var result = new ArrayList<ByteBuffer>();
        for (var name : List.of("sprop-vps", "sprop-sps", "sprop-pps")) {
            codec.formatParameter(name).map(NalUnits::decodeParameterSets).ifPresent(result::addAll);
        }
        return List.copyOf(result);
    }

    /// {@inheritDoc}
    ///
    /// @throws IllegalArgumentException if `sprop-max-don-diff` is above zero: the packetizer does not write decoding
    ///                                  order numbers
    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        checkNoDecodingOrderNumbers();
        return new H265Packetizer(config, spropParameterSets());
    }

    /// {@inheritDoc}
    ///
    /// The depacketizer reads decoding order numbers when `sprop-max-don-diff` is above zero.
    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        // TODO: de-interleave NAL units of different access units (sprop-depack-buf-nalus above zero); decoding order
        //  numbers are honoured within an access unit only, which is all a non-interleaved sender produces.
        return VideoDepacketizer.withDescriptor(new H265Depacketizer(spropParameterSets(),
                number("sprop-max-don-diff", 0) > 0), config);
    }

    /// {@return whether the payload carries an IRAP slice or a sequence parameter set (NAL unit types `16..23` and
    /// `33`), the units a keyframe starts with: as a single NAL unit, any unit of an aggregation packet, any fragment
    /// of a fragmentation unit, or the packet a PACI packet wraps; a malformed payload is not a keyframe}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        List<NalDepacketizer.Unit> units;
        try {
            units = new H265Depacketizer(List.of(), number("sprop-max-don-diff", 0) > 0).units(payload);
        } catch (PayloadFormatException exception) {
            return false;
        }
        for (var unit : units) {
            var header = switch (unit) {
                case NalDepacketizer.Unit.Whole whole -> whole.nal().getShort(whole.nal().position()) & 0xFFFF;
                case NalDepacketizer.Unit.Fragment fragment ->
                        (fragment.header()[0] & 0xFF) << 8 | fragment.header()[1] & 0xFF;
            };
            if (isIrap((header >>> 9) & 0x3F)) {
                return true;
            }
        }
        return false;
    }

    /// {@return an empty optional: video payloads span no timestamp range}
    ///
    /// @param payload the payload
    @Override
    public OptionalInt timestampDuration(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return OptionalInt.empty();
    }

    /// {@return whether a type is an IRAP picture's slice or a sequence parameter set}
    private static boolean isIrap(int type) {
        return type >= 16 && type <= 23 || type == 33;
    }

    /// {@return a numeric format parameter, or a default}
    private int number(String name, int fallback) {
        try {
            return Integer.parseInt(codec.formatParameter(name).orElse(Integer.toString(fallback)).strip());
        } catch (NumberFormatException exception) {
            return fallback;
        }
    }

    /// Rejects a stream with decoding order numbers.
    private void checkNoDecodingOrderNumbers() {
        if (number("sprop-max-don-diff", 0) > 0) {
            throw new IllegalArgumentException("H.265 decoding order numbers (sprop-max-don-diff) are not supported");
        }
    }
}
