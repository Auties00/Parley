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
/// order numbers; PACI packets are neither sent nor accepted.
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
    /// @throws IllegalArgumentException if `sprop-max-don-diff` is above zero: decoding order numbers are not supported
    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        checkNoDecodingOrderNumbers();
        return new H265Packetizer(config, spropParameterSets());
    }

    /// {@inheritDoc}
    ///
    /// @throws IllegalArgumentException if `sprop-max-don-diff` is above zero: decoding order numbers are not supported
    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        checkNoDecodingOrderNumbers();
        return VideoDepacketizer.withDescriptor(new H265Depacketizer(spropParameterSets()), config);
    }

    /// {@return whether the payload carries an IRAP slice (NAL unit types `16..23`): a single NAL unit, any unit of an
    /// aggregation packet, or any fragment of a fragmentation unit}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        if (payload.remaining() < 2) {
            return false;
        }
        var start = payload.position();
        var type = (payload.get(start) >>> 1) & 0x3F;
        if (type == H265Packetizer.FU) {
            return payload.remaining() >= 3 && isIrap(payload.get(start + 2) & 0x3F);
        }
        if (type == H265Packetizer.AP) {
            var offset = start + 2;
            while (offset + 2 < payload.limit()) {
                var size = payload.getShort(offset) & 0xFFFF;
                if (size < 2 || offset + 2 + size > payload.limit()) {
                    return false;
                }
                if (isIrap((payload.get(offset + 2) >>> 1) & 0x3F)) {
                    return true;
                }
                offset += 2 + size;
            }
            return false;
        }
        return isIrap(type);
    }

    /// {@return an empty optional: video payloads span no timestamp range}
    ///
    /// @param payload the payload
    @Override
    public OptionalInt timestampDuration(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return OptionalInt.empty();
    }

    /// {@return whether a type is an IRAP picture's slice}
    private static boolean isIrap(int type) {
        return type >= 16 && type <= 23;
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
