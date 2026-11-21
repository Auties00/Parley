package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.H264ProfileLevelId;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/// The H.264 payload format of RFC 6184.
///
/// A frame is one access unit in Annex B byte-stream format (each NAL unit after a `00 00 01` or `00 00 00 01` start
/// code), in and out. In packetization mode `1` (non-interleaved, what browsers use) the packetizer aggregates small
/// NAL units into STAP-A packets and fragments large ones into FU-A packets; in mode `0` every NAL unit must fit one
/// packet. Mode `2` (interleaved) is not supported.
///
/// The parameter sets of `sprop-parameter-sets` seed both directions: the packetizer inserts them before an IDR
/// picture sent without them, and the depacketizer before one received without them.
///
/// @param codec the codec, `video/H264`
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
public record H264Format(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not `video/H264`
    public H264Format {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.mimeType().equalsIgnoreCase("video/H264")) {
            throw new IllegalArgumentException("not video/H264: " + codec);
        }
    }

    /// {@return the `packetization-mode`, `0` when absent or malformed}
    public int packetizationMode() {
        try {
            return Integer.parseInt(codec.formatParameter("packetization-mode").orElse("0").strip());
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    /// {@return the profile and level of `profile-level-id`, or an empty optional when it is malformed}
    public Optional<H264ProfileLevelId> profileLevelId() {
        return H264ProfileLevelId.of(codec.formatParameters());
    }

    /// {@return the NAL units of `sprop-parameter-sets`, each read-only; malformed entries are skipped}
    public List<ByteBuffer> spropParameterSets() {
        return codec.formatParameter("sprop-parameter-sets").map(NalUnits::decodeParameterSets).orElse(List.of());
    }

    /// {@inheritDoc}
    ///
    /// @throws IllegalArgumentException if the packetization mode is `2`, which this format does not support
    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        var mode = packetizationMode();
        if (mode != 0 && mode != 1) {
            throw new IllegalArgumentException("unsupported H.264 packetization mode " + mode);
        }
        return new H264Packetizer(config, mode == 1, spropParameterSets());
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        return VideoDepacketizer.withDescriptor(new H264Depacketizer(spropParameterSets()), config);
    }

    /// {@return whether the payload carries an IDR slice or a sequence parameter set (NAL unit types 5 and 7), the
    /// units a keyframe starts with: as a single NAL unit, any unit of a STAP-A, or any fragment of an FU-A}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        if (!payload.hasRemaining()) {
            return false;
        }
        var start = payload.position();
        var type = payload.get(start) & 0x1F;
        if (type == 5 || type == 7) {
            return true;
        }
        if (type == H264Packetizer.FU_A) {
            return payload.remaining() >= 2 && ((payload.get(start + 1) & 0x1F) == 5
                    || (payload.get(start + 1) & 0x1F) == 7);
        }
        if (type == H264Packetizer.STAP_A) {
            var offset = start + 1;
            while (offset + 2 < payload.limit()) {
                var size = payload.getShort(offset) & 0xFFFF;
                if (size == 0 || offset + 2 + size > payload.limit()) {
                    return false;
                }
                var unit = payload.get(offset + 2) & 0x1F;
                if (unit == 5 || unit == 7) {
                    return true;
                }
                offset += 2 + size;
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
}
