package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;

import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalInt;

/// The payload format of the audio codecs that put one frame, or a run of samples, in each RTP payload with no
/// payload header: G.711 (`PCMU`, `PCMA`), G.722, linear PCM, GSM, G.729, iLBC and any audio codec Parley has no
/// dedicated format for.
///
/// [#timestampDuration(ByteBuffer)] knows the sample-based and frame-based codecs of RFC 3551; for any other codec
/// it returns an empty optional.
///
/// @param codec the audio codec
/// @spec https://www.rfc-editor.org/rfc/rfc3551.html RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
/// @spec https://www.rfc-editor.org/rfc/rfc3952.html RFC 3952: Real-time Transport Protocol (RTP) Payload Format for internet Low Bit Rate Codec (iLBC) Speech
public record AudioFormat(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not audio
    public AudioFormat {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (codec.kind() != MediaKind.AUDIO) {
            throw new IllegalArgumentException("not an audio codec: " + codec);
        }
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        return new AudioPacketizer(this, Objects.requireNonNull(config, "config cannot be null"));
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        return new AudioDepacketizer(ByteBuffer::hasRemaining, Objects.requireNonNull(config, "config cannot be null"));
    }

    /// {@return `true`: every frame of these codecs decodes on its own}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return true;
    }

    /// {@return the samples per channel in the payload, in clock units}
    ///
    /// | Codec | Duration |
    /// |---|---|
    /// | `PCMU`, `PCMA`, `L8` | one byte per sample per channel |
    /// | `G722` | one byte per clock tick per channel (two 16 kHz samples per tick of its 8 kHz RTP clock) |
    /// | `L16` | two bytes per sample per channel |
    /// | `GSM` | 160 per 33-byte frame |
    /// | `G729` | 80 per 10-byte frame, plus nothing for a 2-byte comfort noise frame |
    /// | `iLBC` | 160 per 38-byte frame, 240 per 50-byte frame |
    ///
    /// @param payload the payload
    @Override
    public OptionalInt timestampDuration(ByteBuffer payload) {
        var length = payload.remaining();
        var channels = codec.channelCount();
        return switch (codec.name().toUpperCase(Locale.ROOT)) {
            case "PCMU", "PCMA", "G722", "L8" -> length % channels == 0 ? OptionalInt.of(length / channels)
                    : OptionalInt.empty();
            case "L16" -> length % (2 * channels) == 0 ? OptionalInt.of(length / (2 * channels)) : OptionalInt.empty();
            case "GSM" -> length % 33 == 0 ? OptionalInt.of(length / 33 * 160) : OptionalInt.empty();
            case "G729" -> length % 10 == 0 || length % 10 == 2 ? OptionalInt.of(length / 10 * 80)
                    : OptionalInt.empty();
            case "ILBC" -> length % 38 == 0 ? OptionalInt.of(length / 38 * 160)
                    : length % 50 == 0 ? OptionalInt.of(length / 50 * 240) : OptionalInt.empty();
            default -> OptionalInt.empty();
        };
    }
}
