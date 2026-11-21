package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.OptionalInt;

/// The comfort noise payload format of RFC 3389, `audio/CN`: one [ComfortNoise] description per payload, sent during
/// silence by a codec without its own discontinuous transmission (G.711, G.722) at that codec's clock rate.
///
/// A comfort noise payload carries no duration: the noise lasts until the next payload of the stream.
///
/// @param codec the comfort noise codec, `audio/CN`
/// @spec https://www.rfc-editor.org/rfc/rfc3389.html RFC 3389: Real-time Transport Protocol (RTP) Payload for Comfort Noise (CN)
public record ComfortNoiseFormat(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not `audio/CN`
    public ComfortNoiseFormat {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.mimeType().equalsIgnoreCase("audio/CN")) {
            throw new IllegalArgumentException("not audio/CN: " + codec);
        }
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        return new AudioPacketizer(this, Objects.requireNonNull(config, "config cannot be null"));
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        return new AudioDepacketizer(payload -> payload.hasRemaining()
                && (payload.get(payload.position()) & 0x80) == 0,
                Objects.requireNonNull(config, "config cannot be null"));
    }

    /// {@return `true`: a comfort noise payload stands alone}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return true;
    }

    /// {@return an empty optional: comfort noise lasts until the next payload}
    ///
    /// @param payload the payload
    @Override
    public OptionalInt timestampDuration(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return OptionalInt.empty();
    }
}
