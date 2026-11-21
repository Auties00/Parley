package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.OptionalInt;

/// The VP8 payload format of RFC 7741.
///
/// A frame is one VP8 frame, in and out. The packetizer writes the payload descriptor from the frame's
/// [Vp8FrameMetadata][com.github.auties00.parley.media.Vp8FrameMetadata] (always with a 15-bit picture id); the
/// depacketizer reads it back, with the keyframe size.
///
/// @param codec the codec, `video/VP8`
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html RFC 7741: RTP Payload Format for VP8 Video
public record Vp8Format(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not `video/VP8`
    public Vp8Format {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.mimeType().equalsIgnoreCase("video/VP8")) {
            throw new IllegalArgumentException("not video/VP8: " + codec);
        }
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        return new Vp8Packetizer(Objects.requireNonNull(config, "config cannot be null"));
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        return VideoDepacketizer.withDescriptor(new Vp8Depacketizer(),
                Objects.requireNonNull(config, "config cannot be null"));
    }

    /// {@return whether the payload starts a VP8 keyframe: the `S` bit in partition `0`, and a clear inverse key frame
    /// bit in the first byte after the descriptor}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        try {
            var descriptor = Vp8Descriptor.parse(payload);
            return descriptor.startOfPartition() && descriptor.partitionIndex() == 0
                    && (payload.get(payload.position() + descriptor.size()) & 0x01) == 0;
        } catch (PayloadFormatException exception) {
            return false;
        }
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
