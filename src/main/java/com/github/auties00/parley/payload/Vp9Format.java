package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.OptionalInt;

/// The VP9 payload format of RFC 9628, in flexible and non-flexible mode.
///
/// A frame is one layer frame (one spatial layer of a picture; a single-layer stream has one per picture), in and
/// out. The packetizer writes the payload descriptor from the frame's
/// [Vp9FrameMetadata][com.github.auties00.parley.media.Vp9FrameMetadata]; the depacketizer reads it back, with the
/// scalability structure and the keyframe size.
///
/// @param codec the codec, `video/VP9`
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
public record Vp9Format(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not `video/VP9`
    public Vp9Format {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.mimeType().equalsIgnoreCase("video/VP9")) {
            throw new IllegalArgumentException("not video/VP9: " + codec);
        }
    }

    /// {@return the `profile-id`, `0` when absent or malformed}
    public int profileId() {
        try {
            return Integer.parseInt(codec.formatParameter("profile-id").orElse("0").strip());
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        return new Vp9Packetizer(Objects.requireNonNull(config, "config cannot be null"));
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        return VideoDepacketizer.withDescriptor(new Vp9Depacketizer(),
                Objects.requireNonNull(config, "config cannot be null"));
    }

    /// {@return whether the payload begins a layer frame that is neither inter-picture nor inter-layer predicted in
    /// the base spatial layer: the start of a keyframe picture}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        try {
            var descriptor = Vp9Descriptor.parse(payload);
            return descriptor.begin() && !descriptor.interPicturePredicted() && descriptor.spatialId() == 0;
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
