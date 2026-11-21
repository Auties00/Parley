package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.OptionalInt;

/// The AV1 payload format of the AOMedia AV1 RTP specification.
///
/// A frame is a temporal unit in low-overhead bitstream format (every OBU with its size field), in and out; with a
/// negotiated dependency descriptor (see [DepacketizerConfig]) the depacketizer delivers the frame of each layer
/// separately, with its frame id and dependencies. The packetizer removes temporal delimiters and OBU sizes as the
/// specification asks, and writes the dependency descriptor when [PacketizerConfig#dependencyDescriptor()] says the
/// session negotiated it; the depacketizer restores the sizes and the temporal delimiter at the start of each
/// temporal unit.
///
/// @param codec the codec, `video/AV1`
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
public record Av1Format(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not `video/AV1`
    public Av1Format {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.mimeType().equalsIgnoreCase("video/AV1")) {
            throw new IllegalArgumentException("not video/AV1: " + codec);
        }
    }

    /// {@return the `profile`, `0` (Main) when absent or malformed}
    public int profile() {
        try {
            return Integer.parseInt(codec.formatParameter("profile").orElse("0").strip());
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        return new Av1Packetizer(Objects.requireNonNull(config, "config cannot be null"));
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        return VideoDepacketizer.withDescriptor(new Av1Depacketizer(),
                Objects.requireNonNull(config, "config cannot be null"));
    }

    /// {@return whether the payload starts a new coded video sequence (`N`) or begins with a sequence header OBU}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        if (payload.remaining() < 2) {
            return false;
        }
        var start = payload.position();
        var header = payload.get(start) & 0xFF;
        if ((header & 0x08) != 0) {
            return true;
        }
        if ((header & 0x80) != 0) {
            return false;
        }
        var count = (header >>> 4) & 0x03;
        var offset = start + 1;
        if (count != 1) {
            try {
                offset += Obus.leb128Size(Obus.readLeb128(payload, offset, payload.limit()));
            } catch (PayloadFormatException exception) {
                return false;
            }
        }
        return offset < payload.limit() && ((payload.get(offset) >>> 3) & 0x0F) == Obus.SEQUENCE_HEADER;
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
