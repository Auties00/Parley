package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.OptionalInt;

/// The Opus payload format of RFC 7587: one Opus packet per RTP payload, at a 48 kHz RTP clock whatever the audio
/// bandwidth.
///
/// The format reads only the table-of-contents byte of a packet, to tell its duration and validity; it never decodes
/// audio.
///
/// @param codec the Opus codec, `audio/opus` at 48 kHz with two channels
/// @spec https://www.rfc-editor.org/rfc/rfc7587.html RFC 7587: RTP Payload Format for the Opus Speech and Audio Codec
/// @spec https://www.rfc-editor.org/rfc/rfc6716.html RFC 6716: Definition of the Opus Audio Codec
public record OpusFormat(Codec codec) implements PayloadFormat {
    /// The duration of one Opus frame of each configuration of the TOC byte, in 48 kHz samples.
    private static final int[] FRAME_SAMPLES = {
            480, 960, 1920, 2880, 480, 960, 1920, 2880, 480, 960, 1920, 2880,
            480, 960, 480, 960,
            120, 240, 480, 960, 120, 240, 480, 960, 120, 240, 480, 960, 120, 240, 480, 960
    };

    /// The longest Opus packet, 120 ms, in 48 kHz samples.
    private static final int MAX_PACKET_SAMPLES = 5760;

    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not Opus at 48 kHz with two channels, the only form RFC 7587
    ///                                  allows in SDP
    public OpusFormat {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.name().equalsIgnoreCase("opus") || codec.clockRate() != 48000 || codec.channelCount() != 2) {
            throw new IllegalArgumentException("not opus/48000/2: " + codec);
        }
    }

    /// {@return the format of [Codec#opus()]}
    public static OpusFormat defaults() {
        return new OpusFormat(Codec.opus());
    }

    /// {@return the Opus parameters of the codec's format parameters}
    public OpusParameters parameters() {
        return OpusParameters.parse(codec.formatParameters());
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        return new AudioPacketizer(this, Objects.requireNonNull(config, "config cannot be null"));
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        return new AudioDepacketizer(payload -> samples(payload) > 0,
                Objects.requireNonNull(config, "config cannot be null"));
    }

    /// {@return `true`: every Opus packet decodes on its own}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return true;
    }

    /// {@return the duration of the Opus packet from its TOC byte and frame count, in 48 kHz samples, or an empty
    /// optional for a malformed packet}
    ///
    /// @param payload the payload
    @Override
    public OptionalInt timestampDuration(ByteBuffer payload) {
        var samples = samples(payload);
        return samples > 0 ? OptionalInt.of(samples) : OptionalInt.empty();
    }

    /// Tests whether an Opus packet is a discontinuous-transmission packet, which the encoder sends instead of audio
    /// during silence: one or two bytes, a TOC byte and at most one byte of comfort noise.
    ///
    /// @param payload the payload, from position to limit
    /// @return whether the payload is a DTX packet
    public static boolean isDtx(ByteBuffer payload) {
        return payload.hasRemaining() && payload.remaining() <= 2;
    }

    /// {@return the duration of an Opus packet in 48 kHz samples, or `-1` when the TOC is malformed or the packet
    /// exceeds 120 ms}
    static int samples(ByteBuffer payload) {
        if (!payload.hasRemaining()) {
            return -1;
        }
        var toc = payload.get(payload.position()) & 0xFF;
        var frameSamples = FRAME_SAMPLES[toc >>> 3];
        var frames = switch (toc & 0x03) {
            case 0 -> 1;
            case 1, 2 -> 2;
            default -> payload.remaining() < 2 ? -1 : payload.get(payload.position() + 1) & 0x3F;
        };
        if (frames <= 0) {
            return -1;
        }
        var total = frameSamples * frames;
        return total > MAX_PACKET_SAMPLES ? -1 : total;
    }
}
