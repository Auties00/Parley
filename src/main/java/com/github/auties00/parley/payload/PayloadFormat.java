package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;

import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.OptionalInt;

/// An RTP payload format: how the frames of one codec travel in RTP payloads.
///
/// A format is an immutable value bound to a [Codec]; it makes the stateful [Packetizer] of an outgoing stream and
/// the [Depacketizer] of an incoming one, and answers per-packet questions (is this a keyframe, how much media does
/// it carry) without state. Parley implements payload formats only: it never encodes or decodes media.
///
/// {@snippet lang = java :
/// var format = PayloadFormat.of(Codec.vp8());
/// var packetizer = format.packetizer(PacketizerConfig.defaults());
/// for (var payload : packetizer.packetize(frame)) {
///     sendStream.send(payload.payload(), payload.marker());
/// }
/// }
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3551.html RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
public sealed interface PayloadFormat permits OpusFormat, AudioFormat, ComfortNoiseFormat, TelephoneEventFormat,
        Vp8Format, Vp9Format, H264Format, H265Format, Av1Format, GenericFormat {
    /// {@return the payload format of a codec}
    ///
    /// | Codec name (any case) | Format |
    /// |---|---|
    /// | `opus` | [OpusFormat] |
    /// | `CN` | [ComfortNoiseFormat] |
    /// | `telephone-event` | [TelephoneEventFormat] |
    /// | `VP8`, `VP9`, `H264`, `H265`, `AV1` | [Vp8Format], [Vp9Format], [H264Format], [H265Format], [Av1Format] |
    /// | any other audio codec (`PCMU`, `PCMA`, `G722`, ...) | [AudioFormat], one frame per packet |
    /// | any other video codec | [GenericFormat], opaque frames split across packets |
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is a repair or redundancy format (`rtx`, `red`, `ulpfec`,
    ///                                  `flexfec`, `flexfec-03`), which carries other packets rather than frames, or
    ///                                  if it violates its format (Opus at a clock rate other than 48 kHz)
    static PayloadFormat of(Codec codec) {
        var name = codec.name().toLowerCase(Locale.ROOT);
        return switch (name) {
            case "rtx", "red", "ulpfec", "flexfec", "flexfec-03" ->
                    throw new IllegalArgumentException(codec.mimeType() + " is a repair format, not a media format");
            case "opus" -> new OpusFormat(codec);
            case "cn" -> new ComfortNoiseFormat(codec);
            case "telephone-event" -> new TelephoneEventFormat(codec);
            case "vp8" -> new Vp8Format(codec);
            case "vp9" -> new Vp9Format(codec);
            case "h264" -> new H264Format(codec);
            case "h265" -> new H265Format(codec);
            case "av1" -> new Av1Format(codec);
            default -> codec.kind() == MediaKind.AUDIO ? new AudioFormat(codec) : new GenericFormat(codec);
        };
    }

    /// {@return the codec the format carries}
    Codec codec();

    /// {@return the kind of media the format carries}
    default MediaKind kind() {
        return codec().kind();
    }

    /// {@return a new packetizer for one outgoing stream}
    ///
    /// @param config the packetizer settings
    Packetizer packetizer(PacketizerConfig config);

    /// {@return a new packetizer for one outgoing stream with [PacketizerConfig#defaults()]}
    default Packetizer packetizer() {
        return packetizer(PacketizerConfig.defaults());
    }

    /// {@return a new depacketizer for one incoming stream that reads no header extension}
    default Depacketizer depacketizer() {
        return depacketizer(DepacketizerConfig.none());
    }

    /// {@return a new depacketizer for one incoming stream}
    ///
    /// @param config the header extensions the depacketizer reads
    Depacketizer depacketizer(DepacketizerConfig config);

    /// Tests whether one RTP payload belongs to a keyframe, from that payload alone.
    ///
    /// Every audio payload is a keyframe. A video payload is one when it shows the start of an intra frame (the
    /// first packet of a VP8 keyframe, a packet with an H.264 IDR slice or an AV1 sequence header); packets after
    /// the first of a VP8 keyframe tell nothing and return `false`.
    ///
    /// @param payload the payload, from position to limit; neither its position nor its content changes
    /// @return whether the payload belongs to a keyframe; `false` for a malformed payload
    boolean isKeyframe(ByteBuffer payload);

    /// {@return the span of media one payload carries, in units of the codec's clock rate (the RTP timestamp step to
    /// the next payload), or an empty optional when the format does not tell (video, unknown codecs)}
    ///
    /// @param payload the payload, from position to limit; neither its position nor its content changes
    OptionalInt timestampDuration(ByteBuffer payload);
}
