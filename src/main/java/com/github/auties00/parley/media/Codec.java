package com.github.auties00.parley.media;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Collectors;

/// A codec as SDP negotiates it: a media type, an RTP clock rate, a channel count for audio, and the `a=fmtp`
/// format parameters.
///
/// Media types compare without regard to case (`video/H264` and `video/h264` are the same codec), and format parameter
/// names are stored in lower case, since RFC 4855 makes them case-insensitive; their values keep their case.
///
/// {@snippet lang = java :
/// var opus = Codec.opus().withFormatParameters(Map.of("useinbandfec", "1"));
/// var h264 = Codec.of("video/H264", 90000).withFormatParameters(Map.of(
///         "profile-level-id", "42e01f", "packetization-mode", "1"));
/// }
///
/// @param mimeType         the media type, `audio/<name>` or `video/<name>`, such as `audio/opus`
/// @param clockRate        the RTP clock rate in Hz, positive
/// @param channels         the channel count of an audio codec as the `a=rtpmap` line states it, or an empty optional
///                         when the line omits it (one channel); always empty for video
/// @param formatParameters the format parameters, unmodifiable, names in lower case
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc4855.html RFC 4855: Media Type Registration of RTP Payload Formats
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
/// @spec https://www.rfc-editor.org/rfc/rfc7587.html RFC 7587: RTP Payload Format for the Opus Speech and Audio Codec
/// @spec https://www.rfc-editor.org/rfc/rfc7798.html RFC 7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
public record Codec(String mimeType, int clockRate, OptionalInt channels, Map<String, String> formatParameters) {
    /// Creates a codec.
    ///
    /// @param mimeType         the media type
    /// @param clockRate        the clock rate
    /// @param channels         the channel count
    /// @param formatParameters the format parameters; names are converted to lower case
    /// @throws IllegalArgumentException if `mimeType` is not `audio/<name>` or `video/<name>`, `clockRate` is not
    ///                                  positive, `channels` is present for video or not positive, or two parameter
    ///                                  names differ only in case
    public Codec {
        Objects.requireNonNull(mimeType, "mimeType cannot be null");
        Objects.requireNonNull(channels, "channels cannot be null");
        Objects.requireNonNull(formatParameters, "formatParameters cannot be null");
        var slash = mimeType.indexOf('/');
        if (slash <= 0 || slash == mimeType.length() - 1 || mimeType.indexOf('/', slash + 1) >= 0
                || mimeType.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("invalid media type: " + mimeType);
        }
        var kind = MediaKind.ofType(mimeType.substring(0, slash))
                .orElseThrow(() -> new IllegalArgumentException("not an audio or video media type: " + mimeType));
        if (clockRate <= 0) {
            throw new IllegalArgumentException("clock rate must be positive: " + clockRate);
        }
        if (channels.isPresent() && (kind == MediaKind.VIDEO || channels.getAsInt() <= 0)) {
            throw new IllegalArgumentException("invalid channel count for " + mimeType + ": " + channels.getAsInt());
        }
        var normalized = new LinkedHashMap<String, String>();
        for (var entry : formatParameters.entrySet()) {
            var name = Objects.requireNonNull(entry.getKey(), "parameter name cannot be null").toLowerCase(Locale.ROOT);
            var value = Objects.requireNonNull(entry.getValue(), "parameter value cannot be null");
            if (normalized.put(name, value) != null) {
                throw new IllegalArgumentException("duplicate format parameter: " + name);
            }
        }
        formatParameters = Map.copyOf(normalized);
    }

    /// {@return a codec without channels or format parameters}
    ///
    /// @param mimeType  the media type
    /// @param clockRate the clock rate in Hz
    /// @throws IllegalArgumentException as [#Codec(String,int,OptionalInt,Map)] does
    public static Codec of(String mimeType, int clockRate) {
        return new Codec(mimeType, clockRate, OptionalInt.empty(), Map.of());
    }

    /// {@return an audio codec with a channel count and no format parameters}
    ///
    /// @param mimeType  the media type
    /// @param clockRate the clock rate in Hz
    /// @param channels  the channel count
    /// @throws IllegalArgumentException as [#Codec(String,int,OptionalInt,Map)] does
    public static Codec of(String mimeType, int clockRate, int channels) {
        return new Codec(mimeType, clockRate, OptionalInt.of(channels), Map.of());
    }

    /// {@return Opus, `audio/opus` at 48 kHz with the two channels RFC 7587 requires every `a=rtpmap` to state,
    /// whatever the stream carries}
    public static Codec opus() {
        return of("audio/opus", 48000, 2);
    }

    /// {@return G.711 mu-law, `audio/PCMU` at 8 kHz}
    public static Codec pcmu() {
        return of("audio/PCMU", 8000);
    }

    /// {@return G.711 A-law, `audio/PCMA` at 8 kHz}
    public static Codec pcma() {
        return of("audio/PCMA", 8000);
    }

    /// {@return G.722, `audio/G722` at the 8 kHz RTP clock RFC 3551 assigns it although it samples at 16 kHz}
    public static Codec g722() {
        return of("audio/G722", 8000);
    }

    /// {@return RFC 4733 telephone events at a clock rate, with the events `0-15` (the DTMF digits)}
    ///
    /// @param clockRate the clock rate, which must be the one of the audio codec the events accompany
    public static Codec telephoneEvent(int clockRate) {
        return new Codec("audio/telephone-event", clockRate, OptionalInt.empty(), Map.of("", "0-15"));
    }

    /// {@return VP8, `video/VP8` at 90 kHz}
    public static Codec vp8() {
        return of("video/VP8", 90000);
    }

    /// {@return VP9 profile 0, `video/VP9` at 90 kHz}
    public static Codec vp9() {
        return of("video/VP9", 90000);
    }

    /// {@return H.264 Constrained Baseline level 3.1 in packetization mode 1, `video/H264` at 90 kHz}
    public static Codec h264() {
        return new Codec("video/H264", 90000, OptionalInt.empty(), Map.of(
                "level-asymmetry-allowed", "1", "packetization-mode", "1", "profile-level-id", "42e01f"));
    }

    /// {@return H.265 Main profile, `video/H265` at 90 kHz}
    public static Codec h265() {
        return of("video/H265", 90000);
    }

    /// {@return AV1 Main profile, `video/AV1` at 90 kHz}
    public static Codec av1() {
        return of("video/AV1", 90000);
    }

    /// {@return the kind of media, from the top-level type of [#mimeType()]}
    public MediaKind kind() {
        return MediaKind.ofType(mimeType.substring(0, mimeType.indexOf('/'))).orElseThrow();
    }

    /// {@return the encoding name, the subtype of [#mimeType()] as written, such as `opus` or `H264`}
    public String name() {
        return mimeType.substring(mimeType.indexOf('/') + 1);
    }

    /// {@return the channel count, `1` when [#channels()] is empty}
    public int channelCount() {
        return channels.orElse(1);
    }

    /// {@return the value of a format parameter, or an empty optional when the codec does not set it}
    ///
    /// @param name the parameter name, in any case
    public Optional<String> formatParameter(String name) {
        return Optional.ofNullable(formatParameters.get(name.toLowerCase(Locale.ROOT)));
    }

    /// {@return a copy of the codec with other format parameters}
    ///
    /// @param parameters the parameters, replacing the current ones
    public Codec withFormatParameters(Map<String, String> parameters) {
        return new Codec(mimeType, clockRate, channels, parameters);
    }

    /// {@return the format parameters as the value of an `a=fmtp` attribute after the payload type, such as
    /// `minptime=10;useinbandfec=1`, sorted by name; a parameter with an empty name is written as its bare value}
    public String formatParametersLine() {
        return formatParameters.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> entry.getKey().isEmpty() ? entry.getValue() : entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(";"));
    }

    /// Parses the value of an `a=fmtp` attribute after the payload type.
    ///
    /// Parameters are separated by `;`, each `name=value`. A parameter without `=`, such as the `0-15` of
    /// `telephone-event`, is stored under the empty name.
    ///
    /// @param value the parameters, such as `minptime=10;useinbandfec=1`
    /// @return the parameters, names in lower case, in their order
    /// @throws IllegalArgumentException if a name appears twice
    public static Map<String, String> parseFormatParameters(String value) {
        var result = new LinkedHashMap<String, String>();
        for (var part : value.split(";")) {
            var trimmed = part.strip();
            if (trimmed.isEmpty()) {
                continue;
            }
            var equals = trimmed.indexOf('=');
            var name = equals < 0 ? "" : trimmed.substring(0, equals).strip().toLowerCase(Locale.ROOT);
            var parameter = equals < 0 ? trimmed : trimmed.substring(equals + 1).strip();
            if (result.put(name, parameter) != null) {
                throw new IllegalArgumentException("duplicate format parameter: " + name);
            }
        }
        return result;
    }

    /// Tests whether another codec is the same codec for negotiation: an offered codec and an answered one match when
    /// this returns `true`.
    ///
    /// The media types must be equal ignoring case, the clock rates equal, and the channel counts equal (an absent
    /// count is one channel). The format parameters must then agree on what identifies the bitstream, and only on
    /// that, since the others are receive preferences each side states for itself:
    ///
    /// | Codec | Parameters that must agree |
    /// |---|---|
    /// | H.264 | the profile of `profile-level-id` (not the level, which each side bounds), `packetization-mode` (default `0`) |
    /// | H.265 | `profile-id` (default `1`) and `tier-flag` (default `0`) |
    /// | VP9 | `profile-id` (default `0`) |
    /// | AV1 | `profile` (default `0`) |
    /// | RTX | `apt` |
    /// | Opus and every other codec | none: `stereo`, `useinbandfec` and the like describe what the receiver wants |
    ///
    /// An H.264 `profile-level-id` this class cannot parse matches nothing.
    ///
    /// @param other the other codec
    /// @return whether the two codecs match
    /// @spec https://www.rfc-editor.org/rfc/rfc6184.html#section-8.1 RFC 6184 section 8.1: Media Type Registration
    public boolean matches(Codec other) {
        Objects.requireNonNull(other, "other cannot be null");
        if (!mimeType.equalsIgnoreCase(other.mimeType) || clockRate != other.clockRate
                || channelCount() != other.channelCount()) {
            return false;
        }
        return switch (name().toLowerCase(Locale.ROOT)) {
            case "h264" -> {
                var mine = H264ProfileLevelId.of(formatParameters);
                var theirs = H264ProfileLevelId.of(other.formatParameters);
                yield mine.isPresent() && theirs.isPresent() && mine.get().profile() == theirs.get().profile()
                        && sameParameter(other, "packetization-mode", "0");
            }
            case "h265" -> sameParameter(other, "profile-id", "1") && sameParameter(other, "tier-flag", "0");
            case "vp9" -> sameParameter(other, "profile-id", "0");
            case "av1" -> sameParameter(other, "profile", "0");
            case "rtx" -> sameParameter(other, "apt", "");
            default -> true;
        };
    }

    /// {@return whether both codecs set a parameter to the same value, `fallback` standing for an absent one}
    private boolean sameParameter(Codec other, String name, String fallback) {
        return formatParameters.getOrDefault(name, fallback).strip()
                .equals(other.formatParameters.getOrDefault(name, fallback).strip());
    }
}
