package com.github.auties00.parley.sdp;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.RtpCodecParameters;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.StringJoiner;

/// One RTP payload format of a media section, as its `a=rtpmap` and `a=fmtp` lines write it: the SDP view of a
/// [RtpCodecParameters].
///
/// ```text
/// a=rtpmap:111 opus/48000/2
/// a=fmtp:111 minptime=10;useinbandfec=1
/// ```
///
/// The record only names a format; it encodes and decodes nothing. [#toParameters()] and
/// [#of(RtpCodecParameters)] convert to and from the canonical codec model of the `media` package.
///
/// @param payloadType      the RTP payload type, `0..127`
/// @param name             the encoding name as written, such as `opus` or `PCMA`
/// @param clockRate        the RTP clock rate in hertz
/// @param channels         the channel count of the `a=rtpmap` line, or an empty optional when the line names none
///                         (one channel)
/// @param formatParameters the format parameters of the `a=fmtp` line in order, unmodifiable, empty when the format has
///                         none; a line that is not a `key=value` list separated by `;` (RED's `111/111`,
///                         telephone-event's `0-15`) is kept verbatim under the empty key `""`
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc3551.html RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
public record RtpCodec(int payloadType, String name, int clockRate, OptionalInt channels,
                       Map<String, String> formatParameters) {
    /// The RTP clock rate of every video payload format.
    private static final int VIDEO_CLOCK_RATE = 90000;

    /// Creates a payload format, copying the parameters in order.
    ///
    /// @param payloadType      the RTP payload type
    /// @param name             the encoding name
    /// @param clockRate        the RTP clock rate in hertz
    /// @param channels         the channel count, or an empty optional
    /// @param formatParameters the format parameters
    /// @throws IllegalArgumentException if `payloadType` is outside `0..127`, `clockRate` or a present `channels`
    ///                                  is not positive, or `name` is empty or holds `/` or whitespace
    public RtpCodec {
        Objects.requireNonNull(name, "name cannot be null");
        Objects.requireNonNull(channels, "channels cannot be null");
        Objects.requireNonNull(formatParameters, "formatParameters cannot be null");
        if (payloadType < 0 || payloadType > 127) {
            throw new IllegalArgumentException("payload type out of range: " + payloadType);
        }
        if (name.isEmpty() || name.indexOf('/') >= 0 || name.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("malformed encoding name: '" + name + "'");
        }
        if (clockRate <= 0 || (channels.isPresent() && channels.getAsInt() <= 0)) {
            throw new IllegalArgumentException("clock rate and channels must be positive");
        }
        var copy = new LinkedHashMap<String, String>();
        formatParameters.forEach((key, value) -> copy.put(Objects.requireNonNull(key, "key cannot be null"),
                Objects.requireNonNull(value, "value cannot be null")));
        formatParameters = java.util.Collections.unmodifiableMap(copy);
    }

    /// {@return a payload format without format parameters}
    ///
    /// @param payloadType the RTP payload type, `0..127`
    /// @param name        the encoding name
    /// @param clockRate   the RTP clock rate in hertz
    /// @throws IllegalArgumentException as the canonical constructor does
    public static RtpCodec of(int payloadType, String name, int clockRate) {
        return new RtpCodec(payloadType, name, clockRate, OptionalInt.empty(), Map.of());
    }

    /// {@return the SDP view of codec parameters: the media subtype as the encoding name, the channel count and the
    /// format parameters of the codec}
    ///
    /// @param parameters the codec parameters
    public static RtpCodec of(RtpCodecParameters parameters) {
        var codec = parameters.codec();
        return new RtpCodec(parameters.payloadType(), codec.name(), codec.clockRate(), codec.channels(),
                codec.formatParameters());
    }

    /// {@return the unmodifiable payload formats of a media section, in the order of its `m=` format list}
    ///
    /// A format without an `a=rtpmap` line is resolved from the static payload types of RFC 3551 (`0` is `PCMU`, `8`
    /// is `PCMA` and `9` is `G722`, all at 8000 Hz); any other format without one, a format that is not a number in
    /// `0..127`, and a format whose `a=rtpmap` line is malformed are skipped.
    ///
    /// @param section the media section
    public static List<RtpCodec> of(MediaDescription section) {
        var result = new ArrayList<RtpCodec>();
        for (var format : section.formats()) {
            int payloadType;
            try {
                payloadType = Integer.parseInt(format);
            } catch (NumberFormatException exception) {
                continue;
            }
            if (payloadType < 0 || payloadType > 127) {
                continue;
            }
            var rtpmap = findFormatAttribute(section, "rtpmap", payloadType);
            var fmtp = findFormatAttribute(section, "fmtp", payloadType).map(RtpCodec::parseFormatParameters)
                    .orElse(Map.of());
            if (rtpmap.isPresent()) {
                var encoding = rtpmap.get().split("/");
                try {
                    var clock = encoding.length > 1 ? Integer.parseInt(encoding[1].trim()) : 8000;
                    var channels = encoding.length > 2 ? OptionalInt.of(Integer.parseInt(encoding[2].trim()))
                            : OptionalInt.empty();
                    result.add(new RtpCodec(payloadType, encoding[0].trim(), clock, channels, fmtp));
                } catch (IllegalArgumentException exception) {
                    // a malformed rtpmap makes the format unusable, not the whole section
                }
            } else if (payloadType == 0) {
                result.add(new RtpCodec(0, "PCMU", 8000, OptionalInt.empty(), fmtp));
            } else if (payloadType == 8) {
                result.add(new RtpCodec(8, "PCMA", 8000, OptionalInt.empty(), fmtp));
            } else if (payloadType == 9) {
                result.add(new RtpCodec(9, "G722", 8000, OptionalInt.empty(), fmtp));
            }
        }
        return List.copyOf(result);
    }

    /// {@return the parameters of an `a=fmtp` value after the payload type, in order}
    ///
    /// A value made of `key=value` pairs separated by `;` maps each key, trimmed and as written, to its trimmed
    /// value; any other value (a part without `=`, an empty key, or a key given twice) maps the whole trimmed value
    /// to the empty key.
    ///
    /// @param value the parameters as written, such as `minptime=10;useinbandfec=1`
    public static Map<String, String> parseFormatParameters(String value) {
        var trimmed = value.strip();
        if (trimmed.isEmpty()) {
            return Map.of();
        }
        var result = new LinkedHashMap<String, String>();
        for (var part : trimmed.split(";")) {
            var parameter = part.strip();
            if (parameter.isEmpty()) {
                continue;
            }
            var equals = parameter.indexOf('=');
            var key = equals < 0 ? "" : parameter.substring(0, equals).strip();
            if (key.isEmpty() || result.containsKey(key)) {
                return Map.of("", trimmed);
            }
            result.put(key, parameter.substring(equals + 1).strip());
        }
        return java.util.Collections.unmodifiableMap(result);
    }

    /// {@return the kind of media the format carries: video for a format at the 90 kHz clock without a channel
    /// count, audio for every other}
    ///
    /// Every RTP video payload format runs at 90 kHz (RFC 3551 section 5) and only audio formats state channels.
    public MediaKind kind() {
        return channels.isEmpty() && clockRate == VIDEO_CLOCK_RATE ? MediaKind.VIDEO : MediaKind.AUDIO;
    }

    /// {@return the canonical codec parameters of this format, without feedback; the media type is
    /// `<kind>/<name>` with the kind of [#kind()], and a video format drops a channel count}
    ///
    /// @throws IllegalArgumentException if the format parameters name one key twice ignoring case
    public RtpCodecParameters toParameters() {
        var kind = kind();
        var codec = new Codec(kind.type() + "/" + name, clockRate,
                kind == MediaKind.VIDEO ? OptionalInt.empty() : channels, formatParameters);
        return RtpCodecParameters.of(payloadType, codec);
    }

    /// {@return whether the encoding name equals `encoding`, ignoring case as media type names require}
    ///
    /// @param encoding the encoding name to compare with
    /// @spec https://www.rfc-editor.org/rfc/rfc4855.html RFC 4855: Media Type Registration of RTP Payload Formats
    public boolean is(String encoding) {
        return name.equalsIgnoreCase(encoding);
    }

    /// {@return the channel count, `1` when [#channels()] is empty}
    public int channelCount() {
        return channels.orElse(1);
    }

    /// {@return the `a=rtpmap` value of this format, `<pt> <name>/<clock>`, with a `/<channels>` suffix when the
    /// channel count is stated}
    public String rtpmapValue() {
        return payloadType + " " + name + "/" + clockRate
                + (channels.isPresent() ? "/" + channels.getAsInt() : "");
    }

    /// {@return the `a=fmtp` value of this format after the payload type, the parameters in order joined by `;` (the
    /// value of the empty key written bare), or an empty optional when the format has none}
    public Optional<String> fmtpValue() {
        if (formatParameters.isEmpty()) {
            return Optional.empty();
        }
        var joiner = new StringJoiner(";");
        formatParameters.forEach((key, value) -> joiner.add(key.isEmpty() ? value : key + "=" + value));
        return Optional.of(joiner.toString());
    }

    /// {@return the encoding name in lower case, in the root locale}
    public String normalizedName() {
        return name.toLowerCase(Locale.ROOT);
    }

    /// {@return the text after the payload type of the first `a=<name>:<pt> ...` attribute for `payloadType`, or an
    /// empty optional when the section has no such line}
    ///
    /// @param name the attribute name, `rtpmap` or `fmtp`
    private static Optional<String> findFormatAttribute(MediaDescription section, String name, int payloadType) {
        var prefix = payloadType + " ";
        for (var value : section.attributes(name)) {
            if (value.startsWith(prefix)) {
                return Optional.of(value.substring(prefix.length()).trim());
            }
        }
        return Optional.empty();
    }
}
