package com.github.auties00.parley.payload;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;

/// The Opus format parameters of RFC 7587, the `a=fmtp` model of an Opus codec.
///
/// Every parameter describes what the side that sends it wants to receive, or (the `sprop-` ones) what it will send.
/// [#parse(Map)] is lenient as RFC 7587 asks: a parameter with a malformed or out-of-range value is ignored.
///
/// @param maxPlaybackRate     `maxplaybackrate`: the highest audio sample rate the receiver renders, `8000..48000` Hz
/// @param spropMaxCaptureRate `sprop-maxcapturerate`: the highest sample rate the sender captures, `8000..48000` Hz
/// @param maxPtime            `maxptime`: the longest packet the receiver accepts, `3..120` ms
/// @param ptime               `ptime`: the packet duration the receiver prefers, `3..120` ms
/// @param minPtime            `minptime`: the shortest packet the receiver accepts, `3..120` ms (a browser extension)
/// @param maxAverageBitrate   `maxaveragebitrate`: the highest average bitrate the receiver accepts,
///                            `6000..510000` bits per second
/// @param stereo              `stereo`: the receiver prefers stereo
/// @param spropStereo         `sprop-stereo`: the sender may send stereo
/// @param cbr                 `cbr`: the receiver prefers constant bitrate
/// @param useInbandFec        `useinbandfec`: the receiver can use Opus in-band forward error correction
/// @param useDtx              `usedtx`: the receiver prefers discontinuous transmission
/// @spec https://www.rfc-editor.org/rfc/rfc7587.html RFC 7587: RTP Payload Format for the Opus Speech and Audio Codec
public record OpusParameters(OptionalInt maxPlaybackRate, OptionalInt spropMaxCaptureRate, OptionalInt maxPtime,
                             OptionalInt ptime, OptionalInt minPtime, OptionalInt maxAverageBitrate, boolean stereo,
                             boolean spropStereo, boolean cbr, boolean useInbandFec, boolean useDtx) {
    /// Parameters that set nothing.
    private static final OpusParameters DEFAULTS = new OpusParameters(OptionalInt.empty(), OptionalInt.empty(),
            OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(), false, false, false,
            false, false);

    /// Creates parameters.
    ///
    /// @param maxPlaybackRate     the `maxplaybackrate`
    /// @param spropMaxCaptureRate the `sprop-maxcapturerate`
    /// @param maxPtime            the `maxptime`
    /// @param ptime               the `ptime`
    /// @param minPtime            the `minptime`
    /// @param maxAverageBitrate   the `maxaveragebitrate`
    /// @param stereo              the `stereo` flag
    /// @param spropStereo         the `sprop-stereo` flag
    /// @param cbr                 the `cbr` flag
    /// @param useInbandFec        the `useinbandfec` flag
    /// @param useDtx              the `usedtx` flag
    /// @throws IllegalArgumentException if a value is outside its range
    public OpusParameters {
        check(maxPlaybackRate, 8000, 48000, "maxplaybackrate");
        check(spropMaxCaptureRate, 8000, 48000, "sprop-maxcapturerate");
        check(maxPtime, 3, 120, "maxptime");
        check(ptime, 3, 120, "ptime");
        check(minPtime, 3, 120, "minptime");
        check(maxAverageBitrate, 6000, 510000, "maxaveragebitrate");
    }

    /// {@return parameters that set nothing, the meaning of an Opus codec without `a=fmtp`}
    public static OpusParameters defaults() {
        return DEFAULTS;
    }

    /// Reads the parameters of a codec's format parameters.
    ///
    /// @param formatParameters the format parameters, names in lower case
    /// @return the parameters; malformed or out-of-range values and unknown names are ignored
    public static OpusParameters parse(Map<String, String> formatParameters) {
        return new OpusParameters(
                number(formatParameters, "maxplaybackrate", 8000, 48000),
                number(formatParameters, "sprop-maxcapturerate", 8000, 48000),
                number(formatParameters, "maxptime", 3, 120),
                number(formatParameters, "ptime", 3, 120),
                number(formatParameters, "minptime", 3, 120),
                number(formatParameters, "maxaveragebitrate", 6000, 510000),
                flag(formatParameters, "stereo"),
                flag(formatParameters, "sprop-stereo"),
                flag(formatParameters, "cbr"),
                flag(formatParameters, "useinbandfec"),
                flag(formatParameters, "usedtx"));
    }

    /// {@return the parameters as format parameters, writing only those that differ from [#defaults()]}
    public Map<String, String> toFormatParameters() {
        var result = new LinkedHashMap<String, String>();
        maxPlaybackRate.ifPresent(value -> result.put("maxplaybackrate", Integer.toString(value)));
        spropMaxCaptureRate.ifPresent(value -> result.put("sprop-maxcapturerate", Integer.toString(value)));
        maxPtime.ifPresent(value -> result.put("maxptime", Integer.toString(value)));
        ptime.ifPresent(value -> result.put("ptime", Integer.toString(value)));
        minPtime.ifPresent(value -> result.put("minptime", Integer.toString(value)));
        maxAverageBitrate.ifPresent(value -> result.put("maxaveragebitrate", Integer.toString(value)));
        if (stereo) {
            result.put("stereo", "1");
        }
        if (spropStereo) {
            result.put("sprop-stereo", "1");
        }
        if (cbr) {
            result.put("cbr", "1");
        }
        if (useInbandFec) {
            result.put("useinbandfec", "1");
        }
        if (useDtx) {
            result.put("usedtx", "1");
        }
        return Map.copyOf(result);
    }

    /// Checks an optional value against a range.
    private static void check(OptionalInt value, int min, int max, String name) {
        Objects.requireNonNull(value, name + " cannot be null");
        if (value.isPresent() && (value.getAsInt() < min || value.getAsInt() > max)) {
            throw new IllegalArgumentException(name + " out of range " + min + ".." + max + ": " + value.getAsInt());
        }
    }

    /// {@return a numeric parameter inside a range, or empty when absent, malformed or outside it}
    private static OptionalInt number(Map<String, String> parameters, String name, int min, int max) {
        var value = parameters.get(name);
        if (value == null) {
            return OptionalInt.empty();
        }
        try {
            var parsed = Integer.parseInt(value.strip());
            return parsed < min || parsed > max ? OptionalInt.empty() : OptionalInt.of(parsed);
        } catch (NumberFormatException exception) {
            return OptionalInt.empty();
        }
    }

    /// {@return whether a flag parameter is `1`}
    private static boolean flag(Map<String, String> parameters, String name) {
        var value = parameters.get(name);
        return value != null && value.strip().equals("1");
    }
}
