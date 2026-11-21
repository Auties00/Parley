package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.RtcpFeedback;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.StringJoiner;
import java.util.TreeMap;

/// The codecs, header extensions and feedback mechanisms Parley negotiates by default, and the codec equivalence the
/// offer/answer exchange matches codecs by.
///
/// @implNote This implementation offers the formats the payload package packetizes, in the order browsers prefer
/// them, with the feedback mechanisms and format parameters Chrome writes, so its offers read like a browser's and
/// match a browser's answers without parameter renegotiation.
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
final class CodecCatalog {
    /// The media type of retransmission streams.
    static final String RTX = "rtx";
    /// The media type of redundant audio or video.
    static final String RED = "red";
    /// The media type of ULPFEC.
    static final String ULPFEC = "ulpfec";
    /// The media type of FlexFEC, in the draft-03 wire format browsers send.
    static final String FLEXFEC = "flexfec-03";
    /// The media type of DTMF events.
    static final String TELEPHONE_EVENT = "telephone-event";

    /// The URI of the `sdes:mid` header extension.
    static final URI MID = URI.create("urn:ietf:params:rtp-hdrext:sdes:mid");
    /// The URI of the `sdes:rtp-stream-id` header extension.
    static final URI RTP_STREAM_ID = URI.create("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id");
    /// The URI of the `sdes:repaired-rtp-stream-id` header extension.
    static final URI REPAIRED_RTP_STREAM_ID = URI.create("urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id");
    /// The URI of the audio level header extension.
    static final URI AUDIO_LEVEL = URI.create("urn:ietf:params:rtp-hdrext:ssrc-audio-level");
    /// The URI of the absolute send time header extension.
    static final URI ABS_SEND_TIME = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
    /// The URI of the transport-wide sequence number header extension.
    static final URI TRANSPORT_WIDE_CC =
            URI.create("http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
    /// The URI of the transmission offset header extension.
    static final URI TOFFSET = URI.create("urn:ietf:params:rtp-hdrext:toffset");
    /// The URI of the video orientation header extension.
    static final URI VIDEO_ORIENTATION = URI.create("urn:3gpp:video-orientation");
    /// The URI of the playout delay header extension.
    static final URI PLAYOUT_DELAY = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/playout-delay");
    /// The URI of the video content type header extension.
    static final URI VIDEO_CONTENT_TYPE =
            URI.create("http://www.webrtc.org/experiments/rtp-hdrext/video-content-type");
    /// The URI of the video timing header extension.
    static final URI VIDEO_TIMING = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/video-timing");
    /// The URI of the color space header extension.
    static final URI COLOR_SPACE = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/color-space");
    /// The URI of the absolute capture time header extension.
    static final URI ABS_CAPTURE_TIME = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
    /// The URI of the AV1 dependency descriptor header extension.
    static final URI DEPENDENCY_DESCRIPTOR = URI.create(
            "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension");

    /// The header extensions offered for audio, in offer order.
    private static final List<URI> AUDIO_EXTENSIONS = List.of(AUDIO_LEVEL, ABS_SEND_TIME, TRANSPORT_WIDE_CC, MID);
    /// The header extensions offered for video, in offer order.
    private static final List<URI> VIDEO_EXTENSIONS = List.of(TOFFSET, ABS_SEND_TIME, VIDEO_ORIENTATION,
            TRANSPORT_WIDE_CC, PLAYOUT_DELAY, VIDEO_CONTENT_TYPE, VIDEO_TIMING, COLOR_SPACE, MID, RTP_STREAM_ID,
            REPAIRED_RTP_STREAM_ID, DEPENDENCY_DESCRIPTOR);

    /// The payload types browsers give the common codecs, so an offer reads like theirs; others are allocated.
    private static final Map<String, Integer> PREFERRED_PAYLOAD_TYPES = Map.of(
            "audio/opus/48000/2", 111,
            "audio/telephone-event/48000/1", 126,
            "audio/telephone-event/8000/1", 110,
            "audio/red/48000/2", 63,
            "video/vp8/90000/1", 96);

    private CodecCatalog() {
    }

    /// {@return the default codecs, audio then video, in preference order}
    static List<Codec> defaultCodecs() {
        var result = new ArrayList<Codec>();
        result.add(codec("audio/opus", 48000, 2, Map.of("minptime", "10", "useinbandfec", "1")));
        result.add(codec("audio/red", 48000, 2, Map.of()));
        result.add(codec("audio/G722", 8000, 1, Map.of()));
        result.add(codec("audio/PCMU", 8000, 1, Map.of()));
        result.add(codec("audio/PCMA", 8000, 1, Map.of()));
        result.add(codec("audio/telephone-event", 48000, 1, Map.of()));
        result.add(codec("audio/telephone-event", 8000, 1, Map.of()));
        result.add(codec("video/VP8", 90000, 0, Map.of()));
        result.add(codec("video/VP9", 90000, 0, Map.of("profile-id", "0")));
        result.add(codec("video/VP9", 90000, 0, Map.of("profile-id", "2")));
        result.add(codec("video/AV1", 90000, 0, Map.of("level-idx", "5", "profile", "0", "tier", "0")));
        for (var profile : List.of("42001f", "42e01f", "4d001f", "64001f")) {
            for (var mode : List.of("1", "0")) {
                result.add(codec("video/H264", 90000, 0, Map.of("level-asymmetry-allowed", "1",
                        "packetization-mode", mode, "profile-level-id", profile)));
            }
        }
        result.add(codec("video/H265", 90000, 0, Map.of("level-id", "93", "profile-id", "1", "tier-flag", "0",
                "tx-mode", "SRST")));
        result.add(codec("video/rtx", 90000, 0, Map.of()));
        result.add(codec("video/red", 90000, 0, Map.of()));
        result.add(codec("video/ulpfec", 90000, 0, Map.of()));
        result.add(codec("video/flexfec-03", 90000, 0, Map.of("repair-window", "10000000")));
        return List.copyOf(result);
    }

    /// {@return the default header extensions, audio then video, each URI once}
    static List<RtpHeaderExtensionCapability> defaultHeaderExtensions() {
        var result = new LinkedHashMap<URI, RtpHeaderExtensionCapability>();
        for (var uri : AUDIO_EXTENSIONS) {
            result.put(uri, new RtpHeaderExtensionCapability(uri));
        }
        for (var uri : VIDEO_EXTENSIONS) {
            result.put(uri, new RtpHeaderExtensionCapability(uri));
        }
        return List.copyOf(result.values());
    }

    /// {@return whether the header extension `uri` applies to media of `kind`}
    static boolean extensionApplies(URI uri, MediaKind kind) {
        if (kind == MediaKind.AUDIO) {
            return AUDIO_EXTENSIONS.contains(uri) || !VIDEO_EXTENSIONS.contains(uri);
        }
        return VIDEO_EXTENSIONS.contains(uri) || !AUDIO_EXTENSIONS.contains(uri);
    }

    /// {@return the header extensions of `capabilities` a transceiver of `kind` negotiates, in order: those that apply
    /// to the kind, without the RTP stream id extensions for audio, which has no simulcast}
    static List<RtpHeaderExtensionCapability> extensionsFor(List<RtpHeaderExtensionCapability> capabilities,
                                                            MediaKind kind) {
        var result = new ArrayList<RtpHeaderExtensionCapability>();
        for (var capability : capabilities) {
            var uri = capability.uri();
            if (!extensionApplies(uri, kind)) {
                continue;
            }
            if (kind == MediaKind.AUDIO && (uri.equals(RTP_STREAM_ID) || uri.equals(REPAIRED_RTP_STREAM_ID))) {
                continue;
            }
            result.add(capability);
        }
        return List.copyOf(result);
    }

    /// {@return a codec with `channels` only when it is positive}
    static Codec codec(String mimeType, int clockRate, int channels, Map<String, String> parameters) {
        return new Codec(mimeType, clockRate, channels > 0 ? OptionalInt.of(channels) : OptionalInt.empty(),
                parameters);
    }

    /// {@return the media kind of a codec, from its media type}
    static MediaKind kindOf(Codec codec) {
        return codec.mimeType().regionMatches(true, 0, "audio/", 0, 6) ? MediaKind.AUDIO : MediaKind.VIDEO;
    }

    /// {@return the lower-case subtype of a codec's media type, such as `opus`}
    static String subtype(Codec codec) {
        var slash = codec.mimeType().indexOf('/');
        return codec.mimeType().substring(slash + 1).toLowerCase(Locale.ROOT);
    }

    /// {@return whether a codec is a retransmission, redundancy or FEC format rather than a media codec}
    static boolean isAuxiliary(Codec codec) {
        var subtype = subtype(codec);
        return subtype.equals(RTX) || subtype.equals(RED) || subtype.equals(ULPFEC) || subtype.equals(FLEXFEC);
    }

    /// {@return the channel count of a codec, `1` when it states none}
    static int channels(Codec codec) {
        return codec.channels().orElse(1);
    }

    /// {@return the format parameter `name` of a codec, ignoring the case of the name}
    static Optional<String> parameter(Codec codec, String name) {
        for (var entry : codec.formatParameters().entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return Optional.of(entry.getValue());
            }
        }
        return Optional.empty();
    }

    /// {@return the key that identifies a codec configuration for payload type allocation: the media type, clock
    /// rate, channels and the parameters that make two configurations different codecs}
    static String key(Codec codec) {
        var joiner = new StringJoiner("/");
        joiner.add(codec.mimeType().toLowerCase(Locale.ROOT)).add(Integer.toString(codec.clockRate()))
                .add(Integer.toString(channels(codec)));
        switch (subtype(codec)) {
            case "h264" -> joiner.add(h264Profile(codec)).add(parameter(codec, "packetization-mode").orElse("0"));
            case "vp9" -> joiner.add(parameter(codec, "profile-id").orElse("0"));
            case "av1" -> joiner.add(parameter(codec, "profile").orElse("0"));
            case "h265" -> joiner.add(parameter(codec, "profile-id").orElse("1"));
            case "flexfec-03" -> joiner.add(parameter(codec, "repair-window").orElse(""));
            default -> {
            }
        }
        return joiner.toString();
    }

    /// {@return the payload type browsers give `codec`, when there is one}
    static OptionalInt preferredPayloadType(Codec codec) {
        var key = codec.mimeType().toLowerCase(Locale.ROOT) + "/" + codec.clockRate() + "/" + channels(codec);
        var preferred = PREFERRED_PAYLOAD_TYPES.get(key);
        if (preferred != null) {
            return OptionalInt.of(preferred);
        }
        return staticPayloadType(codec);
    }

    /// {@return the RFC 3551 static payload type of `codec`, when it has one}
    static OptionalInt staticPayloadType(Codec codec) {
        if (codec.clockRate() != 8000 || channels(codec) != 1) {
            return OptionalInt.empty();
        }
        return switch (subtype(codec)) {
            case "pcmu" -> OptionalInt.of(0);
            case "pcma" -> OptionalInt.of(8);
            case "g722" -> OptionalInt.of(9);
            case "cn" -> OptionalInt.of(13);
            default -> OptionalInt.empty();
        };
    }

    /// {@return whether two codecs are the same codec for negotiation: same media type ignoring case, clock rate and
    /// channel count, and the same value of each parameter that selects a different bitstream}
    ///
    /// The parameters compared are the H.264 profile (not the level) and packetization mode, the VP9 and H.265
    /// `profile-id`, and the AV1 `profile`; every other parameter is a hint the answerer may change.
    static boolean matches(Codec a, Codec b) {
        if (!a.mimeType().equalsIgnoreCase(b.mimeType()) || a.clockRate() != b.clockRate()
                || channels(a) != channels(b)) {
            return false;
        }
        return switch (subtype(a)) {
            case "h264" -> h264Profile(a).equals(h264Profile(b))
                    && parameter(a, "packetization-mode").orElse("0")
                    .equals(parameter(b, "packetization-mode").orElse("0"));
            case "vp9" -> parameter(a, "profile-id").orElse("0").equals(parameter(b, "profile-id").orElse("0"));
            case "av1" -> parameter(a, "profile").orElse("0").equals(parameter(b, "profile").orElse("0"));
            case "h265" -> parameter(a, "profile-id").orElse("1").equals(parameter(b, "profile-id").orElse("1"));
            default -> true;
        };
    }

    /// {@return the profile of an H.264 codec, from the first two bytes of its `profile-level-id` (default
    /// `42000a`): `cb` constrained baseline, `b` baseline, `m` main, `e` extended, `h` high, `ch` constrained high,
    /// or the hex profile indication for any other}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
    static String h264Profile(Codec codec) {
        var text = parameter(codec, "profile-level-id").orElse("42000a");
        if (text.length() != 6) {
            return "invalid";
        }
        int idc;
        int iop;
        try {
            idc = Integer.parseInt(text.substring(0, 2), 16);
            iop = Integer.parseInt(text.substring(2, 4), 16);
        } catch (NumberFormatException exception) {
            return "invalid";
        }
        return switch (idc) {
            case 0x42 -> (iop & 0x40) != 0 ? "cb" : "b";
            case 0x4D -> (iop & 0x80) != 0 ? "cb" : "m";
            case 0x58 -> (iop & 0xC0) == 0xC0 ? "cb" : (iop & 0x80) != 0 ? "b" : "e";
            case 0x64 -> (iop & 0x0C) == 0x0C ? "ch" : "h";
            default -> Integer.toHexString(idc);
        };
    }

    /// {@return the feedback mechanisms Parley supports for a codec, in the order browsers write them}
    static List<RtcpFeedback> feedback(Codec codec) {
        if (isAuxiliary(codec) || subtype(codec).equals(TELEPHONE_EVENT)) {
            return List.of();
        }
        if (kindOf(codec) == MediaKind.AUDIO) {
            return subtype(codec).equals("opus") ? List.of(fb("transport-cc", null)) : List.of();
        }
        return List.of(fb("goog-remb", null), fb("transport-cc", null), fb("ccm", "fir"), fb("nack", null),
                fb("nack", "pli"));
    }

    /// The section-wide feedback mechanism that asks for RFC 8888 congestion control feedback,
    /// `a=rtcp-fb:* ack ccfb`.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
    static final RtcpFeedback CCFB = new RtcpFeedback("ack", Optional.of("ccfb"));

    /// {@return a feedback mechanism, `parameter` absent when `null`}
    static RtcpFeedback fb(String type, String parameter) {
        return new RtcpFeedback(type, Optional.ofNullable(parameter));
    }

    /// {@return the `a=fmtp` text of a codec: its parameters sorted by name, or an empty optional when it has none}
    static Optional<String> fmtpLine(Codec codec) {
        if (codec.formatParameters().isEmpty()) {
            return Optional.empty();
        }
        var sorted = new TreeMap<String, String>(codec.formatParameters());
        var joiner = new StringJoiner(";");
        sorted.forEach((name, value) -> joiner.add(value.isEmpty() ? name : name + "=" + value));
        return Optional.of(joiner.toString());
    }

    /// {@return the codecs of `kind` in `codecs`, in order}
    static List<Codec> ofKind(List<Codec> codecs, MediaKind kind) {
        Objects.requireNonNull(kind);
        return codecs.stream().filter(codec -> kindOf(codec) == kind).toList();
    }

    /// {@return an unmodifiable copy of a parameter map that keeps its order}
    static Map<String, String> orderedCopy(Map<String, String> map) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(map));
    }
}
