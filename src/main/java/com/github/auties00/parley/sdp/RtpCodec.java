package com.github.auties00.parley.sdp;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/// One RTP payload format of a media section: its payload type and the encoding that its `a=rtpmap` and `a=fmtp`
/// lines describe.
///
/// ```text
/// a=rtpmap:111 opus/48000/2
/// a=fmtp:111 minptime=10;useinbandfec=1
/// ```
///
/// The record only names a format; it encodes and decodes nothing.
///
/// @param payloadType the RTP payload type, `0..127`
/// @param name        the encoding name as written, such as `opus` or `PCMA`
/// @param clockRate   the RTP clock rate in hertz
/// @param channels    the channel count, `1` when the `a=rtpmap` line names none
/// @param parameters  the format parameters of the `a=fmtp` line, or `null` when the format has none
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc3551.html RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
public record RtpCodec(int payloadType, String name, int clockRate, int channels, String parameters) {
    /// Creates a payload format.
    ///
    /// @param payloadType the RTP payload type
    /// @param name        the encoding name
    /// @param clockRate   the RTP clock rate in hertz
    /// @param channels    the channel count
    /// @param parameters  the format parameters, or `null` for none
    /// @throws IllegalArgumentException if `payloadType` is outside `0..127`, or `clockRate` or `channels` is not
    ///                                  positive
    public RtpCodec {
        Objects.requireNonNull(name, "name cannot be null");
        if (payloadType < 0 || payloadType > 127) {
            throw new IllegalArgumentException("payload type out of range: " + payloadType);
        }
        if (clockRate <= 0 || channels <= 0) {
            throw new IllegalArgumentException("clock rate and channels must be positive");
        }
    }

    /// {@return the unmodifiable payload formats of a media section, in the order of its `m=` format list}
    ///
    /// A format without an `a=rtpmap` line is resolved from the static payload types of RFC 3551 (`0` is `PCMU` and
    /// `8` is `PCMA`, both at 8000 Hz); any other format without one, a format that is not a number in `0..127`, and
    /// a format whose `a=rtpmap` line is malformed are skipped.
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
            var fmtp = findFormatAttribute(section, "fmtp", payloadType).orElse(null);
            if (rtpmap.isPresent()) {
                var encoding = rtpmap.get().split("/");
                try {
                    var clock = encoding.length > 1 ? Integer.parseInt(encoding[1].trim()) : 8000;
                    var channels = encoding.length > 2 ? Integer.parseInt(encoding[2].trim()) : 1;
                    result.add(new RtpCodec(payloadType, encoding[0].trim(), clock, channels, fmtp));
                } catch (IllegalArgumentException exception) {
                    // a malformed rtpmap makes the format unusable, not the whole section
                }
            } else if (payloadType == 0) {
                result.add(new RtpCodec(0, "PCMU", 8000, 1, fmtp));
            } else if (payloadType == 8) {
                result.add(new RtpCodec(8, "PCMA", 8000, 1, fmtp));
            }
        }
        return List.copyOf(result);
    }

    /// {@return whether the encoding name equals `encoding`, ignoring case as media type names require}
    ///
    /// @param encoding the encoding name to compare with
    /// @spec https://www.rfc-editor.org/rfc/rfc4855.html RFC 4855: Media Type Registration of RTP Payload Formats
    public boolean is(String encoding) {
        return name.equalsIgnoreCase(encoding);
    }

    /// {@return the `a=rtpmap` value of this format, `<pt> <name>/<clock>`, with a `/<channels>` suffix when there
    /// is more than one channel}
    public String rtpmapValue() {
        return payloadType + " " + name + "/" + clockRate + (channels > 1 ? "/" + channels : "");
    }

    /// {@return the format parameters of the `a=fmtp` line, or an empty optional when the format has none}
    public Optional<String> fmtp() {
        return Optional.ofNullable(parameters);
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
