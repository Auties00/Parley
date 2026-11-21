package com.github.auties00.parley.sdp;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// A parsed session description: its session-level lines and its media sections.
///
/// [#parse(String)] accepts `CRLF` and bare `LF` line endings, skips blank lines and keeps every other line
/// verbatim, so [#encode()] reproduces the description with `CRLF` endings. The parser is lenient about line order
/// and unknown line types, as the offer/answer model asks of a receiver; it rejects only a line without a `type=`
/// prefix and a malformed `m=` line. A description is built by hand from [SdpLine]s and [MediaDescription]s:
///
/// {@snippet lang = java :
/// var audio = new MediaDescription("audio", 4000, "RTP/AVP", List.of("0"), List.of(
///         new SdpLine('c', "IN IP4 192.0.2.10"),
///         SdpLine.attribute("rtpmap", "0 PCMU/8000"),
///         SdpLine.flag("sendrecv")));
/// var offer = new SessionDescription(List.of(
///         new SdpLine('v', "0"),
///         new SdpLine('o', "- 1 1 IN IP4 192.0.2.10"),
///         new SdpLine('s', "-"),
///         new SdpLine('t', "0 0")), List.of(audio));
/// String text = offer.encode();
/// }
///
/// @param lines the session-level lines, from `v=` up to the first `m=` line
/// @param media the media sections, in order
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
public record SessionDescription(List<SdpLine> lines, List<MediaDescription> media) {
    /// Creates a description, copying its lists.
    ///
    /// @param lines the session-level lines
    /// @param media the media sections
    /// @throws NullPointerException if either list or one of its elements is `null`
    public SessionDescription {
        lines = List.copyOf(lines);
        media = List.copyOf(media);
    }

    /// Parses a session description.
    ///
    /// @param text the description, with `CRLF` or `LF` line endings
    /// @return the parsed description
    /// @throws IllegalArgumentException if a line is not of the form `<type>=<value>` or an `m=` line is malformed
    public static SessionDescription parse(String text) {
        Objects.requireNonNull(text, "text cannot be null");
        var sessionLines = new ArrayList<SdpLine>();
        var sections = new ArrayList<MediaDescription>();
        String mediaValue = null;
        var mediaLines = new ArrayList<SdpLine>();
        for (var raw : text.split("\r?\n")) {
            var line = raw.strip();
            if (line.isEmpty()) {
                continue;
            }
            if (line.length() < 2 || line.charAt(1) != '=') {
                throw new IllegalArgumentException("malformed SDP line: " + line);
            }
            var parsed = new SdpLine(line.charAt(0), line.substring(2));
            if (parsed.type() == 'm') {
                if (mediaValue != null) {
                    sections.add(MediaDescription.parse(mediaValue, mediaLines));
                    mediaLines = new ArrayList<>();
                }
                mediaValue = parsed.value();
            } else if (mediaValue == null) {
                sessionLines.add(parsed);
            } else {
                mediaLines.add(parsed);
            }
        }
        if (mediaValue != null) {
            sections.add(MediaDescription.parse(mediaValue, mediaLines));
        }
        return new SessionDescription(sessionLines, sections);
    }

    /// {@return the value of the first session-level attribute named `name`: an empty string for a property
    /// attribute, or an empty optional when the session level has no such attribute}
    ///
    /// @param name the attribute name, compared case-sensitively
    public Optional<String> attribute(String name) {
        for (var line : lines) {
            if (line.isAttribute(name)) {
                return Optional.of(line.attributeValue().orElse(""));
            }
        }
        return Optional.empty();
    }

    /// {@return the value of an attribute of a media section, falling back to the session level, or an empty
    /// optional when neither level carries it}
    ///
    /// Attributes such as `ice-ufrag`, `fingerprint` and `setup` may appear at either level, the media level taking
    /// precedence.
    ///
    /// @param section the media section, normally one of [#media()]
    /// @param name    the attribute name, compared case-sensitively
    public Optional<String> attribute(MediaDescription section, String name) {
        return section.attribute(name).or(() -> attribute(name));
    }

    /// {@return the first media section of a media type, or an empty optional when there is none}
    ///
    /// @param mediaType the media type, such as `audio`, compared case-sensitively
    public Optional<MediaDescription> firstMedia(String mediaType) {
        return media.stream()
                .filter(section -> section.media().equals(mediaType))
                .findFirst();
    }

    /// {@return the connection address of a media section, falling back to the session-level `c=` line, or an empty
    /// optional when neither level has one}
    ///
    /// @param section the media section, normally one of [#media()]
    /// @see MediaDescription#connectionAddress()
    public Optional<String> connectionAddress(MediaDescription section) {
        return section.connectionAddress().or(() -> {
            for (var line : lines) {
                if (line.type() == 'c') {
                    return connectionAddressOf(line.value());
                }
            }
            return Optional.empty();
        });
    }

    /// {@return the description text with `CRLF` line endings, a terminator after the last line included}
    public String encode() {
        var builder = new StringBuilder();
        for (var line : lines) {
            builder.append(line).append("\r\n");
        }
        for (var section : media) {
            builder.append("m=").append(section.mediaLineValue()).append("\r\n");
            for (var line : section.lines()) {
                builder.append(line).append("\r\n");
            }
        }
        return builder.toString();
    }

    /// {@return the same text as [#encode()]}
    @Override
    public String toString() {
        return encode();
    }

    /// {@return the address token of a `c=` value such as `IN IP4 203.0.113.7`: its third token without a multicast
    /// `/ttl` suffix, or an empty optional when the value has fewer than three tokens}
    static Optional<String> connectionAddressOf(String value) {
        var tokens = value.trim().split(" +");
        if (tokens.length < 3) {
            return Optional.empty();
        }
        var address = tokens[2];
        var slash = address.indexOf('/');
        return Optional.of(slash < 0 ? address : address.substring(0, slash));
    }
}
