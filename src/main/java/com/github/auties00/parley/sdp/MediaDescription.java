package com.github.auties00.parley.sdp;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// One media section of a session description: its `m=` line and the lines after it, up to the next `m=` line.
///
/// The `m=` line splits into the media type, the transport port, the transport protocol and the format list:
///
/// ```text
/// m=audio 3480 UDP/TLS/RTP/SAVPF 111 126
/// ```
///
/// The other lines are kept in order and verbatim, so a parsed section encodes back to the same text. Attribute
/// lookups on a section see only the section's own lines; [SessionDescription#attribute(MediaDescription,String)]
/// falls back to the session level.
///
/// @param media    the media type, such as `audio` or `video`
/// @param port     the transport port, `0..65535`; `0` rejects the section in an answer. A port count
///                 (`3480/2`) is dropped on parse
/// @param protocol the transport protocol, such as `UDP/TLS/RTP/SAVPF` or `RTP/SAVP`
/// @param formats  the media formats; for RTP, the payload type numbers in preference order
/// @param lines    the lines that follow the `m=` line, in order
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
public record MediaDescription(String media, int port, String protocol, List<String> formats, List<SdpLine> lines) {
    /// Creates a media section, copying its lists.
    ///
    /// @param media    the media type
    /// @param port     the transport port
    /// @param protocol the transport protocol
    /// @param formats  the media formats
    /// @param lines    the lines that follow the `m=` line
    /// @throws IllegalArgumentException if `port` is outside `0..65535`
    public MediaDescription {
        Objects.requireNonNull(media, "media cannot be null");
        Objects.requireNonNull(protocol, "protocol cannot be null");
        formats = List.copyOf(formats);
        lines = List.copyOf(lines);
        if (port < 0 || port > 0xFFFF) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
    }

    /// Parses the value of an `m=` line together with the lines of its section.
    ///
    /// @param value the text after `m=`
    /// @param lines the lines of the section after the `m=` line
    /// @return the media section
    /// @throws IllegalArgumentException if the `m=` value has fewer than three tokens or a malformed port
    static MediaDescription parse(String value, List<SdpLine> lines) {
        var tokens = SdpPatterns.SPACES.split(value.trim());
        if (tokens.length < 3) {
            throw new IllegalArgumentException("malformed m= line: " + value);
        }
        var portToken = tokens[1];
        var slash = portToken.indexOf('/');
        int port;
        try {
            port = Integer.parseInt(slash < 0 ? portToken : portToken.substring(0, slash));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("malformed m= port: " + value, exception);
        }
        var formats = List.of(tokens).subList(3, tokens.length);
        return new MediaDescription(tokens[0], port, tokens[2], formats, lines);
    }

    /// {@return the value of the section's first attribute named `name`: an empty string for a property attribute,
    /// or an empty optional when the section has no such attribute}
    ///
    /// @param name the attribute name, compared case-sensitively
    /// @see SessionDescription#attribute(MediaDescription, String)
    public Optional<String> attribute(String name) {
        for (var line : lines) {
            if (line.isAttribute(name)) {
                return Optional.of(line.attributeValue().orElse(""));
            }
        }
        return Optional.empty();
    }

    /// {@return the unmodifiable values of every attribute of the section named `name`, in order; an empty string
    /// stands for a property attribute}
    ///
    /// @param name the attribute name, compared case-sensitively
    public List<String> attributes(String name) {
        var result = new ArrayList<String>();
        for (var line : lines) {
            if (line.isAttribute(name)) {
                result.add(line.attributeValue().orElse(""));
            }
        }
        return List.copyOf(result);
    }

    /// {@return whether the section carries at least one `a=name` line}
    ///
    /// @param name the attribute name, compared case-sensitively
    public boolean hasAttribute(String name) {
        return attribute(name).isPresent();
    }

    /// {@return the address of the section's own `c=` line, or an empty optional when it has none or the line has
    /// fewer than three tokens}
    ///
    /// A `c=` value has the form `IN IP4 203.0.113.7`; the address is its third token, without a multicast `/ttl`
    /// suffix.
    ///
    /// @see SessionDescription#connectionAddress(MediaDescription)
    public Optional<String> connectionAddress() {
        for (var line : lines) {
            if (line.type() == 'c') {
                return SessionDescription.connectionAddressOf(line.value());
            }
        }
        return Optional.empty();
    }

    /// {@return the unmodifiable typed attributes of the section's `a=` lines, in order}
    ///
    /// @see SdpAttribute#parse(SdpLine)
    public List<SdpAttribute> typedAttributes() {
        var result = new ArrayList<SdpAttribute>();
        for (var line : lines) {
            if (line.type() == 'a') {
                result.add(SdpAttribute.parse(line));
            }
        }
        return List.copyOf(result);
    }

    /// {@return the unmodifiable typed attributes of the section that are instances of `type`, in order}
    ///
    /// @param type the attribute record class, such as `SdpAttribute.Rtpmap.class`
    /// @param <T>  the attribute record type
    public <T extends SdpAttribute> List<T> attributes(Class<T> type) {
        Objects.requireNonNull(type, "type cannot be null");
        var result = new ArrayList<T>();
        for (var line : lines) {
            if (line.type() == 'a') {
                var attribute = SdpAttribute.parse(line);
                if (type.isInstance(attribute)) {
                    result.add(type.cast(attribute));
                }
            }
        }
        return List.copyOf(result);
    }

    /// {@return the first typed attribute of the section that is an instance of `type`, or an empty optional when
    /// there is none}
    ///
    /// @param type the attribute record class
    /// @param <T>  the attribute record type
    public <T extends SdpAttribute> Optional<T> attribute(Class<T> type) {
        Objects.requireNonNull(type, "type cannot be null");
        for (var line : lines) {
            if (line.type() == 'a') {
                var attribute = SdpAttribute.parse(line);
                if (type.isInstance(attribute)) {
                    return Optional.of(type.cast(attribute));
                }
            }
        }
        return Optional.empty();
    }

    /// {@return the identification tag of the section's `a=mid` line, or an empty optional when it has none or it
    /// is malformed}
    public Optional<String> mid() {
        return attribute(SdpAttribute.Mid.class).map(SdpAttribute.Mid::id);
    }

    /// {@return the direction of the section's first direction attribute, or an empty optional when it has none}
    ///
    /// A section without one inherits the session-level direction, and `SENDRECV` when that is absent too; see
    /// [SessionDescription#direction(MediaDescription)].
    public Optional<MediaDirection> direction() {
        return attribute(SdpAttribute.Direction.class).map(SdpAttribute.Direction::direction);
    }

    /// {@return the unmodifiable well-formed `b=` lines of the section, in order}
    public List<Bandwidth> bandwidths() {
        var result = new ArrayList<Bandwidth>();
        for (var line : lines) {
            if (line.type() == 'b') {
                Bandwidth.parse(line.value()).ifPresent(result::add);
            }
        }
        return List.copyOf(result);
    }

    /// {@return whether the section is rejected or disabled: its port is `0` and it is not marked `a=bundle-only`}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
    public boolean isRejected() {
        return port == 0 && !hasAttribute("bundle-only");
    }

    /// {@return a copy of this section with another port}
    ///
    /// @param newPort the port, `0..65535`
    /// @throws IllegalArgumentException if `newPort` is out of range
    public MediaDescription withPort(int newPort) {
        return new MediaDescription(media, newPort, protocol, formats, lines);
    }

    /// {@return a copy of this section with another format list}
    ///
    /// @param newFormats the formats
    public MediaDescription withFormats(List<String> newFormats) {
        return new MediaDescription(media, port, protocol, newFormats, lines);
    }

    /// {@return a copy of this section with other lines after the `m=` line}
    ///
    /// @param newLines the lines
    public MediaDescription withLines(List<SdpLine> newLines) {
        return new MediaDescription(media, port, protocol, formats, newLines);
    }

    /// {@return a copy of this section with `attribute` appended after its last line}
    ///
    /// @param attribute the attribute to append
    public MediaDescription withAttribute(SdpAttribute attribute) {
        var newLines = new ArrayList<>(lines);
        newLines.add(attribute.toLine());
        return withLines(newLines);
    }

    /// {@return a copy of this section without any `a=` line whose attribute name is `name`}
    ///
    /// @param name the attribute name, compared case-sensitively
    public MediaDescription withoutAttributes(String name) {
        Objects.requireNonNull(name, "name cannot be null");
        return withLines(lines.stream().filter(line -> !line.isAttribute(name)).toList());
    }

    /// {@return the `m=` line value of this section, `media port protocol formats...`}
    public String mediaLineValue() {
        var builder = new StringBuilder();
        builder.append(media).append(' ').append(port).append(' ').append(protocol);
        for (var format : formats) {
            builder.append(' ').append(format);
        }
        return builder.toString();
    }
}
