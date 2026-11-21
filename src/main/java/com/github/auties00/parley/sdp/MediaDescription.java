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
        var tokens = value.trim().split(" +");
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
