package com.github.auties00.parley.sdp;

import java.util.Objects;
import java.util.Optional;

/// One `<type>=<value>` line of a session description.
///
/// The type is the single character before the equals sign and the value is everything after it, kept verbatim. An
/// attribute line (`a=`) splits further into a name and an optional value at the first colon:
///
/// ```text
/// a=rtpmap:111 opus/48000/2     name "rtpmap", value "111 opus/48000/2"
/// a=rtcp-mux                    name "rtcp-mux", no value
/// ```
///
/// @param type  the line type character, such as `'v'`, `'o'`, `'m'` or `'a'`
/// @param value the text after the equals sign, without the line terminator
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
public record SdpLine(char type, String value) {
    /// Creates a line.
    ///
    /// @param type  the line type character
    /// @param value the text after the equals sign
    /// @throws IllegalArgumentException if `value` holds a line break
    public SdpLine {
        Objects.requireNonNull(value, "value cannot be null");
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("SDP line value holds a line break");
        }
    }

    /// {@return an attribute line with a name and a value, `a=name:value`}
    ///
    /// @param name  the attribute name
    /// @param value the attribute value
    /// @see #flag(String)
    public static SdpLine attribute(String name, String value) {
        Objects.requireNonNull(name, "name cannot be null");
        Objects.requireNonNull(value, "value cannot be null");
        return new SdpLine('a', name + ':' + value);
    }

    /// {@return a property attribute line, which has a name and no value, `a=name`}
    ///
    /// @param name the attribute name
    /// @see #attribute(String, String)
    public static SdpLine flag(String name) {
        return new SdpLine('a', Objects.requireNonNull(name, "name cannot be null"));
    }

    /// {@return whether this is an `a=` line whose attribute name equals `name`}
    ///
    /// The comparison is case-sensitive, as RFC 8866 section 5.13 requires.
    ///
    /// @param name the attribute name
    public boolean isAttribute(String name) {
        return type == 'a' && name.equals(attributeName());
    }

    /// {@return the attribute name of an `a=` line: the value up to the first colon, or the whole value when it has
    /// none}
    ///
    /// The result is meaningful only for an attribute line; for any other type it is computed from the value all
    /// the same.
    public String attributeName() {
        var colon = value.indexOf(':');
        return colon < 0 ? value : value.substring(0, colon);
    }

    /// {@return the attribute value of an `a=` line: the value after the first colon, or an empty optional for a
    /// property attribute}
    public Optional<String> attributeValue() {
        var colon = value.indexOf(':');
        return colon < 0 ? Optional.empty() : Optional.of(value.substring(colon + 1));
    }

    /// {@return the line as it appears in a session description, `type=value`, without the line terminator}
    @Override
    public String toString() {
        return type + "=" + value;
    }
}
