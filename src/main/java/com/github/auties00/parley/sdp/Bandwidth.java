package com.github.auties00.parley.sdp;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// One `b=<type>:<value>` bandwidth line of a session or media section.
///
/// ```text
/// b=AS:2500        application-specific maximum, kilobits per second
/// b=TIAS:2500000   transport-independent application maximum, bits per second
/// ```
///
/// @param type  the bandwidth type, such as `AS`, `TIAS`, `CT`, `RR` or `RS`; compared case-sensitively
/// @param value the bandwidth value, at least `0`, in the unit the type defines
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc3890.html RFC 3890: A Transport Independent Bandwidth Modifier for the Session Description Protocol (SDP)
public record Bandwidth(String type, long value) {
    /// The application-specific maximum, in kilobits per second.
    public static final String AS = "AS";
    /// The transport-independent application maximum, in bits per second.
    public static final String TIAS = "TIAS";

    /// Creates a bandwidth line.
    ///
    /// @param type  the bandwidth type
    /// @param value the bandwidth value
    /// @throws IllegalArgumentException if `type` is empty or holds a colon or whitespace, or `value` is negative
    public Bandwidth {
        Objects.requireNonNull(type, "type cannot be null");
        if (type.isEmpty() || type.indexOf(':') >= 0 || type.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("malformed bandwidth type: " + type);
        }
        if (value < 0) {
            throw new IllegalArgumentException("negative bandwidth: " + value);
        }
    }

    /// {@return the bandwidth of a `b=` line value such as `AS:2500`, or an empty optional when the value is malformed}
    ///
    /// @param value the text after `b=`
    public static Optional<Bandwidth> parse(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        var colon = value.indexOf(':');
        if (colon <= 0) {
            return Optional.empty();
        }
        try {
            return Optional.of(new Bandwidth(value.substring(0, colon).trim(),
                    Long.parseLong(value.substring(colon + 1).trim())));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    /// {@return the bandwidth in bits per second for the `AS` and `TIAS` types (saturating at [Long#MAX_VALUE]), or an
    /// empty optional for any other type}
    public OptionalLong bitsPerSecond() {
        return switch (type) {
            case AS -> OptionalLong.of(value > Long.MAX_VALUE / 1000 ? Long.MAX_VALUE : value * 1000);
            case TIAS -> OptionalLong.of(value);
            default -> OptionalLong.empty();
        };
    }

    /// {@return the `b=` line of this bandwidth}
    public SdpLine toLine() {
        return new SdpLine('b', type + ':' + value);
    }
}
