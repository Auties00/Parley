package com.github.auties00.parley.ice;

import java.util.Locale;

/// The connection direction of a TCP candidate.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
public enum IceTcpType {
    /// The candidate opens connections and never accepts them; its port is `9`.
    ACTIVE,

    /// The candidate accepts connections and never opens them.
    PASSIVE,

    /// The candidate attempts simultaneous open; Parley parses it but forms no pairs with it.
    SO;

    /// {@return the `tcptype` token, such as `passive`}
    public String token() {
        return name().toLowerCase(Locale.ROOT);
    }

    /// {@return the type named by a `tcptype` token, case-insensitively}
    ///
    /// @param token the token
    /// @throws IllegalArgumentException if the token names no TCP type
    public static IceTcpType ofToken(String token) {
        return switch (token.toLowerCase(Locale.ROOT)) {
            case "active" -> ACTIVE;
            case "passive" -> PASSIVE;
            case "so" -> SO;
            default -> throw new IllegalArgumentException("unknown tcptype: " + token);
        };
    }
}
