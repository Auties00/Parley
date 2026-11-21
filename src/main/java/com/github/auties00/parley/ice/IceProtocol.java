package com.github.auties00.parley.ice;

import java.util.Locale;

/// The transport protocol of an ICE candidate.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
public enum IceProtocol {
    /// UDP.
    UDP,

    /// TCP, with RFC 4571 framing.
    TCP;

    /// {@return the protocol token of the `candidate` attribute, `udp` or `tcp`}
    public String token() {
        return name().toLowerCase(Locale.ROOT);
    }

    /// {@return the protocol named by a `candidate` attribute token, case-insensitively}
    ///
    /// @param token the token
    /// @throws IllegalArgumentException if the token is neither `udp` nor `tcp`
    public static IceProtocol ofToken(String token) {
        return switch (token.toLowerCase(Locale.ROOT)) {
            case "udp" -> UDP;
            case "tcp" -> TCP;
            default -> throw new IllegalArgumentException("unknown candidate transport: " + token);
        };
    }
}
