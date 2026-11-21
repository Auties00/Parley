package com.github.auties00.parley.ice;

import java.util.Locale;

/// The transport protocol of an ICE candidate, or of the connection to the TURN server of a relayed one.
///
/// A candidate itself is [#UDP] or [#TCP] (W3C `RTCIceProtocol`); [#TLS] appears only as the
/// [relay protocol][IceCandidate#relayProtocol()] of a candidate relayed through a `turns:` server (W3C
/// `RTCIceServerTransportProtocol`).
///
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public enum IceProtocol {
    /// UDP.
    UDP,

    /// TCP, with RFC 4571 framing.
    TCP,

    /// TLS over TCP, only as the protocol to a TURN server.
    TLS;

    /// {@return the protocol token, `udp`, `tcp` or `tls`}
    public String token() {
        return name().toLowerCase(Locale.ROOT);
    }

    /// {@return the protocol named by a token, case-insensitively}
    ///
    /// @param token the token
    /// @throws IllegalArgumentException if the token is none of `udp`, `tcp` and `tls`
    public static IceProtocol ofToken(String token) {
        return switch (token.toLowerCase(Locale.ROOT)) {
            case "udp" -> UDP;
            case "tcp" -> TCP;
            case "tls" -> TLS;
            default -> throw new IllegalArgumentException("unknown candidate transport: " + token);
        };
    }
}
