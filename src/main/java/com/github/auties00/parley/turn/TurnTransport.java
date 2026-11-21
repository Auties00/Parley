package com.github.auties00.parley.turn;

/// The transport between a TURN client and its server.
///
/// The relayed transport between the server and peers is always UDP.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc7065.html RFC 7065: Traversal Using Relays around NAT (TURN) Uniform Resource Identifiers
public enum TurnTransport {
    /// UDP, the default of `turn:` URIs.
    UDP,

    /// TCP, `turn:` with `?transport=tcp`.
    TCP,

    /// TLS over TCP, the default of `turns:` URIs.
    TLS;

    /// {@return whether the transport is a byte stream, which frames messages and never retransmits requests}
    public boolean isStream() {
        return this != UDP;
    }
}
