package com.github.auties00.parley.turn;

import java.util.Objects;

/// The long-term credential a TURN server authenticates a client with.
///
/// [#toString()] leaves the password out.
///
/// @param username the username
/// @param password the password
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public record TurnCredentials(String username, String password) {
    /// Creates credentials.
    ///
    /// @param username the username
    /// @param password the password
    public TurnCredentials {
        Objects.requireNonNull(username, "username cannot be null");
        Objects.requireNonNull(password, "password cannot be null");
    }

    /// {@return the username, without the password}
    @Override
    public String toString() {
        return "TurnCredentials[username=" + username + "]";
    }
}
