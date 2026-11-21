package com.github.auties00.parley.turn;

import java.util.Objects;

/// The long-term credential a TURN server authenticates a client with.
///
/// The username and password are prepared with the OpaqueString profile of RFC 8265 before the long-term key is
/// derived, as RFC 8489 sections 9.2.2 and 14.3 require (not the SASLprep of RFC 5389); a server still preparing
/// them with SASLprep derives the same key for every ASCII credential.
///
/// [#toString()] leaves the password out.
///
/// @param username the username
/// @param password the password
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc8265.html RFC 8265: Preparation, Enforcement, and Comparison of Internationalized Strings Representing Usernames and Passwords
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
