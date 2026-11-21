package com.github.auties00.parley.sdp;

import java.util.Objects;
import java.util.Optional;

/// The `o=` origin line of a session description, which names the session and its version.
///
/// ```text
/// o=- 4611731400430051336 2 IN IP4 127.0.0.1
/// ```
///
/// JSEP fixes the session id for the lifetime of a peer connection and increments the version each time a description
/// differs from the previous one.
///
/// @param username       the user name, `-` when there is none
/// @param sessionId      the numeric session id, kept as written (it may exceed 64 bits)
/// @param sessionVersion the session version, at least `0`
/// @param networkType    the network type, `IN`
/// @param addressType    the address type, `IP4` or `IP6`
/// @param address        the unicast address of the originating host
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public record Origin(String username, String sessionId, long sessionVersion, String networkType, String addressType,
                     String address) {
    /// Creates an origin line.
    ///
    /// @param username       the user name
    /// @param sessionId      the session id
    /// @param sessionVersion the session version
    /// @param networkType    the network type
    /// @param addressType    the address type
    /// @param address        the address
    /// @throws IllegalArgumentException if a token is empty or holds whitespace, or `sessionVersion` is negative
    public Origin {
        for (var token : new String[]{username, sessionId, networkType, addressType, address}) {
            Objects.requireNonNull(token, "origin tokens cannot be null");
            if (token.isEmpty() || token.chars().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException("malformed origin token: '" + token + "'");
            }
        }
        if (sessionVersion < 0) {
            throw new IllegalArgumentException("negative session version: " + sessionVersion);
        }
    }

    /// {@return the origin of an `o=` value, or an empty optional when it does not have six well-formed tokens}
    ///
    /// @param value the text after `o=`
    public static Optional<Origin> parse(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        var tokens = SdpPatterns.SPACES.split(value.trim());
        if (tokens.length != 6) {
            return Optional.empty();
        }
        try {
            return Optional.of(new Origin(tokens[0], tokens[1], Long.parseLong(tokens[2]), tokens[3], tokens[4],
                    tokens[5]));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    /// {@return a copy of this origin with another session version}
    ///
    /// @param version the new session version
    public Origin withSessionVersion(long version) {
        return new Origin(username, sessionId, version, networkType, addressType, address);
    }

    /// {@return the `o=` line of this origin}
    public SdpLine toLine() {
        return new SdpLine('o', username + ' ' + sessionId + ' ' + sessionVersion + ' ' + networkType + ' '
                + addressType + ' ' + address);
    }
}
