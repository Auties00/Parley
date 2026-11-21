package com.github.auties00.parley.ice;

/// The type of an ICE candidate.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
public enum IceCandidateType {
    /// A host candidate, an address of a local interface.
    HOST("host", 126),

    /// A server-reflexive candidate, the address a STUN server saw.
    SERVER_REFLEXIVE("srflx", 100),

    /// A peer-reflexive candidate, an address learned from a connectivity check.
    PEER_REFLEXIVE("prflx", 110),

    /// A relayed candidate, an address allocated on a TURN server.
    RELAY("relay", 0);

    /// The `typ` token.
    private final String token;

    /// The type preference RFC 8445 section 5.1.2.2 recommends for UDP candidates of the type.
    private final int typePreference;

    /// Creates a type.
    IceCandidateType(String token, int typePreference) {
        this.token = token;
        this.typePreference = typePreference;
    }

    /// {@return the `typ` token of the `candidate` attribute, such as `srflx`}
    public String token() {
        return token;
    }

    /// {@return the type preference RFC 8445 recommends for a UDP candidate of this type, `0..126`}
    public int typePreference() {
        return typePreference;
    }

    /// {@return the type named by a `typ` token}
    ///
    /// @param token the token
    /// @throws IllegalArgumentException if the token names no candidate type
    public static IceCandidateType ofToken(String token) {
        for (var type : values()) {
            if (type.token.equals(token)) {
                return type;
            }
        }
        throw new IllegalArgumentException("unknown candidate type: " + token);
    }
}
