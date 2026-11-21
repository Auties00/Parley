package com.github.auties00.parley.ice;

/// The role of an ICE agent in a session: the controlling agent nominates the candidate pair, the controlled agent
/// follows.
///
/// The offerer starts as controlling and the answerer as controlled, unless one of them is a lite agent, which is
/// always controlled. When both claim the same role, the tie-breakers in their checks decide (RFC 8445 section
/// 7.3.1.1).
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
public enum IceRole {
    /// The agent that nominates the pair.
    CONTROLLING,

    /// The agent that accepts the peer's nomination.
    CONTROLLED;

    /// {@return the other role}
    public IceRole opposite() {
        return this == CONTROLLING ? CONTROLLED : CONTROLLING;
    }
}
