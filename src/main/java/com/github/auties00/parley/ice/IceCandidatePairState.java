package com.github.auties00.parley.ice;

/// The state of a candidate pair in the checklist.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
public enum IceCandidatePairState {
    /// The pair waits for a pair with the same foundation to succeed before it is checked.
    FROZEN,

    /// The pair will be checked when its turn comes.
    WAITING,

    /// A check of the pair is outstanding.
    IN_PROGRESS,

    /// A check of the pair produced a valid pair.
    SUCCEEDED,

    /// A check of the pair failed or timed out, or consent on it expired.
    FAILED
}
