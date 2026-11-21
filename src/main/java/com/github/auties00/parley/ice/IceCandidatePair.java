package com.github.auties00.parley.ice;

import java.util.Objects;

/// A local and a remote candidate an ICE agent checks connectivity between.
///
/// @param local  the local candidate; for a pair learned from a check, the peer-reflexive candidate the check
///               revealed
/// @param remote the remote candidate
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
public record IceCandidatePair(IceCandidate local, IceCandidate remote) {
    /// Creates a pair.
    ///
    /// @param local  the local candidate
    /// @param remote the remote candidate
    public IceCandidatePair {
        Objects.requireNonNull(local, "local cannot be null");
        Objects.requireNonNull(remote, "remote cannot be null");
    }

    /// {@return the pair priority, `2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0)`, where `G` is the priority of
    /// the controlling agent's candidate and `D` the controlled agent's}
    ///
    /// @param role the role of the local agent
    /// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
    public long priority(IceRole role) {
        return priority(role == IceRole.CONTROLLING ? local.priority() : remote.priority(),
                role == IceRole.CONTROLLING ? remote.priority() : local.priority());
    }

    /// {@return the pair priority of a controlling candidate priority `g` and a controlled one `d`}
    static long priority(long g, long d) {
        return (Math.min(g, d) << 32) + 2 * Math.max(g, d) + (g > d ? 1 : 0);
    }

    /// {@return the local and remote candidates}
    @Override
    public String toString() {
        return "IceCandidatePair[" + local.address() + ":" + local.port() + " " + local.type().token()
                + " -> " + remote.address() + ":" + remote.port() + " " + remote.type().token() + "]";
    }
}
