/// Provides Interactive Connectivity Establishment: the [IceAgent] (full or lite) that gathers [IceCandidate]s,
/// runs the connectivity checks, selects an [IceCandidatePair] and keeps consent on it, exposed as the
/// [IceTransport] the DTLS and SRTP layers send their datagrams through.
///
/// The agent opens every socket through a [com.github.auties00.parley.net.NetworkStack]: UDP host candidates,
/// server-reflexive candidates from `stun:` servers, relayed candidates from `turn:` and `turns:` servers through
/// [com.github.auties00.parley.turn.TurnClient], ICE-TCP candidates, and `.local` names through multicast DNS. It
/// reports what happens as [IceEvent]s and its counters as [IceTransportStatistics]; the local and remote
/// [IceParameters] are the `a=ice-ufrag` and `a=ice-pwd` of the session descriptions.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8838.html RFC 8838: Trickle ICE: Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (ICE) Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
/// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
package com.github.auties00.parley.ice;
