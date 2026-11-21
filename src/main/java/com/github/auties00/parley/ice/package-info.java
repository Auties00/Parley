/// Provides Interactive Connectivity Establishment for one UDP component: the [IceAgent] that runs the connectivity
/// checks and consent freshness, the [IceCandidate]s and [IceCredentials] a session description carries, and the
/// [IceException] that reports a failed nomination.
///
/// The agent owns no socket: whoever owns the socket hands it the received STUN messages and gives it an
/// [IceAgent.DatagramSender] to answer through, so one socket can carry ICE together with DTLS and media.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
package com.github.auties00.parley.ice;
