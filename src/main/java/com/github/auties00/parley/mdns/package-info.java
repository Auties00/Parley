/// Provides the multicast DNS pieces of mDNS ICE candidates: the [MdnsResponder] that answers for the
/// `<uuid>.local` names hiding local host addresses, and the [MdnsResolver] that resolves the names of remote
/// candidates with one-shot queries.
///
/// The package is not exported: the ICE agent uses it when its host candidate policy is
/// `HostCandidatePolicy.MDNS` and when a remote candidate carries a `.local` address.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc6762.html RFC 6762: Multicast DNS
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03 draft-ietf-mmusic-mdns-ice-candidates-03: Using Multicast DNS to protect privacy when exposing ICE candidates
package com.github.auties00.parley.mdns;
