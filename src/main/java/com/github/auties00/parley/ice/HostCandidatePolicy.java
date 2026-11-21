package com.github.auties00.parley.ice;

/// How an ICE agent exposes its host candidates to the peer.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03 draft-ietf-mmusic-mdns-ice-candidates-03: Using Multicast DNS to protect privacy when exposing ICE candidates
public enum HostCandidatePolicy {
    /// Host candidates carry their IP addresses.
    EXPOSE,

    /// Host candidates carry a fresh `<uuid>.local` name per address, which the agent answers multicast DNS queries
    /// for, so only peers on the local link can learn the address. Server-reflexive candidates then carry the related
    /// address `0.0.0.0` (or `::`) port `9`.
    MDNS,

    /// Host candidates are used as the base of server-reflexive and peer-reflexive candidates but never signalled;
    /// server-reflexive candidates carry the related address `0.0.0.0` (or `::`) port `9`.
    NONE
}
