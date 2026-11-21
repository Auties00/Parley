package com.github.auties00.parley.ice;

import com.github.auties00.parley.net.DatagramTransport;

import java.util.List;
import java.util.Optional;

/// An ICE transport for one component: the [DatagramTransport] that carries the datagrams of a BUNDLE group over the
/// selected candidate pair, with the ICE state behind it.
///
/// [#send(java.nio.ByteBuffer)] sends on the selected pair and fails before one is selected or after consent
/// expired. STUN connectivity checks, consent checks and TURN framing are handled inside the transport; every other
/// datagram that arrives from a remote candidate goes to the receiver.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public sealed interface IceTransport extends DatagramTransport permits IceAgent {
    /// {@return the current role, which a role conflict can change}
    IceRole role();

    /// {@return the transport state}
    IceTransportState state();

    /// {@return the gathering state}
    IceGatheringState gatheringState();

    /// {@return the local ICE parameters}
    IceParameters localParameters();

    /// {@return the remote ICE parameters, or an empty optional before they are set}
    Optional<IceParameters> remoteParameters();

    /// {@return the pair the transport sends on, or an empty optional before one is selected}
    Optional<IceCandidatePair> selectedPair();

    /// {@return the local candidates gathered so far, as signalled to the peer}
    List<IceCandidate> localCandidates();

    /// {@return the remote candidates known so far, signalled and peer-reflexive}
    List<IceCandidate> remoteCandidates();

    /// {@return a snapshot of the transport's counters}
    IceTransportStatistics statistics();
}
