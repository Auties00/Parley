package com.github.auties00.parley.peer;

import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceCandidatePair;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceParameters;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.ice.IceTransportState;

import java.util.List;
import java.util.Optional;

/// A read-only view of the ICE transport under a peer connection's DTLS transport, the W3C `RTCIceTransport`.
///
/// The view reads the live transport: each call returns the current value. It is obtained from
/// [PeerDtlsTransport#iceTransport()]; Parley negotiates one component per transport (RTP and RTCP multiplexed), so
/// the W3C `component` is always `rtp`.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
public sealed interface PeerIceTransport permits PeerIceTransportView {
    /// {@return the role of the agent, controlling or controlled}
    IceRole role();

    /// {@return the ICE state}
    IceTransportState state();

    /// {@return the candidate gathering state}
    IceGatheringState gatheringState();

    /// {@return the local candidates gathered so far, the W3C `getLocalCandidates`}
    List<IceCandidate> localCandidates();

    /// {@return the remote candidates received so far, the W3C `getRemoteCandidates`}
    List<IceCandidate> remoteCandidates();

    /// {@return the pair carrying the traffic, the W3C `getSelectedCandidatePair`, or an empty optional before one
    /// is selected}
    Optional<IceCandidatePair> selectedCandidatePair();

    /// {@return the local username fragment and password, the W3C `getLocalParameters`}
    IceParameters localParameters();

    /// {@return the peer's username fragment and password, the W3C `getRemoteParameters`, or an empty optional
    /// before the remote description is applied}
    Optional<IceParameters> remoteParameters();

    /// {@return a stream of the transport's state, gathering state and selected pair changes}
    ///
    /// The first stream opened also gets the events raised since the transport was created; the streams end when
    /// the transport closes.
    EventStream<PeerIceTransportEvent> events();
}
