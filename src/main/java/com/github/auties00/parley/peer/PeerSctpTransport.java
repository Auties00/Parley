package com.github.auties00.parley.peer;

import com.github.auties00.parley.datachannel.SctpTransportState;

import java.util.OptionalInt;

/// A read-only view of the SCTP association that carries a peer connection's data channels, the W3C
/// `RTCSctpTransport`.
///
/// The view reads the live association: each call returns the current value. [PeerConnection#sctp()] returns it
/// once a data section is negotiated; when the peer closes the association and a later negotiation restarts it, the
/// view follows the new association.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html RFC 8831: WebRTC Data Channels
public sealed interface PeerSctpTransport permits PeerSctpTransportView {
    /// {@return the DTLS transport the association runs over}
    PeerDtlsTransport transport();

    /// {@return the state of the association}
    SctpTransportState state();

    /// {@return the largest message a data channel can send, in bytes: the smaller of the local limit and the
    /// peer's `a=max-message-size`, the W3C `maxMessageSize`}
    long maxMessageSize();

    /// {@return the most data channels that can be open at once, the W3C `maxChannels`, or an empty optional before
    /// the association is established}
    OptionalInt maxChannels();
}
