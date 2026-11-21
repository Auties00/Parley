package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.event.EventStream;

import java.security.cert.X509Certificate;
import java.util.List;

/// A read-only view of a DTLS transport of a peer connection, the W3C `RTCDtlsTransport`: the transport the RTP of
/// a sender or receiver, or the SCTP association of the data channels, runs over.
///
/// The view reads the live transport: each call returns the current value. A connection bundling every section has
/// one; [RtpSender#transport()], [RtpReceiver#transport()] and [PeerSctpTransport#transport()] return it.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
public sealed interface PeerDtlsTransport permits PeerDtlsTransportView {
    /// {@return the ICE transport the DTLS transport runs over}
    PeerIceTransport iceTransport();

    /// {@return the DTLS state}
    DtlsState state();

    /// {@return the certificate chain the peer presented, the W3C `getRemoteCertificates`, leaf first; empty before
    /// the handshake completes}
    List<X509Certificate> remoteCertificates();

    /// {@return a stream of the DTLS state changes, the W3C `statechange` event; a change to `FAILED` stands for the
    /// W3C `error` event}
    ///
    /// The first stream opened also gets the changes raised since the transport was created; the streams end when
    /// the transport closes.
    EventStream<DtlsState> events();
}
