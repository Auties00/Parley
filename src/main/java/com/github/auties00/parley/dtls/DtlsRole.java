package com.github.auties00.parley.dtls;

/// The role of an endpoint in a DTLS handshake.
///
/// A session description decides it through `a=setup` ([DtlsSetup]): the side that answers `active` is the client and
/// the side that answers `passive` the server.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
public enum DtlsRole {
    /// Sends the `ClientHello`.
    CLIENT,

    /// Answers the `ClientHello`.
    SERVER
}
