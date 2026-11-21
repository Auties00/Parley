/// Provides DTLS for WebRTC: [DtlsTransport], a DTLS 1.2 and 1.3 client and server over a datagram path that
/// negotiates the `use_srtp` extension and exports the SRTP keys of both directions ([DtlsSrtpKeys]), carries
/// application data for SCTP, and passes RTP and RTCP through; the [DtlsCertificate] each side authenticates with
/// and its [DtlsFingerprint]s; and the session description attributes of a DTLS association ([DtlsSetup],
/// [DtlsTlsId], [DtlsParameters]).
///
/// The implementation covers what WebRTC peers use: ECDHE over X25519, P-256 or P-384; ECDSA and RSA certificates;
/// the AES-GCM and ChaCha20-Poly1305 suites of both versions; the extended master secret; cookie exchanges;
/// retransmission with backoff, fragmentation and reordering; DTLS 1.3 acknowledgements and key updates. It never
/// resumes sessions, sends early data, negotiates connection ids or renegotiates: every WebRTC association starts
/// fresh with new certificates.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc5705.html RFC 5705: Keying Material Exporters for Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc7627.html RFC 7627: Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
/// @spec https://www.rfc-editor.org/rfc/rfc8422.html RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
/// @spec https://www.rfc-editor.org/rfc/rfc7905.html RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc8827.html RFC 8827: WebRTC Security Architecture
package com.github.auties00.parley.dtls;
