/// Provides DTLS-SRTP keying: [DtlsEndpoint], a DTLS 1.2 client and server that negotiates the `use_srtp`
/// extension and exports the SRTP master keys of both directions ([DtlsSrtpKeys]), the self-signed
/// [DtlsCertificate] each side authenticates through a session description fingerprint, and the [SrtpProfile]s it
/// negotiates.
///
/// The endpoint owns no socket either: it sends and receives through a [DtlsDatagramIo] its owner implements.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
package com.github.auties00.parley.dtls;
