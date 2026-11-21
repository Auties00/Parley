/// Provides the secure media path: [RtpTransport] and its implementation [SrtpTransport], which protect RTP and RTCP
/// with SRTP keyed by DTLS-SRTP or SDES, and [MediaTransport], which ties ICE or a fixed UDP address, the keying and
/// the protection together for applications that do not use the W3C object model.
///
/// Every datagram on the media path is classified by its first byte (RFC 7983): STUN to ICE, DTLS to the
/// [com.github.auties00.parley.dtls.DtlsTransport], RTP and RTCP to the SRTP layer.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
/// @spec https://www.rfc-editor.org/rfc/rfc9443.html RFC 9443: Multiplexing Scheme Updates for QUIC
/// @spec https://www.rfc-editor.org/rfc/rfc3711.html RFC 3711: The Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
/// @spec https://www.rfc-editor.org/rfc/rfc8858.html RFC 8858: Indicating Exclusive Support of RTP and RTP Control Protocol (RTCP) Multiplexing Using the Session Description Protocol (SDP)
package com.github.auties00.parley.transport;
