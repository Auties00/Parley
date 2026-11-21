/// Provides [RtcTransport], which carries the SRTP media of one session over a single UDP socket: it gathers host
/// candidates, runs ICE and a DTLS-SRTP handshake (or takes SDES keys), demultiplexes every datagram the socket
/// receives, and protects and unprotects RTP and RTCP.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
package com.github.auties00.parley.transport;
