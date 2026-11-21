/// Defines Parley, a pure-Java WebRTC transport stack: session descriptions, STUN and ICE, a DTLS 1.2 endpoint that
/// keys SRTP, RTP and RTCP framing, and a transport that runs them all over one UDP socket.
///
/// Parley carries media but never encodes it: it moves RTP packets whose payloads the application produces and
/// consumes, so any codec can ride on it. The one payload format it implements itself is G.711 (`PCMA` and `PCMU`),
/// whose companding is a table lookup rather than a codec. It depends only on the JDK and the pure-Java `srtp`
/// library, which protects the packets; it loads no native code.
///
/// The module exports six packages, from the wire formats up to the transport:
///
/// | Package | Contents |
/// |---|---|
/// | [com.github.auties00.parley.sdp] | The session description model of RFC 8866: [com.github.auties00.parley.sdp.SessionDescription], its media sections, RTP payload formats and SDES keys |
/// | [com.github.auties00.parley.stun] | STUN messages with the attributes ICE uses, `MESSAGE-INTEGRITY` and `FINGERPRINT` |
/// | [com.github.auties00.parley.ice] | A full ICE agent for one component, candidates and credentials |
/// | [com.github.auties00.parley.dtls] | A DTLS 1.2 client and server that negotiate `use_srtp` and export the SRTP master keys |
/// | [com.github.auties00.parley.rtp] | RTP packets, RTCP reports, G.711 and RFC 4733 telephone events |
/// | [com.github.auties00.parley.transport] | [com.github.auties00.parley.transport.RtcTransport], which ties them to one UDP socket |
///
/// # Threading and logging
///
/// Parley starts threads only in [com.github.auties00.parley.transport.RtcTransport], always through the
/// [java.util.concurrent.ThreadFactory] the application passes, so the application decides whether they are virtual
/// or platform threads and how they are named. Every blocking call takes a timeout. Parley logs through
/// [System#getLogger(String)], under the name of the logging class, and so through whatever backend the application
/// configures for the platform logger.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3711.html RFC 3711: The Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
module com.github.auties00.parley {
    requires transitive com.github.auties00.srtp;

    exports com.github.auties00.parley.sdp;
    exports com.github.auties00.parley.stun;
    exports com.github.auties00.parley.ice;
    exports com.github.auties00.parley.dtls;
    exports com.github.auties00.parley.rtp;
    exports com.github.auties00.parley.transport;
}
