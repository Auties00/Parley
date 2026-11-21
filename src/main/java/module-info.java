/// Defines Parley, a pure-Java, codec-agnostic WebRTC stack: the W3C peer connection with its JSEP offer/answer
/// engine, ICE with STUN and TURN, DTLS 1.2 and 1.3 keying SRTP, RTP and RTCP with retransmission, forward error
/// correction and congestion control, payload formats and jitter buffers, and SCTP data channels.
///
/// Parley carries media but never encodes it: the application writes encoded frames into a local track and reads
/// encoded frames from a remote track, so any codec rides on it, and an SFU can forward RTP packets without decoding
/// them. It depends only on the JDK and two pure-Java libraries, `srtp` (SRTP and SRTCP protection) and `sctp` (the
/// association under the data channels); it loads no native code.
///
/// The packages, from the application down to the wire:
///
/// | Package | Contents |
/// |---|---|
/// | [com.github.auties00.parley.peer] | [com.github.auties00.parley.peer.PeerConnection], transceivers, senders, receivers, tracks, transport views and events: the W3C object model and the JSEP engine |
/// | [com.github.auties00.parley.event] | The bounded, blocking event streams the application-level objects expose |
/// | [com.github.auties00.parley.stats] | The statistics records of `getStats()` |
/// | [com.github.auties00.parley.sdp] | The session description model with typed attributes |
/// | [com.github.auties00.parley.datachannel] | SCTP over DTLS and the data channels on it |
/// | [com.github.auties00.parley.media] | Encoded frames, codecs and per-format frame metadata |
/// | [com.github.auties00.parley.payload] | RTP payload formats: packetizers and depacketizers per codec |
/// | [com.github.auties00.parley.jitter] | The audio playout buffer and the video frame assembler |
/// | [com.github.auties00.parley.cc] | Congestion control, pacing and bitrate allocation |
/// | [com.github.auties00.parley.rtp.session] | RTP sessions with their send and receive streams, BUNDLE demultiplexing and RTCP |
/// | [com.github.auties00.parley.rtp.rtcp] | RTCP packets and feedback messages |
/// | [com.github.auties00.parley.rtp.extension] | RTP header extensions |
/// | [com.github.auties00.parley.rtp] | RTP packets |
/// | [com.github.auties00.parley.transport] | SRTP-protected RTP transports, keyed by DTLS-SRTP or SDES |
/// | [com.github.auties00.parley.dtls] | DTLS 1.2 and 1.3 transports, certificates and fingerprints |
/// | [com.github.auties00.parley.ice] | ICE agents, full and lite, with candidate gathering (host, mDNS, server-reflexive, relayed, TCP), trickle, restarts and consent freshness |
/// | [com.github.auties00.parley.turn] | The TURN client: allocations, permissions and channels over UDP, TCP and TLS |
/// | [com.github.auties00.parley.stun] | STUN messages, attributes, long-term and short-term credentials, client transactions |
/// | [com.github.auties00.parley.net] | The network SPI every socket goes through, and its JDK implementation |
///
/// # Threading and logging
///
/// Parley starts its threads through the [java.util.concurrent.ThreadFactory] of the peer connection's configuration
/// (virtual threads by default), or of the [com.github.auties00.parley.net.NetworkStack] for the sockets' readers, so
/// the application decides how they are named and run; the one exception is the SCTP association's internal reader,
/// timer and writer threads, which the `sctp` library starts as virtual threads of its own. Every call that waits on
/// the network blocks the calling thread and takes a timeout or can be interrupted; nothing returns a future, and
/// events arrive through blocking [com.github.auties00.parley.event.EventStream]s. Parley logs through [System#getLogger(String)], under the name of the logging class,
/// and never logs key material or ICE credentials.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3711.html RFC 3711: The Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html RFC 8831: WebRTC Data Channels
module com.github.auties00.parley {
    requires transitive com.github.auties00.srtp;
    requires com.github.auties00.sctp;

    exports com.github.auties00.parley.peer;
    exports com.github.auties00.parley.event;
    exports com.github.auties00.parley.stats;
    exports com.github.auties00.parley.sdp;
    exports com.github.auties00.parley.datachannel;
    exports com.github.auties00.parley.media;
    exports com.github.auties00.parley.payload;
    exports com.github.auties00.parley.jitter;
    exports com.github.auties00.parley.cc;
    exports com.github.auties00.parley.rtp.session;
    exports com.github.auties00.parley.rtp.rtcp;
    exports com.github.auties00.parley.rtp.extension;
    exports com.github.auties00.parley.rtp;
    exports com.github.auties00.parley.transport;
    exports com.github.auties00.parley.dtls;
    exports com.github.auties00.parley.ice;
    exports com.github.auties00.parley.turn;
    exports com.github.auties00.parley.stun;
    exports com.github.auties00.parley.net;
}
