/// Provides RTP and RTCP framing: [RtpPacket] with its fixed header, the compound reports of [RtcpPackets], and the
/// two payload formats simple enough to need no codec library, G.711 ([G711]) and RFC 4733 telephone events
/// ([TelephoneEvent]).
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3551.html RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
package com.github.auties00.parley.rtp;
