/// Provides RTCP: the sealed [RtcpPacket] hierarchy with one immutable record per packet type and feedback format,
/// and the compound and reduced-size codec ([RtcpPacket#parseCompound(java.nio.ByteBuffer)],
/// [RtcpPacket#encodeCompound(java.util.List, int)]).
///
/// The packets cover the RFC 3550 reports and descriptions, the RFC 3611 extended reports a receive-only peer measures
/// its round-trip time with, the RFC 4585 and RFC 5104 feedback messages that drive retransmission and keyframe
/// requests, and the three congestion control feedback formats browsers send: REMB, transport-wide feedback and
/// RFC 8888 feedback.
///
/// Parsing copies every byte a packet keeps, so a parsed packet outlives the receive buffer it came from.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3611.html RFC 3611: RTP Control Protocol Extended Reports (RTCP XR)
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
/// @spec https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03 RTCP message for Receiver Estimated Maximum Bitrate
package com.github.auties00.parley.rtp.rtcp;
