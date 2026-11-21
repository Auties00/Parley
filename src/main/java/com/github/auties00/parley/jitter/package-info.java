/// Turns the RTP packets of an incoming stream, in network order and timing, into the frames a decoder consumes:
/// [AudioPlayoutBuffer] paces audio frames out at their playout instants with an adaptive delay, and
/// [VideoFrameAssembler] groups video packets into frames and releases them once they are decodable, asking the
/// sender for retransmissions and keyframes when packets are lost. Both date each frame on the sender's capture clock,
/// honour the `playout-delay` bounds the sender asks for, and can join a [SyncGroup] that aligns the playout of the
/// audio and video streams of one sender.
///
/// Both take packets from the thread that receives them and hand frames out through blocking calls on the thread that
/// decodes, so they suit one virtual thread per direction. Both measure time with a
/// [MonotonicClock][com.github.auties00.parley.net.MonotonicClock], which tests replace with a manual one.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
package com.github.auties00.parley.jitter;
