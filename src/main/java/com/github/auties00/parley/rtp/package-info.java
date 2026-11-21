/// Provides RTP packet framing: the zero-copy read-only [RtpPacket] view with its RFC 8285 header extension
/// elements, [RtpPacketWriter], which writes a packet into a buffer the caller owns, the detached [RtpHeader], and
/// the wrapping-counter helpers [SequenceNumbers], [SequenceUnwrapper] and [NtpTime].
///
/// RTCP lives in the `rtp.rtcp` subpackage, the typed header extensions in `rtp.extension`, and the per-stream
/// machinery (statistics, retransmission, BUNDLE demultiplexing) in `rtp.session`.
///
/// # Buffers
///
/// Every packet is a heap [java.nio.ByteBuffer] positioned at its first byte with its limit after its last. Views
/// never copy; a view of a received packet is valid only while its receive buffer is, which for a receiver callback
/// is the duration of the call.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
package com.github.auties00.parley.rtp;
