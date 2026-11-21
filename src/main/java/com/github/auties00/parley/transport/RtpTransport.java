package com.github.auties00.parley.transport;

import com.github.auties00.parley.net.PacketReceiver;

import java.io.IOException;
import java.nio.ByteBuffer;

/// SRTP-protected RTP and RTCP over one datagram path: plain packets go in and come out, protection happens in
/// between.
///
/// RTP and RTCP share the path (`rtcp-mux`); a received packet whose second byte is 192 to 223 is RTCP, anything else
/// RTP. Reduced-size RTCP (a compound packet that does not start with a sender or receiver report) is accepted as
/// any other RTCP.
///
/// # Buffers
///
/// [#sendRtp(ByteBuffer)] and [#sendRtcp(ByteBuffer)] protect the packet in place when the buffer is a writable heap
/// buffer with at least [#protectionOverhead()] bytes of capacity after its limit, overwriting the packet and the
/// bytes after it; otherwise they protect a copy and leave the buffer untouched. The buffer's position and limit never
/// change, and the caller may reuse it once the call returns. Receivers get a buffer positioned at the plain
/// packet, valid only during the call.
///
/// # Threading
///
/// Receivers are called on the path's reader thread. Sends may come from any thread: the transport serializes
/// protection, so the packets of each SSRC, one ordered SRTP stream, reach the path in the order of their SRTP indexes,
/// and it serializes the unprotection of each received stream.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3711.html RFC 3711: The Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
public sealed interface RtpTransport extends AutoCloseable permits SrtpTransport {
    /// Protects and sends one RTP packet.
    ///
    /// @param plainRtp the packet between position and limit
    /// @throws java.nio.channels.ClosedChannelException if the transport is not keyed yet or is closed
    /// @throws IOException                              if protection or the path fails
    void sendRtp(ByteBuffer plainRtp) throws IOException;

    /// Protects and sends one compound RTCP packet.
    ///
    /// @param plainCompoundRtcp the compound packet between position and limit
    /// @throws java.nio.channels.ClosedChannelException if the transport is not keyed yet or is closed
    /// @throws IOException                              if protection or the path fails
    void sendRtcp(ByteBuffer plainCompoundRtcp) throws IOException;

    /// Sets the receiver of unprotected RTP packets, replacing the previous one.
    ///
    /// @param receiver the receiver
    void setRtpReceiver(PacketReceiver receiver);

    /// Sets the receiver of unprotected compound RTCP packets, replacing the previous one.
    ///
    /// @param receiver the receiver
    void setRtcpReceiver(PacketReceiver receiver);

    /// {@return the spare bytes a buffer needs after its limit for [#sendRtp(ByteBuffer)] and
    /// [#sendRtcp(ByteBuffer)] to protect it in place: the largest of the RTP and RTCP expansions}
    int protectionOverhead();

    /// {@return a snapshot of the counters}
    RtpTransportStatistics statistics();

    /// Stops the transport and wipes its keys; the path underneath stays open. Calling this method again has no
    /// effect.
    @Override
    void close();
}
