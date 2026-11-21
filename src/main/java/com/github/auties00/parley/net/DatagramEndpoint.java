package com.github.auties00.parley.net;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/// A bound UDP socket, as a [NetworkStack] opens it.
///
/// One thread reads with [#receive(ByteBuffer)] while others send; implementations are safe for that use.
public interface DatagramEndpoint extends AutoCloseable {
    /// {@return the local address and port the endpoint is bound to}
    InetSocketAddress localAddress();

    /// Sends one datagram.
    ///
    /// The datagram is the buffer's remaining bytes; on return the buffer's position has advanced past them and the
    /// caller may reuse it.
    ///
    /// @param datagram the datagram
    /// @param remote   the destination, resolved
    /// @throws IOException if the endpoint is closed or the network refused the datagram
    void send(ByteBuffer datagram, InetSocketAddress remote) throws IOException;

    /// Receives one datagram, blocking until one arrives.
    ///
    /// The datagram is written at the buffer's position, which advances past it; bytes that do not fit in the
    /// buffer's remaining space are discarded.
    ///
    /// @param destination the buffer to fill
    /// @return the address the datagram came from
    /// @throws IOException if the endpoint is closed, before or while the call blocks
    InetSocketAddress receive(ByteBuffer destination) throws IOException;

    /// Marks every datagram sent from now on with a Differentiated Services code point, as RFC 8837 maps WebRTC's
    /// `networkPriority` to one.
    ///
    /// The code point fills the upper six bits of the IPv4 TOS byte or the IPv6 traffic class; the two ECN bits are
    /// left zero. Platforms may ignore the request (Windows does without a QoS policy) or refuse it, which the
    /// result reports; datagrams are sent either way.
    ///
    /// @implSpec The default implementation does nothing and returns `false`.
    ///
    /// @param dscp the code point, `0..63`; `0` is the default (best effort)
    /// @return whether the endpoint accepted the marking
    /// @throws IllegalArgumentException if `dscp` is out of range
    /// @spec https://www.rfc-editor.org/rfc/rfc8837.html RFC 8837: Differentiated Services Code Point (DSCP) Packet Markings for WebRTC QoS
    /// @spec https://www.rfc-editor.org/rfc/rfc2474.html RFC 2474: Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers
    default boolean setTrafficClass(int dscp) {
        if (dscp < 0 || dscp > 63) {
            throw new IllegalArgumentException("dscp must be in 0..63: " + dscp);
        }
        return false;
    }

    /// Closes the endpoint; a thread blocked in [#receive(ByteBuffer)] fails with an [IOException]. Calling it again
    /// has no effect.
    @Override
    void close();
}
