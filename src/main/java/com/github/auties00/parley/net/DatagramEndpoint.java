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

    /// Closes the endpoint; a thread blocked in [#receive(ByteBuffer)] fails with an [IOException]. Calling it again
    /// has no effect.
    @Override
    void close();
}
