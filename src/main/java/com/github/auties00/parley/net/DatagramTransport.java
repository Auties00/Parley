package com.github.auties00.parley.net;

import java.io.IOException;
import java.nio.ByteBuffer;

/// A connected, unreliable, message-oriented path to one peer: the selected pair of an ICE agent, a fixed peer
/// address, or the application data of a DTLS association.
///
/// A datagram passed to [#send(ByteBuffer)] reaches the peer whole or not at all; datagrams may be lost, duplicated
/// or reordered. When the path runs over a stream (ICE-TCP, TURN over TCP or TLS) the transport frames each datagram
/// itself, so callers always see datagram boundaries. Received datagrams go to the [PacketReceiver] set with
/// [#setReceiver(PacketReceiver)].
///
/// # Threading
///
/// Implementations are safe for use by several threads at once. [#send(ByteBuffer)] may block briefly while the
/// network accepts the datagram; the receiver is called on the transport's reading thread.
public interface DatagramTransport extends AutoCloseable {
    /// Sends one datagram to the peer.
    ///
    /// The datagram is the buffer's remaining bytes; the position and limit may change during the call, and the
    /// caller may reuse the buffer once the call returns.
    ///
    /// @param datagram the datagram, at most [#maxDatagramSize()] bytes
    /// @throws IOException if the path is closed, has failed, or the network refused the datagram
    void send(ByteBuffer datagram) throws IOException;

    /// Sets the receiver of incoming datagrams, replacing the previous one.
    ///
    /// Datagrams that arrive before a receiver is set are dropped.
    ///
    /// @param receiver the receiver
    void setReceiver(PacketReceiver receiver);

    /// {@return the largest datagram, in bytes, [#send(ByteBuffer)] carries without IP fragmentation on the current
    /// path, after the overhead of the IP and UDP headers and of any TURN or TCP framing}
    ///
    /// The value can change when the path changes, such as when an ICE agent selects another pair.
    int maxDatagramSize();

    /// Closes the transport and releases its network resources.
    ///
    /// A thread blocked in [#send(ByteBuffer)] fails with an [IOException]; no receiver call starts after this method
    /// returns. Calling it again has no effect.
    @Override
    void close();
}
