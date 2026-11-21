package com.github.auties00.parley.net;

import java.nio.ByteBuffer;

/// Receives the packets a transport reads from the network.
///
/// A transport calls its receiver on the thread that reads from the network, one packet at a time and in arrival
/// order, so a receiver that blocks delays every packet behind it. The buffer is positioned at the first byte of the
/// packet with its limit at the last one; it belongs to the transport and is valid only until the call returns. A
/// receiver that keeps the packet copies it first:
///
/// {@snippet lang = java :
/// PacketReceiver receiver = (packet, arrivalNanos) -> {
///     var copy = ByteBuffer.allocate(packet.remaining()).put(packet.duplicate()).flip();
///     queue.add(copy);
/// };
/// }
@FunctionalInterface
public interface PacketReceiver {
    /// Handles one packet.
    ///
    /// The receiver may move the buffer's position and limit and may modify its contents (an SRTP layer decrypts in
    /// place); it must not keep a reference to it after returning. An exception thrown by the receiver is logged by
    /// the transport and the packet is dropped; it never stops the reading thread.
    ///
    /// @param packet       the packet, valid only during the call
    /// @param arrivalNanos the [MonotonicClock#nanos()] at which the packet was read from the network
    void receive(ByteBuffer packet, long arrivalNanos);
}
