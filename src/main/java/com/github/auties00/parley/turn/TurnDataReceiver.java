package com.github.auties00.parley.turn;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/// Receives the data peers send to a [TurnAllocation]'s relayed address.
///
/// Called on the TURN client's reading thread, one datagram at a time; the buffer is valid only during the call (see
/// [com.github.auties00.parley.net.PacketReceiver]).
@FunctionalInterface
public interface TurnDataReceiver {
    /// Handles one datagram relayed from a peer.
    ///
    /// @param peer         the peer's address as the server saw it
    /// @param data         the datagram, valid only during the call
    /// @param arrivalNanos the [com.github.auties00.parley.net.MonotonicClock#nanos()] at which it arrived
    void receive(InetSocketAddress peer, ByteBuffer data, long arrivalNanos);
}
