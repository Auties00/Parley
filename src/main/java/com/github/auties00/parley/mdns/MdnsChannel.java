package com.github.auties00.parley.mdns;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/// The UDP socket a resolver or responder exchanges DNS messages through; tests replace it with an in-memory link.
public interface MdnsChannel extends AutoCloseable {
    /// The IPv4 multicast group and port of multicast DNS, `224.0.0.251:5353`.
    InetSocketAddress IPV4_GROUP = new InetSocketAddress(java.net.InetAddress.ofLiteral("224.0.0.251"), 5353);

    /// The IPv6 link-local multicast group and port of multicast DNS, `[ff02::fb]:5353`.
    InetSocketAddress IPV6_GROUP = new InetSocketAddress(java.net.InetAddress.ofLiteral("ff02::fb"), 5353);

    /// {@return the multicast group this socket sends announcements and queries to}
    ///
    /// @implSpec The default implementation returns [#IPV4_GROUP].
    default InetSocketAddress group() {
        return IPV4_GROUP;
    }

    /// Sends one message.
    ///
    /// @param message the message, its remaining bytes
    /// @param target  the destination, the multicast group or a unicast address
    /// @throws IOException if the socket is closed or the send fails
    void send(ByteBuffer message, InetSocketAddress target) throws IOException;

    /// Receives one message, blocking until one arrives.
    ///
    /// @param destination the buffer to fill at its position
    /// @return the source of the message
    /// @throws IOException if the socket is closed, before or while the call blocks
    InetSocketAddress receive(ByteBuffer destination) throws IOException;

    /// {@return the local port, `5353` for a responder}
    int localPort();

    /// Closes the socket; a blocked [#receive(ByteBuffer)] fails.
    @Override
    void close();
}
