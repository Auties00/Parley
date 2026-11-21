package com.github.auties00.parley.mdns;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/// An in-memory link for multicast DNS tests: a message to the multicast group reaches every other channel on port
/// 5353, a unicast message the channel at its address.
public final class MemoryMdnsLink {
    /// The inbox of every open channel.
    private final Map<InetSocketAddress, LinkedBlockingQueue<Datagram>> inboxes = new ConcurrentHashMap<>();

    /// {@return a new channel at an address}
    ///
    /// @param ip   the IP literal
    /// @param port the port
    public MdnsChannel channel(String ip, int port) {
        var address = new InetSocketAddress(InetAddress.ofLiteral(ip), port);
        var inbox = new LinkedBlockingQueue<Datagram>();
        inboxes.put(address, inbox);
        return new MdnsChannel() {
            private volatile boolean closed;

            @Override
            public void send(ByteBuffer message, InetSocketAddress target) {
                var bytes = new byte[message.remaining()];
                message.get(bytes);
                inboxes.forEach((destination, queue) -> {
                    var multicast = target.equals(IPV4_GROUP) && destination.getPort() == 5353 && !destination.equals(address);
                    if (multicast || destination.equals(target)) {
                        queue.add(new Datagram(address, bytes));
                    }
                });
            }

            @Override
            public InetSocketAddress receive(ByteBuffer destination) throws IOException {
                try {
                    while (true) {
                        if (closed) {
                            throw new IOException("closed");
                        }
                        var datagram = inbox.poll(20, TimeUnit.MILLISECONDS);
                        if (datagram != null) {
                            destination.put(datagram.bytes());
                            return datagram.source();
                        }
                    }
                } catch (InterruptedException exception) {
                    throw new IOException(exception);
                }
            }

            @Override
            public int localPort() {
                return port;
            }

            @Override
            public void close() {
                closed = true;
                inboxes.remove(address);
            }
        };
    }

    /// One message in flight.
    ///
    /// @param source the sender
    /// @param bytes  the message
    private record Datagram(InetSocketAddress source, byte[] bytes) {
    }
}
