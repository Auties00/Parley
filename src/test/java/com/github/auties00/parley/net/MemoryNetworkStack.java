package com.github.auties00.parley.net;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/// An in-memory UDP network for tests: endpoints of every stack built on one [Network] reach each other by address,
/// every datagram sent is recorded, and a drop filter simulates loss. TCP is not supported.
public final class MemoryNetworkStack implements NetworkStack {
    /// The network the stack's endpoints join.
    private final Network network;

    /// The interfaces the stack reports.
    private final List<NetworkInterfaceAddress> interfaces;

    /// The thread factory.
    private final ThreadFactory threadFactory = Thread.ofVirtual().name("memory-net-", 0).factory();

    /// Creates a stack.
    ///
    /// @param network    the shared network
    /// @param interfaces the interfaces to report
    public MemoryNetworkStack(Network network, List<NetworkInterfaceAddress> interfaces) {
        this.network = network;
        this.interfaces = List.copyOf(interfaces);
    }

    @Override
    public DatagramEndpoint bindUdp(InetSocketAddress local) {
        var port = local.getPort() == 0 ? network.nextPort.incrementAndGet() : local.getPort();
        var address = new InetSocketAddress(local.getAddress(), port);
        var endpoint = new MemoryEndpoint(network, address);
        network.endpoints.put(address, endpoint);
        return endpoint;
    }

    @Override
    public StreamConnection connectTcp(InetSocketAddress remote, Duration timeout) throws IOException {
        throw new IOException("TCP is not simulated");
    }

    @Override
    public StreamConnection connectTls(InetSocketAddress remote, String serverName, Duration timeout) throws IOException {
        throw new IOException("TLS is not simulated");
    }

    @Override
    public StreamListener listenTcp(InetSocketAddress local) throws IOException {
        throw new IOException("TCP is not simulated");
    }

    @Override
    public List<NetworkInterfaceAddress> interfaceAddresses() {
        return interfaces;
    }

    @Override
    public ThreadFactory threadFactory() {
        return threadFactory;
    }

    /// A shared network.
    public static final class Network {
        /// The endpoints by address.
        private final Map<InetSocketAddress, MemoryEndpoint> endpoints = new ConcurrentHashMap<>();

        /// Every datagram sent, in order.
        private final List<Sent> sent = new CopyOnWriteArrayList<>();

        /// The next ephemeral port.
        private final AtomicInteger nextPort = new AtomicInteger(40_000);

        /// The filter of datagrams to drop.
        private volatile Predicate<Sent> drop = _ -> false;

        /// {@return every datagram sent so far}
        public List<Sent> sent() {
            return List.copyOf(sent);
        }

        /// Sets the filter of datagrams to drop; they are still recorded.
        ///
        /// @param drop the filter
        public void drop(Predicate<Sent> drop) {
            this.drop = drop;
        }
    }

    /// One recorded datagram.
    ///
    /// @param from  the source
    /// @param to    the destination
    /// @param bytes the datagram
    public record Sent(InetSocketAddress from, InetSocketAddress to, byte[] bytes) {
        /// {@return the datagram as a read-only buffer}
        public ByteBuffer buffer() {
            return ByteBuffer.wrap(bytes).asReadOnlyBuffer();
        }
    }

    /// One endpoint.
    private static final class MemoryEndpoint implements DatagramEndpoint {
        /// The network.
        private final Network network;

        /// The address.
        private final InetSocketAddress address;

        /// The received datagrams.
        private final LinkedBlockingQueue<Sent> inbox = new LinkedBlockingQueue<>();

        /// Whether the endpoint closed.
        private volatile boolean closed;

        /// Creates an endpoint.
        MemoryEndpoint(Network network, InetSocketAddress address) {
            this.network = network;
            this.address = address;
        }

        @Override
        public InetSocketAddress localAddress() {
            return address;
        }

        @Override
        public void send(ByteBuffer datagram, InetSocketAddress remote) throws IOException {
            if (closed) {
                throw new IOException("closed");
            }
            var bytes = new byte[datagram.remaining()];
            datagram.get(bytes);
            var sent = new Sent(address, remote, bytes);
            network.sent.add(sent);
            if (network.drop.test(sent)) {
                return;
            }
            var target = network.endpoints.get(remote);
            if (target != null) {
                target.inbox.add(sent);
            }
        }

        @Override
        public InetSocketAddress receive(ByteBuffer destination) throws IOException {
            try {
                while (true) {
                    if (closed) {
                        throw new IOException("closed");
                    }
                    var next = inbox.poll(20, TimeUnit.MILLISECONDS);
                    if (next != null) {
                        destination.put(next.bytes(), 0, Math.min(next.bytes().length, destination.remaining()));
                        return next.from();
                    }
                }
            } catch (InterruptedException exception) {
                throw new IOException(exception);
            }
        }

        @Override
        public void close() {
            closed = true;
            network.endpoints.remove(address);
        }
    }
}
