package com.github.auties00.parley.it;

import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.NetworkInterfaceAddress;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.net.StreamConnection;
import com.github.auties00.parley.net.StreamListener;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/// The JDK network stack restricted to the IPv4 loopback interface, with an optional random loss on outgoing UDP
/// datagrams, so two peers in one JVM pair on 127.0.0.1 only and a test can degrade the path at will.
final class LoopbackOnlyStack implements NetworkStack {
    private final NetworkStack delegate;
    private final Random random = new Random(7);
    private final AtomicLong dropped = new AtomicLong();
    private volatile double loss;
    private volatile int minimumSize;

    private LoopbackOnlyStack(NetworkStack delegate) {
        this.delegate = delegate;
    }

    /// {@return a loopback stack over the JDK's}
    static LoopbackOnlyStack create() {
        return new LoopbackOnlyStack(NetworkStack.system(Thread.ofVirtual().name("it-net-", 0).factory()));
    }

    /// {@return a loopback stack whose TLS connections trust `context`}
    static LoopbackOnlyStack create(SSLContext context) {
        return new LoopbackOnlyStack(NetworkStack.system(Thread.ofVirtual().name("it-net-", 0).factory(), context));
    }

    /// Drops outgoing datagrams of at least `size` bytes with probability `probability`, as from now.
    void setLoss(double probability, int size) {
        minimumSize = size;
        loss = probability;
    }

    /// {@return the datagrams dropped so far}
    long dropped() {
        return dropped.get();
    }

    @Override
    public DatagramEndpoint bindUdp(InetSocketAddress local) throws IOException {
        var endpoint = delegate.bindUdp(local);
        return new DatagramEndpoint() {
            @Override
            public InetSocketAddress localAddress() {
                return endpoint.localAddress();
            }

            @Override
            public void send(ByteBuffer datagram, InetSocketAddress remote) throws IOException {
                var probability = loss;
                if (probability > 0 && datagram.remaining() >= minimumSize) {
                    boolean drop;
                    synchronized (random) {
                        drop = random.nextDouble() < probability;
                    }
                    if (drop) {
                        dropped.incrementAndGet();
                        return;
                    }
                }
                endpoint.send(datagram, remote);
            }

            @Override
            public InetSocketAddress receive(ByteBuffer destination) throws IOException {
                return endpoint.receive(destination);
            }

            @Override
            public void close() {
                endpoint.close();
            }
        };
    }

    @Override
    public StreamConnection connectTcp(InetSocketAddress remote, Duration timeout) throws IOException {
        return delegate.connectTcp(remote, timeout);
    }

    @Override
    public StreamConnection connectTls(InetSocketAddress remote, String serverName, Duration timeout)
            throws IOException {
        return delegate.connectTls(remote, serverName, timeout);
    }

    @Override
    public StreamListener listenTcp(InetSocketAddress local) throws IOException {
        return delegate.listenTcp(local);
    }

    @Override
    public List<NetworkInterfaceAddress> interfaceAddresses() throws IOException {
        return delegate.interfaceAddresses().stream()
                .filter(address -> address.loopback() && address.address() instanceof Inet4Address)
                .toList();
    }

    @Override
    public List<InetAddress> resolve(String hostName) throws IOException {
        return delegate.resolve(hostName);
    }

    @Override
    public ThreadFactory threadFactory() {
        return delegate.threadFactory();
    }
}
