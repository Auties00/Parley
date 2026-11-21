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
import java.util.concurrent.DelayQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/// The JDK network stack restricted to the IPv4 loopback interface, with an optional random loss and an optional
/// bottleneck on outgoing UDP datagrams, so two peers in one JVM pair on 127.0.0.1 only and a test can degrade the
/// path at will.
///
/// The bottleneck is a drop-tail queue drained at a fixed bit rate, shared by every endpoint of the stack: a datagram
/// leaves once the link has serialised everything queued before it, and is dropped when it would wait longer than
/// the queue's limit, as on a constrained access link.
final class LoopbackOnlyStack implements NetworkStack {
    private final NetworkStack delegate;
    private final Random random = new Random(7);
    private final AtomicLong dropped = new AtomicLong();
    private final DelayQueue<Delayed> link = new DelayQueue<>();
    private final Object linkLock = new Object();
    private volatile double loss;
    private volatile int minimumSize;
    private volatile long bitsPerSecond;
    private volatile long queueLimitNanos;
    private long linkFreeAtNanos;
    private Thread linkThread;

    /// A datagram waiting in the bottleneck queue.
    private record Delayed(long dueNanos, DatagramEndpoint endpoint, ByteBuffer datagram, InetSocketAddress remote)
            implements java.util.concurrent.Delayed {
        @Override
        public long getDelay(TimeUnit unit) {
            return unit.convert(dueNanos - System.nanoTime(), TimeUnit.NANOSECONDS);
        }

        @Override
        public int compareTo(java.util.concurrent.Delayed other) {
            return Long.compare(dueNanos, ((Delayed) other).dueNanos);
        }
    }

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

    /// Limits outgoing UDP to `bitsPerSecond` behind a drop-tail queue holding at most `queueLimit` of traffic, as
    /// from now; zero removes the limit.
    void setBandwidth(long bitsPerSecond, Duration queueLimit) {
        synchronized (linkLock) {
            this.queueLimitNanos = queueLimit.toNanos();
            this.bitsPerSecond = bitsPerSecond;
            if (bitsPerSecond > 0 && linkThread == null) {
                linkThread = Thread.ofVirtual().name("it-link").start(this::drainLink);
            }
        }
    }

    /// Sends queued datagrams when the bottleneck has serialised them.
    private void drainLink() {
        while (true) {
            try {
                var next = link.take();
                next.endpoint().send(next.datagram(), next.remote());
            } catch (InterruptedException exception) {
                return;
            } catch (IOException exception) {
                // The endpoint closed while its datagram was queued, as a link drops it
            }
        }
    }

    /// {@return whether the bottleneck queued `datagram` (or dropped it), false when no limit applies}
    private boolean throughLink(DatagramEndpoint endpoint, ByteBuffer datagram, InetSocketAddress remote) {
        var rate = bitsPerSecond;
        if (rate <= 0) {
            return false;
        }
        var now = System.nanoTime();
        synchronized (linkLock) {
            var start = Math.max(now, linkFreeAtNanos);
            if (start - now > queueLimitNanos) {
                dropped.incrementAndGet();
                return true;
            }
            linkFreeAtNanos = start + datagram.remaining() * 8L * 1_000_000_000L / rate;
            var copy = ByteBuffer.allocate(datagram.remaining()).put(datagram.duplicate()).flip();
            link.add(new Delayed(linkFreeAtNanos, endpoint, copy, remote));
            return true;
        }
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
                if (!throughLink(endpoint, datagram, remote)) {
                    endpoint.send(datagram, remote);
                }
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
