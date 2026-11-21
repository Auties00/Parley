package com.github.auties00.parley.dtls;

import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/// An in-memory datagram link between two endpoints, with optional loss, duplication and reordering driven by a
/// seeded random source so failures reproduce.
///
/// Each endpoint is either a callback [DatagramTransport] with its own delivery thread, or a blocking queue for peers
/// such as BouncyCastle that pull datagrams.
public final class MemoryLink implements AutoCloseable {
    /// The conditions of one direction.
    ///
    /// @param lossRate        the probability a datagram is dropped
    /// @param duplicateRate   the probability a datagram is delivered twice
    /// @param reorderRate     the probability a datagram is held back and delivered after the next one
    /// @param seed            the random seed
    public record Conditions(double lossRate, double duplicateRate, double reorderRate, long seed) {
        /// A perfect link.
        public static final Conditions PERFECT = new Conditions(0, 0, 0, 1);
    }

    /// The left endpoint.
    public final Endpoint left;

    /// The right endpoint.
    public final Endpoint right;

    /// Creates a link.
    public MemoryLink(Conditions conditions) {
        this.left = new Endpoint("left", conditions, conditions.seed());
        this.right = new Endpoint("right", conditions, conditions.seed() * 31 + 7);
        left.peer = right;
        right.peer = left;
    }

    /// Creates a perfect link.
    public MemoryLink() {
        this(Conditions.PERFECT);
    }

    @Override
    public void close() {
        left.close();
        right.close();
    }

    /// One endpoint of the link.
    public static final class Endpoint implements DatagramTransport {
        /// The marker that stops the delivery thread.
        private static final byte[] STOP = new byte[0];

        /// The name, for thread names.
        private final String name;

        /// The conditions of datagrams sent from this endpoint.
        private final Conditions conditions;

        /// The random source of the conditions.
        private final Random random;

        /// The datagrams waiting for this endpoint.
        final LinkedBlockingQueue<byte[]> inbox = new LinkedBlockingQueue<>();

        /// The datagrams sent from this endpoint, as they were sent.
        public final List<byte[]> sent = java.util.Collections.synchronizedList(new ArrayList<>());

        /// The datagrams dropped by a filter or the loss rate.
        final AtomicInteger dropped = new AtomicInteger();

        /// The other endpoint.
        private Endpoint peer;

        /// A datagram held back for reordering, or `null`.
        private byte[] held;

        /// A filter that drops matching datagrams sent from this endpoint, or `null`.
        public volatile Predicate<byte[]> dropFilter;

        /// The receiver, or `null` for a pulled endpoint.
        private volatile PacketReceiver receiver;

        /// The delivery thread, started with the first receiver.
        private Thread delivery;

        /// The size budget reported.
        public volatile int maxDatagramSize = 1500;

        /// Creates an endpoint.
        private Endpoint(String name, Conditions conditions, long seed) {
            this.name = name;
            this.conditions = conditions;
            this.random = new Random(seed);
        }

        @Override
        public synchronized void send(ByteBuffer datagram) throws IOException {
            var bytes = new byte[datagram.remaining()];
            datagram.duplicate().get(bytes);
            sent.add(bytes.clone());
            var filter = dropFilter;
            if ((filter != null && filter.test(bytes)) || random.nextDouble() < conditions.lossRate()) {
                dropped.incrementAndGet();
                return;
            }
            if (held == null && random.nextDouble() < conditions.reorderRate()) {
                held = bytes;
                return;
            }
            peer.inbox.add(bytes);
            if (random.nextDouble() < conditions.duplicateRate()) {
                peer.inbox.add(bytes.clone());
            }
            if (held != null) {
                peer.inbox.add(held);
                held = null;
            }
        }

        /// Sends raw bytes from this endpoint, bypassing the conditions.
        public void inject(byte[] datagram) {
            peer.inbox.add(datagram.clone());
        }

        @Override
        public void setReceiver(PacketReceiver receiver) {
            synchronized (this) {
                this.receiver = receiver;
                if (delivery == null) {
                    delivery = Thread.ofVirtual().name("link-" + name).start(this::deliver);
                }
            }
        }

        @Override
        public int maxDatagramSize() {
            return maxDatagramSize;
        }

        @Override
        public void close() {
            inbox.add(STOP);
        }

        /// Pulls a datagram, for a blocking peer.
        byte[] poll(long timeoutMillis) throws InterruptedException {
            var datagram = inbox.poll(timeoutMillis, TimeUnit.MILLISECONDS);
            return datagram == STOP ? null : datagram;
        }

        /// Delivers queued datagrams to the receiver.
        private void deliver() {
            try {
                while (true) {
                    var datagram = inbox.take();
                    if (datagram == STOP) {
                        return;
                    }
                    var current = receiver;
                    if (current != null) {
                        current.receive(ByteBuffer.wrap(datagram), System.nanoTime());
                    }
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
