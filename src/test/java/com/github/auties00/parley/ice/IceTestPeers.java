package com.github.auties00.parley.ice;

import com.github.auties00.parley.mdns.MdnsResolver;
import com.github.auties00.parley.mdns.MdnsResponder;
import com.github.auties00.parley.mdns.MemoryMdnsLink;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

/// Wires two ICE agents to each other as a signalling channel would: each trickles its candidates and its end of
/// candidates to the other, through an optional filter, and records the events it saw.
final class IceTestPeers implements AutoCloseable {
    /// The first agent, conventionally the offerer.
    final IceAgent first;

    /// The second agent.
    final IceAgent second;

    /// The events of the first agent.
    final List<IceEvent> firstEvents = new CopyOnWriteArrayList<>();

    /// The events of the second agent.
    final List<IceEvent> secondEvents = new CopyOnWriteArrayList<>();

    /// Builds both agents and exchanges their parameters; gathering is not started.
    ///
    /// @param firstBuilder  the builder of the first agent
    /// @param secondBuilder the builder of the second agent
    /// @param toSecond      which of the first agent's candidates reach the second
    /// @param toFirst       which of the second agent's candidates reach the first
    IceTestPeers(IceAgent.Builder firstBuilder, IceAgent.Builder secondBuilder,
                 Predicate<IceCandidate> toSecond, Predicate<IceCandidate> toFirst) {
        var firstRef = new AtomicReference<IceAgent>();
        var secondRef = new AtomicReference<IceAgent>();
        first = firstBuilder.eventListener(event -> {
            firstEvents.add(event);
            forward(event, secondRef.get(), toSecond);
        }).build();
        firstRef.set(first);
        second = secondBuilder.eventListener(event -> {
            secondEvents.add(event);
            forward(event, firstRef.get(), toFirst);
        }).build();
        secondRef.set(second);
        first.setRemoteParameters(second.localParameters());
        second.setRemoteParameters(first.localParameters());
    }

    /// Starts gathering on both agents.
    void gather() {
        first.gather();
        second.gather();
    }

    /// Waits until both agents have a selected pair.
    void awaitConnected(Duration timeout) throws Exception {
        first.awaitConnected(timeout);
        second.awaitConnected(timeout);
    }

    /// Hands a trickled candidate or the end of candidates to the other agent.
    private static void forward(IceEvent event, IceAgent other, Predicate<IceCandidate> filter) {
        if (other == null) {
            return;
        }
        try {
            switch (event) {
                case IceEvent.CandidateGathered(var candidate) when filter.test(candidate) -> other.addRemoteCandidate(candidate);
                case IceEvent.GatheringStateChanged(var state) when state == IceGatheringState.COMPLETE -> other.endOfRemoteCandidates();
                default -> {
                }
            }
        } catch (IllegalStateException closed) {
            // The other agent closed first.
        }
    }

    @Override
    public void close() {
        first.close();
        second.close();
    }

    /// {@return a builder restricted to the IPv4 loopback interface}
    static IceAgent.Builder loopbackBuilder() {
        return IceAgent.builder()
                .addressFilter(address -> address.address() instanceof Inet4Address && address.loopback())
                .loopbackCandidates(true);
    }

    /// {@return an mDNS factory whose responder and resolver share an in-memory link}
    static IceAgent.MdnsFactory memoryMdns(MemoryMdnsLink link, String ip) {
        var threads = Thread.ofVirtual().name("mdns-", 0).factory();
        return new IceAgent.MdnsFactory() {
            @Override
            public MdnsResponder openResponder() {
                return new MdnsResponder(link.channel(ip, 5353), threads);
            }

            @Override
            public MdnsResolver openResolver() {
                return new MdnsResolver(link.channel(ip, 50000 + (int) (Math.random() * 10000)), threads);
            }
        };
    }

    /// A receiver that queues copies of what it receives.
    static final class Inbox implements com.github.auties00.parley.net.PacketReceiver {
        private final LinkedBlockingQueue<byte[]> packets = new LinkedBlockingQueue<>();

        @Override
        public void receive(ByteBuffer packet, long arrivalNanos) {
            var bytes = new byte[packet.remaining()];
            packet.get(bytes);
            packets.add(bytes);
        }

        /// {@return the next packet, or `null` after the timeout}
        byte[] next(Duration timeout) throws InterruptedException {
            return packets.poll(timeout.toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    /// {@return the loopback address}
    static InetAddress loopback() {
        return InetAddress.ofLiteral("127.0.0.1");
    }
}
