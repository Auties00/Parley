package com.github.auties00.parley.it;

import com.github.auties00.parley.peer.JsepDescription;
import com.github.auties00.parley.peer.PeerConnection;
import com.github.auties00.parley.peer.PeerConnectionEvent;
import com.github.auties00.parley.peer.PeerConnectionState;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

/// Runs two peer connections against each other in one JVM, over loopback, with an in-memory signaling channel.
final class Loopback {
    /// How long a test waits for a state.
    static final Duration TIMEOUT = Duration.ofSeconds(20);

    private Loopback() {
    }

    /// A connection with every event it raised recorded.
    static final class Peer implements AutoCloseable {
        final PeerConnection pc;
        final List<PeerConnectionEvent> events = new CopyOnWriteArrayList<>();
        private final Object monitor = new Object();

        Peer(PeerConnection pc) {
            this.pc = pc;
            pc.addListener(event -> {
                events.add(event);
                synchronized (monitor) {
                    monitor.notifyAll();
                }
            });
        }

        /// Waits until an event matches `predicate`, returning it.
        <E extends PeerConnectionEvent> E await(Class<E> type, Predicate<? super E> predicate)
                throws InterruptedException, TimeoutException {
            var deadline = System.nanoTime() + TIMEOUT.toNanos();
            synchronized (monitor) {
                while (true) {
                    for (var event : events) {
                        if (type.isInstance(event) && predicate.test(type.cast(event))) {
                            return type.cast(event);
                        }
                    }
                    var left = deadline - System.nanoTime();
                    if (left <= 0) {
                        throw new TimeoutException("no " + type.getSimpleName() + " event; events were " + events);
                    }
                    monitor.wait(Math.max(1, left / 1_000_000));
                }
            }
        }

        /// Waits until the connection reaches `state`.
        void awaitState(PeerConnectionState state) throws InterruptedException, TimeoutException {
            await(PeerConnectionEvent.ConnectionStateChanged.class, event -> event.state() == state);
        }

        /// Waits until gathering completes on every transport, then returns the local description.
        JsepDescription gatheredDescription() throws InterruptedException, TimeoutException {
            var deadline = System.nanoTime() + TIMEOUT.toNanos();
            while (pc.iceGatheringState() != com.github.auties00.parley.ice.IceGatheringState.COMPLETE) {
                if (System.nanoTime() > deadline) {
                    throw new TimeoutException("gathering did not complete: " + pc.iceGatheringState());
                }
                Thread.sleep(10);
            }
            return pc.localDescription().orElseThrow();
        }

        @Override
        public void close() {
            pc.close();
        }
    }

    /// {@return a connection gathering loopback UDP candidates only, configured further by `configure`}
    static Peer peer(UnaryOperator<PeerConnection.Builder> configure) {
        Objects.requireNonNull(configure);
        var builder = PeerConnection.builder()
                .loopbackCandidates(true)
                .tcpCandidates(false)
                .networkStack(LoopbackOnlyStack.create());
        return new Peer(configure.apply(builder).build());
    }

    /// {@return a connection with the loopback defaults}
    static Peer peer() {
        return peer(UnaryOperator.identity());
    }

    /// Runs one non-trickle exchange: each side waits for its candidates before sending its description.
    static void negotiate(Peer offerer, Peer answerer) throws InterruptedException, TimeoutException {
        offerer.pc.setLocalDescription(offerer.pc.createOffer());
        var offer = offerer.gatheredDescription();
        answerer.pc.setRemoteDescription(offer);
        answerer.pc.setLocalDescription(answerer.pc.createAnswer());
        var answer = answerer.gatheredDescription();
        offerer.pc.setRemoteDescription(answer);
    }

    /// Runs an exchange and waits until both connections are connected.
    static void connect(Peer offerer, Peer answerer) throws InterruptedException, TimeoutException {
        negotiate(offerer, answerer);
        offerer.awaitState(PeerConnectionState.CONNECTED);
        answerer.awaitState(PeerConnectionState.CONNECTED);
    }
}
