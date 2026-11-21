package com.github.auties00.parley.peer;

import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.sdp.SessionDescription;

import java.time.Duration;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

/// Builds peer connections over a [FakeBackend] and runs offer/answer exchanges between them.
final class Peers {
    private Peers() {
    }

    /// A connection, its fake backend and a stream of its events opened at creation.
    record Peer(PeerConnection pc, FakeBackend backend, EventStream<PeerConnectionEvent> events) {
        /// {@return the events raised since the last call, without waiting}
        List<PeerConnectionEvent> drain() {
            var result = new ArrayList<PeerConnectionEvent>();
            try {
                for (var event = events.next(Duration.ZERO); event.isPresent(); event = events.next(Duration.ZERO)) {
                    result.add(event.get());
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            return result;
        }

        /// {@return how many events of `type` were raised since the last drain}
        long count(Class<? extends PeerConnectionEvent> type) {
            return drain().stream().filter(type::isInstance).count();
        }
    }

    /// {@return a connection with the default configuration}
    static Peer peer() {
        return peer(UnaryOperator.identity());
    }

    /// {@return a connection configured by `configure`}
    static Peer peer(UnaryOperator<Configuration.Builder> configure) {
        var backend = new AtomicReference<FakeBackend>();
        var pc = PeerConnection.create(configure.apply(Configuration.builder()).build(), (configuration, listener) -> {
            var fake = new FakeBackend(configuration, listener);
            backend.set(fake);
            return fake;
        });
        return new Peer(pc, backend.get(), pc.events());
    }

    /// Runs one complete exchange: `offerer` offers, `answerer` answers.
    static void negotiate(Peer offerer, Peer answerer) {
        var offer = offerer.pc().createOffer();
        offerer.pc().setLocalDescription(offer);
        answerer.pc().setRemoteDescription(offer);
        var answer = answerer.pc().createAnswer();
        answerer.pc().setLocalDescription(answer);
        offerer.pc().setRemoteDescription(answer);
    }

    /// {@return the parsed SDP of a description}
    static SessionDescription parse(JsepDescription description) {
        return SessionDescription.parse(description.sdp());
    }
}
