package com.github.auties00.parley.peer;

import com.github.auties00.parley.event.EventSource;
import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.ice.IceAgent;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceCandidatePair;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceParameters;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.ice.IceTransportState;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// The [PeerIceTransport] of one transport, reading its [IceAgent] and fed its events by the backend.
final class PeerIceTransportView implements PeerIceTransport {
    /// The agent the view reads.
    private final IceAgent agent;
    /// The events the backend publishes.
    private final EventSource<PeerIceTransportEvent> events = new EventSource<>();

    /// Creates the view of `agent`.
    PeerIceTransportView(IceAgent agent) {
        this.agent = Objects.requireNonNull(agent);
    }

    @Override
    public IceRole role() {
        return agent.role();
    }

    @Override
    public IceTransportState state() {
        return agent.state();
    }

    @Override
    public IceGatheringState gatheringState() {
        return agent.gatheringState();
    }

    @Override
    public List<IceCandidate> localCandidates() {
        return agent.localCandidates();
    }

    @Override
    public List<IceCandidate> remoteCandidates() {
        return agent.remoteCandidates();
    }

    @Override
    public Optional<IceCandidatePair> selectedCandidatePair() {
        return agent.selectedPair();
    }

    @Override
    public IceParameters localParameters() {
        return agent.localParameters();
    }

    @Override
    public Optional<IceParameters> remoteParameters() {
        return agent.remoteParameters();
    }

    @Override
    public EventStream<PeerIceTransportEvent> events() {
        return events.open();
    }

    /// Raises an event.
    void publish(PeerIceTransportEvent event) {
        events.publish(event);
    }

    /// Ends the event streams, as when the transport closes.
    void end() {
        events.end();
    }

    /// {@return the state of the transport}
    @Override
    public String toString() {
        return "PeerIceTransport[state=" + state() + "]";
    }
}
