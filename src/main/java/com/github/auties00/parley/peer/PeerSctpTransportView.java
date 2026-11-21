package com.github.auties00.parley.peer;

import com.github.auties00.parley.datachannel.SctpTransport;
import com.github.auties00.parley.datachannel.SctpTransportState;

import java.util.Objects;
import java.util.OptionalInt;
import java.util.function.Supplier;

/// The [PeerSctpTransport] of a connection, reading the backend's current association, which a restart replaces.
final class PeerSctpTransportView implements PeerSctpTransport {
    /// The current association.
    private final Supplier<SctpTransport> association;
    /// The DTLS transport the association runs over.
    private final PeerDtlsTransport transport;

    /// Creates the view of the association `association` supplies, over `transport`.
    PeerSctpTransportView(Supplier<SctpTransport> association, PeerDtlsTransport transport) {
        this.association = Objects.requireNonNull(association);
        this.transport = Objects.requireNonNull(transport);
    }

    @Override
    public PeerDtlsTransport transport() {
        return transport;
    }

    @Override
    public SctpTransportState state() {
        return association.get().state();
    }

    @Override
    public long maxMessageSize() {
        return association.get().maxMessageSize();
    }

    @Override
    public OptionalInt maxChannels() {
        return association.get().maxChannels();
    }

    /// {@return the state of the association}
    @Override
    public String toString() {
        return "PeerSctpTransport[state=" + state() + "]";
    }
}
