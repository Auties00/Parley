package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.event.EventSource;
import com.github.auties00.parley.event.EventStream;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/// The [PeerDtlsTransport] of one transport, reading its [DtlsTransport] and fed its state changes by the backend.
final class PeerDtlsTransportView implements PeerDtlsTransport {
    /// The transport the view reads; replaced when the peer restarts DTLS.
    private volatile DtlsTransport dtls;
    /// The view of the ICE transport under it.
    private final PeerIceTransportView ice;
    /// The state changes the backend publishes.
    private final EventSource<DtlsState> events = new EventSource<>();

    /// Creates the view of `dtls` over `ice`.
    PeerDtlsTransportView(DtlsTransport dtls, PeerIceTransportView ice) {
        this.dtls = Objects.requireNonNull(dtls);
        this.ice = Objects.requireNonNull(ice);
    }

    @Override
    public PeerIceTransport iceTransport() {
        return ice;
    }

    @Override
    public DtlsState state() {
        return dtls.state();
    }

    @Override
    public List<X509Certificate> remoteCertificates() {
        return dtls.remoteCertificate().map(List::of).orElse(List.of());
    }

    @Override
    public EventStream<DtlsState> events() {
        return events.open();
    }

    /// Reads `replacement` from now on, as when a DTLS restart replaces the association.
    void replace(DtlsTransport replacement) {
        this.dtls = Objects.requireNonNull(replacement);
    }

    /// Raises a state change.
    void publish(DtlsState state) {
        events.publish(state);
    }

    /// Ends the event streams of this view and of its ICE view, as when the transport closes.
    void end() {
        events.end();
        ice.end();
    }

    /// {@return the state of the transport}
    @Override
    public String toString() {
        return "PeerDtlsTransport[state=" + state() + "]";
    }
}
