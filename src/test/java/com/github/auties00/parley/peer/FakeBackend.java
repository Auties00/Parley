package com.github.auties00.parley.peer;

import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelInit;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.stats.RtcStats;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/// A backend that records what the JSEP engine asks of the transports, so the signaling can be tested without
/// sockets.
final class FakeBackend implements PeerBackend {
    /// The fingerprint every fake backend presents.
    static final SdpAttribute.Fingerprint FINGERPRINT = SdpAttribute.Fingerprint.of("sha-256", new byte[32]);

    final Configuration configuration;
    final Listener listener;
    final List<Map.Entry<String, Negotiated.IceCredentials>> gathering = new CopyOnWriteArrayList<>();
    final List<Negotiated> applied = new CopyOnWriteArrayList<>();
    final List<Map.Entry<String, String>> remoteCandidates = new CopyOnWriteArrayList<>();
    final List<String> endedCandidates = new CopyOnWriteArrayList<>();
    final List<String> channels = new CopyOnWriteArrayList<>();
    final List<RtcStats> statistics = new ArrayList<>();
    volatile boolean closed;

    FakeBackend(Configuration configuration, Listener listener) {
        this.configuration = configuration;
        this.listener = listener;
    }

    @Override
    public List<SdpAttribute.Fingerprint> fingerprints() {
        return List.of(FINGERPRINT);
    }

    @Override
    public void startGathering(String transportId, Negotiated.IceCredentials credentials) {
        gathering.add(Map.entry(transportId, credentials));
    }

    @Override
    public void apply(Negotiated negotiated, boolean finalAnswer) {
        applied.add(negotiated);
    }

    @Override
    public void addRemoteCandidate(String transportId, String candidate) {
        remoteCandidates.add(Map.entry(transportId, candidate));
    }

    @Override
    public void endOfRemoteCandidates(String transportId) {
        endedCandidates.add(transportId);
    }

    @Override
    public DataChannel createDataChannel(String label, DataChannelInit init) {
        channels.add(label);
        return null;
    }

    @Override
    public List<RtcStats> statistics(Instant now) {
        return List.copyOf(statistics);
    }

    @Override
    public void updateEncodings(RtpSender sender, List<Encoding> encodings) {
    }

    @Override
    public void updateJitterBufferTarget(RtpReceiver receiver, Optional<Duration> target) {
    }

    @Override
    public void close() {
        closed = true;
    }

    /// {@return the last negotiation applied}
    Negotiated last() {
        return applied.getLast();
    }
}
