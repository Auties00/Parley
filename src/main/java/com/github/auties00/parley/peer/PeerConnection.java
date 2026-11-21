package com.github.auties00.parley.peer;

import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelInit;
import com.github.auties00.parley.datachannel.DataChannelPriority;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceTransportState;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.RtpCodecParameters;
import com.github.auties00.parley.stats.PeerConnectionStats;
import com.github.auties00.parley.stats.RtcStats;
import com.github.auties00.parley.stats.StatsReport;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

/// A WebRTC peer connection, the W3C `RTCPeerConnection`: it negotiates media and data with a remote peer through
/// JSEP offers and answers, and runs the ICE, DTLS, SRTP, RTP and SCTP transports the negotiation calls for.
///
/// The application carries the descriptions and candidates to the peer over its own signaling channel; Parley never
/// signals by itself. Media flows as encoded frames: [LocalTrack]s in, [RemoteTrack]s out.
///
/// {@snippet lang = java :
/// var pc = PeerConnection.builder()
///         .iceServers(List.of(new IceServer(List.of(URI.create("stun:stun.example.org")), Optional.empty(),
///                 Optional.empty())))
///         .bundlePolicy(BundlePolicy.MAX_BUNDLE)
///         .build();
/// var audio = LocalTrack.audio("mic");
/// pc.addTrack(audio, List.of("stream-1"));
/// var offer = pc.createOffer();
/// pc.setLocalDescription(offer);
/// signaling.send(offer.sdp());
/// pc.setRemoteDescription(JsepDescription.answer(signaling.receiveAnswer()));
/// try (var events = pc.events()) {
///     for (var event : events) {
///         switch (event) {
///             case PeerConnectionEvent.IceCandidate(var candidate) -> signaling.send(candidate);
///             case PeerConnectionEvent.Track(var receiver, var streams, var transceiver) -> play(receiver.track());
///             default -> { }
///         }
///     }
/// }
/// }
///
/// # Perfect negotiation
///
/// A remote offer applied while a local offer is pending rolls the local offer back first, and
/// [#setLocalDescription()] creates the right description for the signaling state, so the W3C perfect negotiation
/// pattern works as written for browsers.
///
/// # Threading
///
/// Every method is safe for concurrent use; the signaling methods run one at a time under the connection's lock, as
/// the W3C operations chain orders them. None blocks on the network: transports connect on threads of the configured
/// factory and report through events. Events go to every [EventStream] and listener in the order they were raised.
///
/// # Lifecycle
///
/// [#close()] stops every transceiver, closes the transports and data channels, ends the event streams and moves the
/// connection to the `CLOSED` states; afterwards most methods throw [InvalidStateException].
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.w3.org/TR/webrtc-extensions/ WebRTC Extensions
public final class PeerConnection implements AutoCloseable {
    /// The lock the W3C operations chain is modelled on, shared with the transceivers.
    private final Object lock = new Object();
    /// The source of synchronization sources.
    private final SecureRandom random = new SecureRandom();
    /// The events.
    private final EventHub<PeerConnectionEvent> events;
    /// The transceivers, in creation order; guarded by [#lock].
    private final List<RtpTransceiver> transceivers = new ArrayList<>();
    /// The synchronization sources in use; guarded by [#lock].
    private final Set<Long> ssrcs = new HashSet<>();
    /// The ICE state of each transport; guarded by [#lock].
    private final Map<String, IceTransportState> iceStates = new HashMap<>();
    /// The DTLS state of each transport; guarded by [#lock].
    private final Map<String, DtlsState> dtlsStates = new HashMap<>();
    /// The gathering state of each transport; guarded by [#lock].
    private final Map<String, IceGatheringState> gatheringStates = new HashMap<>();
    /// The JSEP engine; guarded by [#lock].
    private final JsepEngine engine;
    /// The transports.
    private final PeerBackend backend;
    /// The configuration; guarded by [#lock].
    private Configuration configuration;
    /// Whether a `negotiationneeded` event was raised and not yet answered; guarded by [#lock].
    private boolean negotiationNeeded;
    /// The aggregate gathering state; guarded by [#lock].
    private IceGatheringState iceGatheringState = IceGatheringState.NEW;
    /// The aggregate ICE state; guarded by [#lock].
    private IceTransportState iceConnectionState = IceTransportState.NEW;
    /// The aggregate connection state; guarded by [#lock].
    private PeerConnectionState connectionState = PeerConnectionState.NEW;
    /// Whether the connection is closed; guarded by [#lock].
    private boolean closed;
    /// The data channels opened and closed, for the peer-connection statistics.
    private final long[] dataChannelCounters = new long[2];

    /// Creates a connection whose transports `backendFactory` creates.
    PeerConnection(Configuration configuration, PeerBackend.Factory backendFactory) {
        this.configuration = Objects.requireNonNull(configuration, "configuration cannot be null");
        this.events = new EventHub<>(configuration.threadFactory());
        this.engine = new JsepEngine(this);
        this.backend = backendFactory.create(configuration, new BackendListener());
    }

    /// {@return a builder with the default configuration}
    public static Builder builder() {
        return new Builder();
    }

    /// {@return a connection with `configuration`}
    ///
    /// @param configuration the configuration
    public static PeerConnection create(Configuration configuration) {
        return new PeerConnection(configuration, TransportBackend::new);
    }


    /// Creates an offer, the W3C `createOffer`.
    ///
    /// @return the offer, to apply with [#setLocalDescription(JsepDescription)] and send to the peer
    /// @throws InvalidStateException if the connection is closed or the signaling state is neither `STABLE` nor
    ///                               `HAVE_LOCAL_OFFER`
    public JsepDescription createOffer() {
        return createOffer(OfferOptions.DEFAULT);
    }

    /// Creates an offer with options, the W3C `createOffer`.
    ///
    /// @param options the options
    /// @return the offer
    /// @throws InvalidStateException if the connection is closed or the signaling state is neither `STABLE` nor
    ///                               `HAVE_LOCAL_OFFER`
    public JsepDescription createOffer(OfferOptions options) {
        Objects.requireNonNull(options, "options cannot be null");
        synchronized (lock) {
            checkOpen();
            return engine.createOffer(options);
        }
    }

    /// Creates an answer to the applied remote offer, the W3C `createAnswer`.
    ///
    /// @return the answer, to apply with [#setLocalDescription(JsepDescription)] and send to the peer
    /// @throws InvalidStateException if the connection is closed or no remote offer is applied
    public JsepDescription createAnswer() {
        synchronized (lock) {
            checkOpen();
            return engine.createAnswer();
        }
    }

    /// Applies a local description, the W3C `setLocalDescription`.
    ///
    /// The description must be the last one [#createOffer()] or [#createAnswer()] returned, edited at most as RFC 9429
    /// section 5.4 allows; one with an empty SDP stands for the last created one of its type. Applying an offer starts
    /// candidate gathering; applying an answer starts the transports.
    ///
    /// @param description the description
    /// @throws InvalidStateException        if the connection is closed or the type does not fit the signaling state
    /// @throws InvalidModificationException if the SDP was edited beyond what is allowed
    /// @throws OperationErrorException      if the SDP cannot be parsed
    public void setLocalDescription(JsepDescription description) {
        Objects.requireNonNull(description, "description cannot be null");
        synchronized (lock) {
            checkOpen();
            var result = engine.setLocalDescription(description);
            result.ifPresent(negotiated -> applyNegotiation(negotiated, description.type() == JsepType.ANSWER));
            updateNegotiationNeeded();
        }
    }

    /// Creates and applies the description the signaling state calls for, the W3C implicit `setLocalDescription()`:
    /// an answer when a remote offer is applied, an offer otherwise.
    ///
    /// @return the applied description, to send to the peer
    /// @throws InvalidStateException if the connection is closed
    public JsepDescription setLocalDescription() {
        synchronized (lock) {
            checkOpen();
            var state = engine.state();
            var description = state == SignalingState.HAVE_REMOTE_OFFER || state == SignalingState.HAVE_LOCAL_PRANSWER
                    ? engine.createAnswer() : engine.createOffer(OfferOptions.DEFAULT);
            setLocalDescription(description);
            return engine.localDescription().orElse(description);
        }
    }

    /// Applies a remote description, the W3C `setRemoteDescription`.
    ///
    /// A remote offer applied while a local offer is pending rolls the local offer back first. Applying an answer
    /// starts the transports; applying a description in which the peer starts sending raises a
    /// [PeerConnectionEvent.Track] event.
    ///
    /// @param description the description
    /// @throws InvalidStateException   if the connection is closed or the type does not fit the signaling state
    /// @throws InvalidAccessException  if an answer does not match the pending offer
    /// @throws OperationErrorException if the SDP cannot be parsed or lacks what the transports need
    public void setRemoteDescription(JsepDescription description) {
        Objects.requireNonNull(description, "description cannot be null");
        synchronized (lock) {
            checkOpen();
            var result = engine.setRemoteDescription(description);
            result.ifPresent(negotiated -> applyNegotiation(negotiated, description.type() == JsepType.ANSWER));
            updateNegotiationNeeded();
        }
    }

    /// Hands a negotiation outcome to the transports and wires the senders and receivers.
    private void applyNegotiation(Negotiated negotiated, boolean finalAnswer) {
        for (var transport : negotiated.transports()) {
            iceStates.putIfAbsent(transport.id(), IceTransportState.NEW);
            dtlsStates.putIfAbsent(transport.id(), DtlsState.NEW);
        }
        if (finalAnswer) {
            var ids = new HashSet<String>();
            negotiated.transports().forEach(transport -> ids.add(transport.id()));
            iceStates.keySet().retainAll(ids);
            dtlsStates.keySet().retainAll(ids);
            gatheringStates.keySet().retainAll(ids);
        }
        backend.apply(negotiated, finalAnswer);
        updateAggregateStates();
    }

    /// {@return the pending local description if any, else the current one, with the candidates gathered so far}
    public Optional<JsepDescription> localDescription() {
        synchronized (lock) {
            return engine.localDescription();
        }
    }

    /// {@return the local description of the last completed exchange, with the candidates gathered so far}
    public Optional<JsepDescription> currentLocalDescription() {
        synchronized (lock) {
            return engine.currentLocalDescription();
        }
    }

    /// {@return the local description of the exchange in progress}
    public Optional<JsepDescription> pendingLocalDescription() {
        synchronized (lock) {
            return engine.pendingLocalDescription();
        }
    }

    /// {@return the pending remote description if any, else the current one, with the candidates added so far}
    public Optional<JsepDescription> remoteDescription() {
        synchronized (lock) {
            return engine.remoteDescription();
        }
    }

    /// {@return the remote description of the last completed exchange}
    public Optional<JsepDescription> currentRemoteDescription() {
        synchronized (lock) {
            return engine.currentRemoteDescription();
        }
    }

    /// {@return the remote description of the exchange in progress}
    public Optional<JsepDescription> pendingRemoteDescription() {
        synchronized (lock) {
            return engine.pendingRemoteDescription();
        }
    }

    /// {@return the signaling state}
    public SignalingState signalingState() {
        synchronized (lock) {
            return engine.state();
        }
    }

    /// {@return the aggregate candidate gathering state of the transports}
    public IceGatheringState iceGatheringState() {
        synchronized (lock) {
            return iceGatheringState;
        }
    }

    /// {@return the aggregate ICE state of the transports, the W3C `iceConnectionState`}
    public IceTransportState iceConnectionState() {
        synchronized (lock) {
            return iceConnectionState;
        }
    }

    /// {@return the aggregate ICE and DTLS state of the transports}
    public PeerConnectionState connectionState() {
        synchronized (lock) {
            return connectionState;
        }
    }

    /// {@return whether the peer trickles candidates, from `a=ice-options:trickle` in its description, or an empty
    /// optional before a remote description is applied}
    public Optional<Boolean> canTrickleIceCandidates() {
        synchronized (lock) {
            return engine.remoteDescription()
                    .map(description -> description.sdp().contains("a=ice-options:") && description.sdp()
                            .contains("trickle"));
        }
    }

    /// Adds a candidate the peer trickled, the W3C `addIceCandidate`; an empty candidate string ends the peer's
    /// candidates for its media section.
    ///
    /// @param candidate the candidate
    /// @throws InvalidStateException   if the connection is closed or no remote description is applied
    /// @throws OperationErrorException if the candidate matches no media section or belongs to another ICE generation
    public void addIceCandidate(IceCandidateInit candidate) {
        Objects.requireNonNull(candidate, "candidate cannot be null");
        synchronized (lock) {
            checkOpen();
            var target = engine.addIceCandidate(candidate);
            if (target.isPresent()) {
                if (target.get().getValue().isEmpty()) {
                    backend.endOfRemoteCandidates(target.get().getKey());
                } else {
                    backend.addRemoteCandidate(target.get().getKey(), target.get().getValue());
                }
            }
        }
    }

    /// Asks for an ICE restart, the W3C `restartIce`: the next offer carries fresh credentials and a
    /// [PeerConnectionEvent.NegotiationNeeded] event follows. The selected pairs keep working until new ones are
    /// nominated.
    ///
    /// @throws InvalidStateException if the connection is closed
    public void restartIce() {
        synchronized (lock) {
            checkOpen();
            engine.requestIceRestart();
            updateNegotiationNeeded();
        }
    }

    /// {@return the configuration}
    public Configuration getConfiguration() {
        synchronized (lock) {
            return configuration;
        }
    }

    /// Changes the configuration, the W3C `setConfiguration`.
    ///
    /// The ICE servers and ICE transport policy apply to the next gathering; the candidate pool size can change only
    /// before the first local description. Every other setting must be unchanged.
    ///
    /// @param newConfiguration the configuration
    /// @throws InvalidStateException        if the connection is closed
    /// @throws InvalidModificationException if a fixed setting differs
    public void setConfiguration(Configuration newConfiguration) {
        Objects.requireNonNull(newConfiguration, "newConfiguration cannot be null");
        synchronized (lock) {
            checkOpen();
            var current = configuration;
            if (current.bundlePolicy() != newConfiguration.bundlePolicy()
                    || current.rtcpMuxPolicy() != newConfiguration.rtcpMuxPolicy()
                    || !current.certificates().equals(newConfiguration.certificates())
                    || current.iceLite() != newConfiguration.iceLite()
                    || !current.dtlsVersions().equals(newConfiguration.dtlsVersions())
                    || !current.srtpProfiles().equals(newConfiguration.srtpProfiles())
                    || !current.codecs().equals(newConfiguration.codecs())
                    || !current.headerExtensions().equals(newConfiguration.headerExtensions())
                    || current.remoteTrackMode() != newConfiguration.remoteTrackMode()
                    || !current.networkStack().equals(newConfiguration.networkStack())
                    || current.threadFactory() != newConfiguration.threadFactory()
                    || current.clock() != newConfiguration.clock()) {
                throw new InvalidModificationException("only the ICE servers, ICE transport policy and candidate pool "
                        + "size can change");
            }
            if (current.iceCandidatePoolSize() != newConfiguration.iceCandidatePoolSize()
                    && engine.localDescription().isPresent()) {
                throw new InvalidModificationException("the candidate pool size is fixed once a local description "
                        + "is applied");
            }
            configuration = newConfiguration;
        }
    }


    /// Sends a track, the W3C `addTrack`: reuses a transceiver of the track's kind that never sent and is not
    /// stopped, or creates a `SENDRECV` one.
    ///
    /// @param track   the track
    /// @param streams the ids of the media streams the peer sees the track in
    /// @return the sender of the track
    /// @throws InvalidStateException  if the connection is closed
    /// @throws InvalidAccessException if a sender of the connection already sends the track
    public RtpSender addTrack(LocalTrack track, List<String> streams) {
        Objects.requireNonNull(track, "track cannot be null");
        var streamIds = List.copyOf(streams);
        synchronized (lock) {
            checkOpen();
            for (var transceiver : transceivers) {
                if (transceiver.sender().trackOrNull() == track) {
                    throw new InvalidAccessException("the track is already sent");
                }
            }
            for (var transceiver : transceivers) {
                if (transceiver.kind() == track.kind() && !transceiver.stopping && !transceiver.stopped
                        && transceiver.sender().trackOrNull() == null && !transceiver.usedByAddTrack
                        && transceiver.createdByRemote) {
                    var sender = transceiver.sender();
                    sender.setTrack(track);
                    sender.setStreams(streamIds);
                    transceiver.usedByAddTrack = true;
                    if (!transceiver.direction.sends()) {
                        transceiver.direction = TransceiverDirection.of(true, transceiver.direction.receives());
                    }
                    updateNegotiationNeeded();
                    return sender;
                }
            }
            var transceiver = newTransceiver(track.kind(), TransceiverDirection.SENDRECV, streamIds, List.of());
            transceiver.usedByAddTrack = true;
            transceiver.sender().setTrack(track);
            updateNegotiationNeeded();
            return transceiver.sender();
        }
    }

    /// Stops sending a sender's track, the W3C `removeTrack`: detaches the track and drops the sending half of the
    /// transceiver's direction, which makes a negotiation needed.
    ///
    /// @param sender the sender
    /// @throws InvalidStateException  if the connection is closed
    /// @throws InvalidAccessException if the sender belongs to another connection
    public void removeTrack(RtpSender sender) {
        Objects.requireNonNull(sender, "sender cannot be null");
        synchronized (lock) {
            checkOpen();
            var transceiver = transceivers.stream().filter(candidate -> candidate.sender() == sender).findFirst()
                    .orElseThrow(() -> new InvalidAccessException("the sender belongs to another connection"));
            if (transceiver.stopping || transceiver.stopped || sender.trackOrNull() == null) {
                return;
            }
            sender.setTrack(null);
            transceiver.direction = TransceiverDirection.of(false, transceiver.direction.receives());
            updateNegotiationNeeded();
        }
    }

    /// Adds a transceiver of a media kind, without a track, the W3C `addTransceiver`.
    ///
    /// @param kind the media kind
    /// @param init the options
    /// @return the transceiver
    /// @throws InvalidStateException if the connection is closed
    public RtpTransceiver addTransceiver(MediaKind kind, TransceiverInit init) {
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(init, "init cannot be null");
        synchronized (lock) {
            checkOpen();
            var transceiver = newTransceiver(kind, init.direction(), init.streams(), init.sendEncodings());
            updateNegotiationNeeded();
            return transceiver;
        }
    }

    /// Adds a transceiver that sends a track, the W3C `addTransceiver`.
    ///
    /// @param track the track
    /// @param init  the options
    /// @return the transceiver
    /// @throws InvalidStateException if the connection is closed
    public RtpTransceiver addTransceiver(LocalTrack track, TransceiverInit init) {
        Objects.requireNonNull(track, "track cannot be null");
        Objects.requireNonNull(init, "init cannot be null");
        synchronized (lock) {
            checkOpen();
            var transceiver = newTransceiver(track.kind(), init.direction(), init.streams(), init.sendEncodings());
            transceiver.sender().setTrack(track);
            updateNegotiationNeeded();
            return transceiver;
        }
    }

    /// {@return the transceivers, in creation order; a stopped one disappears once the negotiation that rejects its
    /// section completes}
    public List<RtpTransceiver> getTransceivers() {
        synchronized (lock) {
            return List.copyOf(transceivers);
        }
    }

    /// {@return the senders of the transceivers that are not stopped}
    public List<RtpSender> getSenders() {
        synchronized (lock) {
            return transceivers.stream().filter(transceiver -> !transceiver.stopped).map(RtpTransceiver::sender)
                    .toList();
        }
    }

    /// {@return the receivers of the transceivers that are not stopped}
    public List<RtpReceiver> getReceivers() {
        synchronized (lock) {
            return transceivers.stream().filter(transceiver -> !transceiver.stopped).map(RtpTransceiver::receiver)
                    .toList();
        }
    }

    /// Creates a reliable, ordered data channel with the default options, the W3C `createDataChannel`.
    ///
    /// @param label the channel label
    /// @return the channel, which opens once the data section is negotiated and SCTP is established
    /// @throws InvalidStateException if the connection is closed
    public DataChannel createDataChannel(String label) {
        return createDataChannel(label, new DataChannelInit(true, OptionalInt.empty(), Optional.empty(), "", false,
                OptionalInt.empty(), DataChannelPriority.LOW));
    }

    /// Creates a data channel, the W3C `createDataChannel`. The first channel makes a negotiation needed.
    ///
    /// @param label the channel label, at most 65535 UTF-8 bytes
    /// @param init  the options
    /// @return the channel, which opens once the data section is negotiated and SCTP is established
    /// @throws IllegalArgumentException if the label or protocol is longer than 65535 UTF-8 bytes, both
    ///                                  retransmission limits are set, a negotiated channel has no id, or the id is
    ///                                  above 65534
    /// @throws InvalidStateException    if the connection is closed
    public DataChannel createDataChannel(String label, DataChannelInit init) {
        Objects.requireNonNull(label, "label cannot be null");
        Objects.requireNonNull(init, "init cannot be null");
        if (label.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 65535
                || init.protocol().getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 65535) {
            throw new IllegalArgumentException("labels and protocols are at most 65535 bytes");
        }
        if (init.maxRetransmits().isPresent() && init.maxPacketLifeTime().isPresent()) {
            throw new IllegalArgumentException("maxRetransmits and maxPacketLifeTime are mutually exclusive");
        }
        if (init.negotiated() && init.id().isEmpty()) {
            throw new IllegalArgumentException("a negotiated channel needs an id");
        }
        if (init.id().isPresent() && (init.id().getAsInt() < 0 || init.id().getAsInt() > 65534)) {
            throw new IllegalArgumentException("data channel ids are within 0..65534");
        }
        synchronized (lock) {
            checkOpen();
            engine.requestData();
            var channel = backend.createDataChannel(label, init);
            updateNegotiationNeeded();
            return channel;
        }
    }


    /// {@return a snapshot of every statistic of the connection, the W3C `getStats()`}
    public StatsReport getStats() {
        var now = Instant.now();
        var objects = new ArrayList<RtcStats>();
        synchronized (lock) {
            objects.add(new PeerConnectionStats("P", now, dataChannelCounters[0], dataChannelCounters[1]));
        }
        objects.addAll(backend.statistics(now));
        return StatsReport.of(objects);
    }

    /// {@return the statistics of one sender and the objects they reference}
    StatsReport getStats(RtpSender sender) {
        List<Long> sources;
        synchronized (lock) {
            sources = sender.layers().stream().map(Negotiated.SendLayer::ssrc).toList();
        }
        return StatsSelection.select(getStats(), sources, true);
    }

    /// {@return the statistics of one receiver and the objects they reference}
    StatsReport getStats(RtpReceiver receiver) {
        List<Long> sources = new ArrayList<>();
        synchronized (lock) {
            for (var transceiver : transceivers) {
                if (transceiver.receiver() == receiver && transceiver.negotiated != null) {
                    for (var layer : transceiver.negotiated.receiveLayers()) {
                        layer.ssrc().ifPresent(sources::add);
                    }
                }
            }
        }
        return StatsSelection.select(getStats(), sources, false);
    }


    /// {@return a stream of the events raised from now on}
    public EventStream<PeerConnectionEvent> events() {
        return events.open();
    }

    /// Calls `listener` with every event raised from now on, in order, on a thread of the configured factory.
    ///
    /// @param listener the listener
    /// @return the registration, which stops the listener when closed
    public Subscription addListener(Consumer<? super PeerConnectionEvent> listener) {
        return events.addListener(listener)::close;
    }

    /// Closes the connection, the W3C `close`: stops every transceiver, closes the transports and data channels,
    /// and ends the event streams after a final [PeerConnectionEvent.SignalingStateChanged] to `CLOSED`. Idempotent.
    @Override
    public void close() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            for (var transceiver : transceivers) {
                transceiver.stopped = true;
                transceiver.stopping = false;
                transceiver.currentDirection = null;
                transceiver.sender().stopSending();
                transceiver.receiver().track().end();
            }
            engine.close();
            backend.close();
            iceConnectionState = IceTransportState.CLOSED;
            connectionState = PeerConnectionState.CLOSED;
            events.publish(new PeerConnectionEvent.SignalingStateChanged(SignalingState.CLOSED));
            events.end();
        }
    }


    /// {@return the lock the transceivers synchronize on}
    Object lock() {
        return lock;
    }

    /// {@return the backend}
    PeerBackend backend() {
        return backend;
    }

    /// {@return the configuration; the caller holds the lock}
    Configuration configuration() {
        return configuration;
    }

    /// {@return the live transceiver list; the caller holds the lock}
    List<RtpTransceiver> transceiverList() {
        return transceivers;
    }

    /// Fails when the connection is closed.
    void checkOpen() {
        if (closed) {
            throw new InvalidStateException("the connection is closed");
        }
    }

    /// {@return the codec capabilities of `kind`: the configured codecs of that kind}
    List<Codec> codecCapabilities(MediaKind kind) {
        return CodecCatalog.ofKind(configuration.codecs(), kind);
    }

    /// {@return a new encoding with fresh, unique media and retransmission sources}
    Negotiated.SendLayer allocateLayer(Encoding encoding) {
        var ssrc = newSsrc();
        var rtx = newSsrc();
        return new Negotiated.SendLayer(encoding.rid(), ssrc, OptionalLong.of(rtx), encoding);
    }

    /// {@return a synchronization source no stream of the connection uses}
    private long newSsrc() {
        while (true) {
            var candidate = random.nextLong(1, 0x1_0000_0000L);
            if (ssrcs.add(candidate)) {
                return candidate;
            }
        }
    }

    /// Creates and registers a transceiver.
    private RtpTransceiver newTransceiver(MediaKind kind, TransceiverDirection direction, List<String> streams,
                                          List<Encoding> encodings) {
        var sender = new RtpSender(this, kind, streams, encodings);
        var receiver = new RtpReceiver(this, kind, UUID.randomUUID().toString(), configuration.remoteTrackMode());
        var transceiver = new RtpTransceiver(this, kind, direction, sender, receiver);
        transceivers.add(transceiver);
        return transceiver;
    }

    /// Creates a `RECVONLY` transceiver for a section of a remote offer no transceiver takes.
    RtpTransceiver createRemoteTransceiver(MediaKind kind) {
        var transceiver = newTransceiver(kind, TransceiverDirection.RECVONLY, List.of(), List.of());
        transceiver.createdByRemote = true;
        return transceiver;
    }

    /// Removes a transceiver, as when its section is rejected after `stop()` or a rollback undoes its creation.
    void removeTransceiver(RtpTransceiver transceiver) {
        transceivers.remove(transceiver);
        for (var layer : transceiver.sender().layers()) {
            ssrcs.remove(layer.ssrc());
            layer.rtxSsrc().ifPresent(ssrcs::remove);
        }
    }

    /// Raises the track event of a transceiver the peer started sending on.
    void announceTrack(RtpTransceiver transceiver, List<String> streams) {
        events.publish(new PeerConnectionEvent.Track(transceiver.receiver(), streams, transceiver));
    }

    /// Raises a signaling state change.
    void signalingStateChanged(SignalingState state) {
        events.publish(new PeerConnectionEvent.SignalingStateChanged(state));
    }

    /// Recomputes whether a negotiation is needed and raises the event when it becomes needed.
    void updateNegotiationNeeded() {
        if (closed) {
            return;
        }
        var needed = engine.isNegotiationNeeded();
        if (needed && !negotiationNeeded) {
            negotiationNeeded = true;
            events.publish(new PeerConnectionEvent.NegotiationNeeded());
        } else if (!needed && engine.state() == SignalingState.STABLE) {
            negotiationNeeded = false;
        }
    }

    /// {@return the parameters of a sender, with a transaction id}
    RtpSendParameters sendParameters(RtpSender sender, String transactionId) {
        var media = negotiatedMedia(sender);
        var encodings = sender.layers().stream().map(Negotiated.SendLayer::encoding).toList();
        return new RtpSendParameters(transactionId, encodings, headerExtensions(media),
                new RtcpParameters(engine.cname(), media.map(Negotiated.Media::reducedSizeRtcp).orElse(false)),
                codecParameters(media));
    }

    /// {@return the parameters of a receiver}
    RtpReceiveParameters receiveParameters(RtpReceiver receiver) {
        synchronized (lock) {
            var media = transceivers.stream().filter(transceiver -> transceiver.receiver() == receiver)
                    .map(transceiver -> transceiver.negotiated).filter(Objects::nonNull).findFirst();
            return new RtpReceiveParameters(headerExtensions(media),
                    new RtcpParameters(engine.cname(), media.map(Negotiated.Media::reducedSizeRtcp).orElse(false)),
                    codecParameters(media));
        }
    }

    /// {@return the negotiated section of a sender's transceiver}
    private Optional<Negotiated.Media> negotiatedMedia(RtpSender sender) {
        return transceivers.stream().filter(transceiver -> transceiver.sender() == sender)
                .map(transceiver -> transceiver.negotiated).filter(Objects::nonNull).findFirst();
    }

    /// {@return the header extensions of a negotiated section}
    private static List<RtpHeaderExtensionParameters> headerExtensions(Optional<Negotiated.Media> media) {
        var result = new ArrayList<RtpHeaderExtensionParameters>();
        media.ifPresent(value -> value.extensions().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> result.add(new RtpHeaderExtensionParameters(entry.getValue(), entry.getKey(), false))));
        return result;
    }

    /// {@return the codecs of a negotiated section}
    private static List<RtpCodecParameters> codecParameters(Optional<Negotiated.Media> media) {
        var result = new ArrayList<RtpCodecParameters>();
        media.ifPresent(value -> value.codecs().forEach(entry ->
                result.add(new RtpCodecParameters(entry.payloadType(), entry.codec(), entry.feedback()))));
        return result;
    }

    /// {@return whether a sender's transceiver currently sends}
    boolean isSending(RtpSender sender) {
        synchronized (lock) {
            return transceivers.stream().filter(transceiver -> transceiver.sender() == sender).findFirst()
                    .map(transceiver -> transceiver.currentDirection != null && transceiver.currentDirection.sends()
                            && !transceiver.stopping && !transceiver.stopped)
                    .orElse(false);
        }
    }

    /// Recomputes the aggregate gathering, ICE and connection states and raises their changes.
    private void updateAggregateStates() {
        if (closed) {
            return;
        }
        var gathering = aggregateGathering();
        if (gathering != iceGatheringState) {
            iceGatheringState = gathering;
            events.publish(new PeerConnectionEvent.IceGatheringStateChanged(gathering));
            if (gathering == IceGatheringState.COMPLETE) {
                events.publish(new PeerConnectionEvent.EndOfCandidates());
            }
        }
        var ice = aggregateIce();
        if (ice != iceConnectionState) {
            iceConnectionState = ice;
            events.publish(new PeerConnectionEvent.IceConnectionStateChanged(ice));
        }
        var connection = aggregateConnection();
        if (connection != connectionState) {
            connectionState = connection;
            events.publish(new PeerConnectionEvent.ConnectionStateChanged(connection));
        }
    }

    /// {@return the W3C `RTCIceGatheringState` of the transports}
    private IceGatheringState aggregateGathering() {
        var states = gatheringStates.values();
        if (states.contains(IceGatheringState.GATHERING)) {
            return IceGatheringState.GATHERING;
        }
        if (!states.isEmpty() && states.stream().allMatch(state -> state == IceGatheringState.COMPLETE)) {
            return IceGatheringState.COMPLETE;
        }
        return IceGatheringState.NEW;
    }

    /// {@return the W3C `RTCIceConnectionState` of the transports}
    private IceTransportState aggregateIce() {
        var states = iceStates.values();
        if (states.contains(IceTransportState.FAILED)) {
            return IceTransportState.FAILED;
        }
        if (states.contains(IceTransportState.DISCONNECTED)) {
            return IceTransportState.DISCONNECTED;
        }
        if (states.stream().allMatch(state -> state == IceTransportState.NEW || state == IceTransportState.CLOSED)) {
            return IceTransportState.NEW;
        }
        if (states.stream().anyMatch(state -> state == IceTransportState.NEW || state == IceTransportState.CHECKING)) {
            return IceTransportState.CHECKING;
        }
        if (states.stream().allMatch(state -> state == IceTransportState.COMPLETED
                || state == IceTransportState.CLOSED)) {
            return IceTransportState.COMPLETED;
        }
        return IceTransportState.CONNECTED;
    }

    /// {@return the W3C `RTCPeerConnectionState` of the transports}
    private PeerConnectionState aggregateConnection() {
        var ice = iceStates.values();
        var dtls = dtlsStates.values();
        if (ice.contains(IceTransportState.FAILED) || dtls.contains(DtlsState.FAILED)) {
            return PeerConnectionState.FAILED;
        }
        if (ice.contains(IceTransportState.DISCONNECTED)) {
            return PeerConnectionState.DISCONNECTED;
        }
        var iceIdle = ice.stream().allMatch(state -> state == IceTransportState.NEW
                || state == IceTransportState.CLOSED);
        var dtlsIdle = dtls.stream().allMatch(state -> state == DtlsState.NEW || state == DtlsState.CLOSED);
        if (iceIdle && dtlsIdle) {
            return PeerConnectionState.NEW;
        }
        var iceUp = ice.stream().allMatch(state -> state == IceTransportState.CONNECTED
                || state == IceTransportState.COMPLETED || state == IceTransportState.CLOSED);
        var dtlsUp = dtls.stream().allMatch(state -> state == DtlsState.CONNECTED || state == DtlsState.CLOSED);
        return iceUp && dtlsUp ? PeerConnectionState.CONNECTED : PeerConnectionState.CONNECTING;
    }

    /// Receives the backend's transport events.
    private final class BackendListener implements PeerBackend.Listener {
        @Override
        public void onLocalCandidate(String transportId, String candidate) {
            synchronized (lock) {
                if (closed) {
                    return;
                }
                engine.localCandidate(transportId, candidate)
                        .ifPresent(init -> events.publish(new PeerConnectionEvent.IceCandidate(init)));
            }
        }

        @Override
        public void onGatheringState(String transportId, IceGatheringState state) {
            synchronized (lock) {
                if (closed) {
                    return;
                }
                if (state == IceGatheringState.COMPLETE) {
                    engine.localGatheringComplete(transportId);
                }
                gatheringStates.put(transportId, state);
                updateAggregateStates();
            }
        }

        @Override
        public void onCandidateError(String transportId, URI server, int errorCode, String reason) {
            events.publish(new PeerConnectionEvent.IceCandidateError(server, errorCode, reason));
        }

        @Override
        public void onIceState(String transportId, IceTransportState state) {
            synchronized (lock) {
                if (closed || !iceStates.containsKey(transportId)) {
                    return;
                }
                iceStates.put(transportId, state);
                updateAggregateStates();
            }
        }

        @Override
        public void onDtlsState(String transportId, DtlsState state) {
            synchronized (lock) {
                if (closed || !dtlsStates.containsKey(transportId)) {
                    return;
                }
                dtlsStates.put(transportId, state);
                updateAggregateStates();
            }
        }

        @Override
        public void onDataChannel(DataChannel channel) {
            synchronized (lock) {
                if (closed) {
                    return;
                }
                dataChannelCounters[0]++;
            }
            events.publish(new PeerConnectionEvent.DataChannel(channel));
        }
    }

    /// Builds [PeerConnection]s.
    public static final class Builder extends ConfigurationBuilder<Builder> {
        /// The transports, replaceable by tests.
        private PeerBackend.Factory backendFactory = TransportBackend::new;

        /// Creates a builder with the defaults.
        Builder() {
        }

        @Override
        Builder self() {
            return this;
        }

        /// Replaces the transports, for tests that exercise the signaling alone.
        Builder backendFactory(PeerBackend.Factory factory) {
            backendFactory = Objects.requireNonNull(factory);
            return this;
        }

        /// Starts from an existing configuration.
        ///
        /// @param configuration the configuration
        /// @return this builder
        public Builder configuration(Configuration configuration) {
            copyFrom(Objects.requireNonNull(configuration, "configuration cannot be null"));
            return this;
        }

        /// {@return a connection with the configured settings}
        ///
        /// @throws IllegalArgumentException as the [Configuration] constructor does
        public PeerConnection build() {
            return new PeerConnection(configuration(), backendFactory);
        }
    }
}
