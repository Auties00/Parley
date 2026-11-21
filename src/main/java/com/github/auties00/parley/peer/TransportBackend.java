package com.github.auties00.parley.peer;

import com.github.auties00.parley.cc.CongestionConfig;
import com.github.auties00.parley.cc.CongestionController;
import com.github.auties00.parley.cc.TargetBitrate;
import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelInit;
import com.github.auties00.parley.datachannel.SctpConfig;
import com.github.auties00.parley.datachannel.SctpTransport;
import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsConfig;
import com.github.auties00.parley.dtls.DtlsFingerprint;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.ice.IceAgent;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceEvent;
import com.github.auties00.parley.ice.IceParameters;
import com.github.auties00.parley.jitter.AudioPlayoutBuffer;
import com.github.auties00.parley.jitter.AudioPlayoutConfig;
import com.github.auties00.parley.jitter.FeedbackSink;
import com.github.auties00.parley.jitter.VideoAssemblerConfig;
import com.github.auties00.parley.jitter.VideoFrameAssembler;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.payload.PacketizerConfig;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.session.FeedbackMechanism;
import com.github.auties00.parley.rtp.session.KeyframeMethod;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;
import com.github.auties00.parley.rtp.session.ReceiveStreamConfig;
import com.github.auties00.parley.rtp.session.RtpReceiveStream;
import com.github.auties00.parley.rtp.session.RtpRoutingTable;
import com.github.auties00.parley.rtp.session.RtpSendStream;
import com.github.auties00.parley.rtp.session.RtpSession;
import com.github.auties00.parley.rtp.session.SendStreamConfig;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.stats.RtcStats;
import com.github.auties00.parley.transport.SrtpTransport;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/// The production [PeerBackend]: it runs one ICE agent, DTLS transport, SRTP transport, RTP session, congestion
/// controller and, for the data section, SCTP association per negotiated transport, and wires the senders and
/// receivers to RTP streams through the payload formats and jitter buffers.
///
/// @implNote This implementation creates the ICE agent of a transport when the local description first names it, so
/// candidates trickle while the answer is on its way, and starts DTLS and SCTP on a thread of the configured factory
/// once ICE connects; nothing here blocks the peer connection's lock.
final class TransportBackend implements PeerBackend {
    private static final System.Logger LOGGER = System.getLogger(TransportBackend.class.getName());
    /// The largest RTP payload the packetizers produce, which leaves room for headers, SRTP and TURN.
    private static final int MAX_PAYLOAD_SIZE = 1200;
    /// How long a sent packet stays available for retransmission.
    private static final Duration HISTORY = Duration.ofSeconds(1);

    /// The configuration of the connection.
    private final Configuration configuration;
    /// Where transport events go.
    private final Listener listener;
    /// The certificates the transports present.
    private final List<DtlsCertificate> certificates;
    /// The network stack every socket goes through.
    private final NetworkStack networkStack;
    /// The running transports by id.
    private final Map<String, TransportRuntime> transports = new ConcurrentHashMap<>();
    /// The data channels the application created, opened once SCTP is up.
    private final List<DataChannel> channels = new CopyOnWriteArrayList<>();
    /// Whether the backend is closed.
    private volatile boolean closed;

    /// The objects of one transport.
    private static final class TransportRuntime {
        /// The transport id.
        final String id;
        /// The ICE agent.
        final IceAgent ice;
        /// The DTLS transport, once negotiated.
        volatile DtlsTransport dtls;
        /// The SRTP transport, once negotiated.
        volatile SrtpTransport srtp;
        /// The RTP session, once media is negotiated.
        volatile RtpSession session;
        /// The congestion controller, once media is negotiated.
        volatile CongestionController congestion;
        /// The SCTP association, once the data section is negotiated.
        volatile SctpTransport sctp;
        /// The thread connecting DTLS and SCTP, or `null`.
        volatile Thread connector;
        /// The send streams by synchronization source.
        final Map<Long, RtpSendStream> sendStreams = new ConcurrentHashMap<>();
        /// The receive streams by section and layer.
        final Map<String, RtpReceiveStream> receiveStreams = new ConcurrentHashMap<>();

        TransportRuntime(String id, IceAgent ice) {
            this.id = id;
            this.ice = ice;
        }
    }

    /// Creates the backend of a connection.
    TransportBackend(Configuration configuration, Listener listener) {
        this.configuration = configuration;
        this.listener = listener;
        this.certificates = configuration.certificates().isEmpty()
                ? List.of(DtlsCertificate.generateEcdsa()) : configuration.certificates();
        this.networkStack = configuration.networkStack()
                .orElseGet(() -> NetworkStack.system(configuration.threadFactory()));
    }

    @Override
    public List<SdpAttribute.Fingerprint> fingerprints() {
        var result = new ArrayList<SdpAttribute.Fingerprint>();
        for (var certificate : certificates) {
            for (var fingerprint : certificate.fingerprints()) {
                result.add(SdpAttribute.Fingerprint.of(fingerprint.algorithm(), fingerprint.value()));
            }
        }
        return result;
    }

    @Override
    public void startGathering(String transportId, Negotiated.IceCredentials credentials) {
        if (closed) {
            return;
        }
        var parameters = new IceParameters(credentials.usernameFragment(), credentials.password(),
                configuration.iceLite());
        var existing = transports.get(transportId);
        if (existing != null) {
            existing.ice.restart(parameters);
            return;
        }
        var agent = IceAgent.builder()
                .networkStack(networkStack)
                .clock(configuration.clock())
                .servers(configuration.iceServers())
                .policy(configuration.iceTransportPolicy())
                .hostCandidatePolicy(configuration.hostCandidatePolicy())
                .lite(configuration.iceLite())
                .candidatePoolSize(configuration.iceCandidatePoolSize())
                .localParameters(parameters)
                .eventListener(event -> onIceEvent(transportId, event))
                .build();
        transports.put(transportId, new TransportRuntime(transportId, agent));
        agent.gather();
    }

    /// Forwards an ICE event to the connection.
    private void onIceEvent(String transportId, IceEvent event) {
        switch (event) {
            case IceEvent.CandidateGathered(var candidate) -> listener.onLocalCandidate(transportId, candidate.toSdp());
            case IceEvent.GatheringStateChanged(var state) -> listener.onGatheringState(transportId, state);
            case IceEvent.CandidateError(var server, var code, var reason) ->
                    listener.onCandidateError(transportId, server, code, reason);
            case IceEvent.StateChanged(var state) -> listener.onIceState(transportId, state);
            case IceEvent.SelectedPairChanged ignored -> {
            }
        }
    }

    @Override
    public void apply(Negotiated negotiated, boolean finalAnswer) {
        if (closed) {
            return;
        }
        for (var transport : negotiated.transports()) {
            startGathering(transport.id(), transport.local());
            var runtime = transports.get(transport.id());
            runtime.ice.setRole(transport.iceRole());
            runtime.ice.setRemoteParameters(new IceParameters(transport.remote().usernameFragment(),
                    transport.remote().password(), transport.remoteLite()));
            for (var candidate : transport.remoteCandidates()) {
                addRemoteCandidate(transport.id(), candidate);
            }
            if (transport.remoteComplete()) {
                runtime.ice.endOfRemoteCandidates();
            }
            connect(runtime, transport, negotiated);
        }
        if (finalAnswer) {
            var keep = negotiated.transports().stream().map(Negotiated.Transport::id).toList();
            for (var id : List.copyOf(transports.keySet())) {
                if (!keep.contains(id)) {
                    close(transports.remove(id));
                }
            }
        }
        for (var media : negotiated.media()) {
            var runtime = transports.get(media.transportId());
            if (runtime != null) {
                wireMedia(runtime, media);
            }
        }
        for (var runtime : transports.values()) {
            updateRoutes(runtime, negotiated);
        }
    }

    /// Creates the DTLS, SRTP, RTP and SCTP layers of a transport, once, and connects them on a new thread.
    private void connect(TransportRuntime runtime, Negotiated.Transport transport, Negotiated negotiated) {
        if (runtime.dtls == null) {
            var dtls = DtlsTransport.over(runtime.ice, new DtlsConfig(certificates, configuration.srtpProfiles(),
                    configuration.dtlsVersions(), Duration.ofSeconds(1), configuration.clock()));
            dtls.setStateListener(state -> listener.onDtlsState(transport.id(), state));
            runtime.dtls = dtls;
            runtime.srtp = SrtpTransport.dtlsSrtp(dtls);
        }
        if (runtime.session == null && negotiated.media().stream()
                .anyMatch(media -> media.transportId().equals(transport.id()))) {
            var congestion = CongestionController.gcc(new CongestionConfig(configuration.minBitrate(),
                    configuration.startBitrate(), configuration.maxBitrate(), configuration.clock()));
            congestion.setTargetListener(target -> onTargetBitrate(negotiated, target));
            runtime.congestion = congestion;
            runtime.session = RtpSession.builder(runtime.srtp)
                    .clock(configuration.clock())
                    .scheduler(congestion.pacer())
                    .feedbackObserver(congestion)
                    .cname(negotiated.media().getFirst().cname())
                    .reducedSizeRtcp(negotiated.media().stream().allMatch(Negotiated.Media::reducedSizeRtcp))
                    .threadFactory(configuration.threadFactory())
                    .build();
        }
        var data = negotiated.data().filter(section -> section.transportId().equals(transport.id()));
        if (data.isPresent() && runtime.sctp == null) {
            runtime.sctp = SctpTransport.over(runtime.dtls, new SctpConfig(data.get().localPort(),
                    data.get().localMaxMessageSize(), configuration.threadFactory()));
        }
        if (runtime.connector == null) {
            var thread = configuration.threadFactory().newThread(() -> runConnection(runtime, transport, data));
            runtime.connector = thread;
            thread.start();
        }
    }

    /// Waits for ICE, runs the DTLS handshake, then starts SCTP and accepts the peer's data channels.
    private void runConnection(TransportRuntime runtime, Negotiated.Transport transport,
                               Optional<Negotiated.Data> data) {
        try {
            runtime.ice.awaitConnected(configuration.handshakeTimeout());
            var fingerprints = new ArrayList<DtlsFingerprint>();
            for (var fingerprint : transport.remoteFingerprints()) {
                fingerprints.add(new DtlsFingerprint(fingerprint.hashFunction(), fingerprint.digest()));
            }
            runtime.dtls.handshake(transport.dtlsRole(), fingerprints, configuration.handshakeTimeout());
            if (data.isPresent() && runtime.sctp != null) {
                runtime.sctp.start(transport.dtlsRole(), data.get().remotePort(), data.get().remoteMaxMessageSize(),
                        configuration.handshakeTimeout());
                while (!closed) {
                    listener.onDataChannel(runtime.sctp.acceptDataChannel());
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (IOException | RuntimeException exception) {
            if (!closed) {
                LOGGER.log(Level.WARNING, "transport " + transport.id() + " failed", exception);
                listener.onDtlsState(transport.id(), DtlsState.FAILED);
            }
        }
    }

    /// Creates the send and receive streams of a media section and wires them to its sender and receiver.
    private void wireMedia(TransportRuntime runtime, Negotiated.Media media) {
        var session = runtime.session;
        if (session == null || media.codecs().isEmpty()) {
            return;
        }
        var codec = media.codecs().getFirst();
        var extensions = HeaderExtensionMap.of(media.extensions());
        var feedback = feedbackOf(codec);
        var sender = media.transceiver().sender();
        if (media.direction().sends()) {
            var streams = new HashMap<String, RtpSendStream>();
            for (var layer : media.sendLayers()) {
                var stream = runtime.sendStreams.computeIfAbsent(layer.ssrc(), ssrc -> session.createSendStream(
                        new SendStreamConfig(media.mid(), layer.rid(), ssrc, codec.rtxPayloadType().isPresent()
                                ? layer.rtxSsrc() : OptionalLong.empty(), codec.payloadType(), codec.rtxPayloadType(),
                                codec.codec().clockRate(), extensions, feedback, Optional.empty(), Optional.empty(),
                                HISTORY)));
                stream.setKeyframeRequestListener(request -> {
                    var track = sender.track();
                    track.ifPresent(value -> value.requestKeyframe(layer.rid()));
                });
                streams.put(layer.rid().orElse(""), stream);
            }
            var format = PayloadFormat.of(codec.codec());
            var packetizer = format.packetizer(new PacketizerConfig(MAX_PAYLOAD_SIZE));
            var priority = media.kind() == MediaKind.AUDIO ? OutgoingPacketScheduler.Priority.AUDIO
                    : OutgoingPacketScheduler.Priority.VIDEO;
            var first = media.sendLayers().isEmpty() ? "" : media.sendLayers().getFirst().rid().orElse("");
            sender.setPipeline((frame, rid) -> {
                var stream = streams.get(rid.orElse(first));
                if (stream == null) {
                    return;
                }
                try {
                    var payloads = packetizer.packetize(frame);
                    var buffers = new ArrayList<ByteBuffer>(payloads.size());
                    Map<URI, ByteBuffer> values = Map.of();
                    for (var payload : payloads) {
                        buffers.add(payload.payload());
                        if (!payload.extensions().isEmpty()) {
                            values = payload.extensions();
                        }
                    }
                    stream.send(buffers, frame.rtpTimestamp(), true, values, priority);
                } catch (IOException | RuntimeException exception) {
                    LOGGER.log(Level.DEBUG, "a frame could not be sent", exception);
                }
            });
            // TODO: install the DTMF tone sink once the RTP send stream can send another payload type (RFC 4733
            //  events share the audio stream's SSRC and sequence space).
        }
        if (media.direction().receives()) {
            var receiver = media.transceiver().receiver();
            for (var layer : media.receiveLayers()) {
                var key = media.mid() + "/" + layer.rid().orElse("");
                if (runtime.receiveStreams.containsKey(key)) {
                    continue;
                }
                var clockRates = new HashMap<Integer, Integer>();
                var rtxTypes = new HashMap<Integer, Integer>();
                for (var entry : media.codecs()) {
                    clockRates.put(entry.payloadType(), entry.codec().clockRate());
                    entry.rtxPayloadType().ifPresent(rtx -> rtxTypes.put(rtx, entry.payloadType()));
                }
                var stream = session.createReceiveStream(new ReceiveStreamConfig(media.mid(), layer.rid(),
                        layer.ssrc(), layer.rtxSsrc(), clockRates, rtxTypes, extensions, feedback, Optional.empty(),
                        Optional.empty()));
                runtime.receiveStreams.put(key, stream);
                startReceiving(media, layer, stream, receiver);
            }
        }
    }

    /// Feeds a receive stream into the receiver's track: raw packets, or frames through a jitter buffer.
    private void startReceiving(Negotiated.Media media, Negotiated.ReceiveLayer layer, RtpReceiveStream stream,
                                RtpReceiver receiver) {
        var track = receiver.track();
        var clock = configuration.clock();
        if (track.mode() == RemoteTrackMode.RAW_PACKETS) {
            stream.setPacketReceiver(packet -> {
                receiver.recordSources(packet.ssrc(), packet.timestamp(), java.util.OptionalDouble.empty(),
                        packet.csrcs());
                track.deliver(new RemoteTrack.Packet(packet.copy(), layer.rid(), clock.nanos()));
            });
            return;
        }
        var format = PayloadFormat.of(media.codecs().getFirst().codec());
        if (media.kind() == MediaKind.AUDIO) {
            var buffer = AudioPlayoutBuffer.create(format, media.codecs().getFirst().codec().clockRate(),
                    new AudioPlayoutConfig(Duration.ofMillis(20), Duration.ofMillis(20), Duration.ofMillis(500),
                            clock));
            stream.setPacketReceiver(packet -> {
                receiver.recordSources(packet.ssrc(), packet.timestamp(), java.util.OptionalDouble.empty(),
                        packet.csrcs());
                buffer.insert(packet, clock.nanos());
            });
            configuration.threadFactory().newThread(() -> {
                try {
                    while (!closed && !track.isEnded()) {
                        var playout = buffer.next();
                        if (playout instanceof com.github.auties00.parley.jitter.AudioPlayout.Frame(var frame)) {
                            receiver.deliverFrame(frame);
                        } else {
                            track.deliver(playout);
                        }
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
            }).start();
            return;
        }
        var assembler = VideoFrameAssembler.create(format, new VideoAssemblerConfig(Duration.ofMillis(500), clock),
                new FeedbackSink() {
                    @Override
                    public void requestKeyframe() {
                        try {
                            stream.requestKeyframe(KeyframeMethod.PLI);
                        } catch (IOException exception) {
                            LOGGER.log(Level.DEBUG, "a keyframe request could not be sent", exception);
                        }
                    }

                    @Override
                    public void requestRetransmission(List<Integer> sequences) {
                        try {
                            stream.requestRetransmission(sequences);
                        } catch (IOException exception) {
                            LOGGER.log(Level.DEBUG, "a NACK could not be sent", exception);
                        }
                    }
                });
        stream.setPacketReceiver(packet -> {
            receiver.recordSources(packet.ssrc(), packet.timestamp(), java.util.OptionalDouble.empty(),
                    packet.csrcs());
            assembler.insert(packet, clock.nanos());
        });
        configuration.threadFactory().newThread(() -> {
            try {
                while (!closed && !track.isEnded()) {
                    EncodedFrame frame = assembler.next();
                    receiver.deliverFrame(frame);
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }

    /// {@return the RTCP feedback mechanisms negotiated for a codec}
    private static Set<FeedbackMechanism> feedbackOf(Negotiated.CodecEntry codec) {
        var result = EnumSet.noneOf(FeedbackMechanism.class);
        for (var fb : codec.feedback()) {
            switch (fb.type()) {
                case "nack" -> result.add(fb.parameter().filter("pli"::equals).isPresent() ? FeedbackMechanism.PLI
                        : FeedbackMechanism.NACK);
                case "ccm" -> {
                    if (fb.parameter().filter("fir"::equals).isPresent()) {
                        result.add(FeedbackMechanism.FIR);
                    }
                }
                case "goog-remb" -> result.add(FeedbackMechanism.REMB);
                case "transport-cc" -> result.add(FeedbackMechanism.TRANSPORT_CC);
                default -> {
                }
            }
        }
        return result;
    }

    /// Routes the RTP of a transport to its receive streams.
    private void updateRoutes(TransportRuntime runtime, Negotiated negotiated) {
        if (runtime.session == null) {
            return;
        }
        var byMid = new HashMap<String, List<RtpReceiveStream>>();
        var bySsrc = new HashMap<Long, RtpReceiveStream>();
        var byPayloadType = new HashMap<Integer, RtpReceiveStream>();
        for (var media : negotiated.media()) {
            if (!media.transportId().equals(runtime.id)) {
                continue;
            }
            for (var layer : media.receiveLayers()) {
                var stream = runtime.receiveStreams.get(media.mid() + "/" + layer.rid().orElse(""));
                if (stream == null) {
                    continue;
                }
                byMid.computeIfAbsent(media.mid(), ignored -> new ArrayList<>()).add(stream);
                layer.ssrc().ifPresent(ssrc -> bySsrc.put(ssrc, stream));
                for (var codec : media.codecs()) {
                    byPayloadType.putIfAbsent(codec.payloadType(), stream);
                }
            }
        }
        runtime.session.updateRoutes(new RtpRoutingTable(byMid, bySsrc, byPayloadType));
    }

    /// Splits a new target bitrate across the encodings of the senders and tells their tracks.
    private void onTargetBitrate(Negotiated negotiated, TargetBitrate target) {
        var demands = new ArrayList<Map.Entry<Negotiated.Media, Negotiated.SendLayer>>();
        var weight = 0.0;
        for (var media : negotiated.media()) {
            for (var layer : media.sendLayers()) {
                if (layer.encoding().active()) {
                    demands.add(Map.entry(media, layer));
                    weight += layer.encoding().priority().weight();
                }
            }
        }
        for (var demand : demands) {
            var layer = demand.getValue();
            var share = (long) (target.bitsPerSecond() * layer.encoding().priority().weight() / weight);
            var capped = layer.encoding().maxBitrate().isPresent()
                    ? Math.min(share, layer.encoding().maxBitrate().getAsLong()) : share;
            if (demand.getKey().remoteBitrate().isPresent()) {
                capped = Math.min(capped, demand.getKey().remoteBitrate().getAsLong());
            }
            var bitrate = capped;
            demand.getKey().transceiver().sender().track()
                    .ifPresent(track -> track.updateTargetBitrate(layer.rid(), bitrate));
        }
    }

    @Override
    public void addRemoteCandidate(String transportId, String candidate) {
        var runtime = transports.get(transportId);
        if (runtime == null) {
            return;
        }
        try {
            runtime.ice.addRemoteCandidate(IceCandidate.parse(candidate));
        } catch (IllegalArgumentException exception) {
            LOGGER.log(Level.DEBUG, "an unusable remote candidate was skipped", exception);
        }
    }

    @Override
    public void endOfRemoteCandidates(String transportId) {
        var runtime = transports.get(transportId);
        if (runtime != null) {
            runtime.ice.endOfRemoteCandidates();
        }
    }

    @Override
    public DataChannel createDataChannel(String label, DataChannelInit init) {
        for (var runtime : transports.values()) {
            var sctp = runtime.sctp;
            if (sctp != null) {
                try {
                    var channel = sctp.createDataChannel(label, init);
                    channels.add(channel);
                    return channel;
                } catch (IOException exception) {
                    throw new OperationErrorException("the data channel could not be created", exception);
                }
            }
        }
        // TODO: return a channel that opens once the data section is negotiated; this needs a data channel that
        //  exists before its SCTP association (see the integration notes).
        throw new InvalidStateException("the data section is not negotiated yet");
    }

    @Override
    public List<RtcStats> statistics(Instant now) {
        return StatsMapper.map(now, transports.values().stream().map(runtime -> new StatsMapper.TransportView(
                runtime.id, runtime.ice, Optional.ofNullable(runtime.dtls), Optional.ofNullable(runtime.srtp),
                Map.copyOf(runtime.sendStreams), Map.copyOf(runtime.receiveStreams))).toList(), channels, certificates);
    }

    @Override
    public void updateEncodings(RtpSender sender, List<Encoding> encodings) {
        // the allocation reads the encodings at the next target update
    }

    @Override
    public void updateJitterBufferTarget(RtpReceiver receiver, Optional<Duration> target) {
        // TODO: forward the target to the jitter buffer once it exposes one (W3C jitterBufferTarget).
    }

    /// Closes the layers of one transport.
    private void close(TransportRuntime runtime) {
        if (runtime == null) {
            return;
        }
        var connector = runtime.connector;
        if (connector != null) {
            connector.interrupt();
        }
        for (AutoCloseable closeable : new AutoCloseable[]{runtime.sctp, runtime.session, runtime.srtp, runtime.dtls,
                runtime.ice}) {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (Exception exception) {
                    LOGGER.log(Level.DEBUG, "a transport layer failed to close", exception);
                }
            }
        }
    }

    @Override
    public void close() {
        closed = true;
        for (var channel : channels) {
            try {
                channel.close();
            } catch (RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a data channel failed to close", exception);
            }
        }
        for (var runtime : transports.values()) {
            close(runtime);
        }
        transports.clear();
    }

    /// {@return an empty optional; keeps the import of [OptionalInt] for the stream configurations}
    static OptionalInt none() {
        return OptionalInt.empty();
    }
}
