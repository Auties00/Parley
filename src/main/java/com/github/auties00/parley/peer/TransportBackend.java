package com.github.auties00.parley.peer;

import com.github.auties00.parley.cc.AllocationKey;
import com.github.auties00.parley.cc.BitrateAllocator;
import com.github.auties00.parley.cc.CongestionConfig;
import com.github.auties00.parley.cc.CongestionController;
import com.github.auties00.parley.cc.EncodingDemand;
import com.github.auties00.parley.cc.RembGenerator;
import com.github.auties00.parley.cc.TargetBitrate;
import com.github.auties00.parley.cc.TransportFeedbackGenerator;
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
import com.github.auties00.parley.jitter.AudioPlayout;
import com.github.auties00.parley.jitter.AudioPlayoutBuffer;
import com.github.auties00.parley.jitter.AudioPlayoutConfig;
import com.github.auties00.parley.jitter.FeedbackSink;
import com.github.auties00.parley.jitter.VideoAssemblerConfig;
import com.github.auties00.parley.jitter.VideoFrameAssembler;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.payload.DepacketizerConfig;
import com.github.auties00.parley.payload.DtmfToneSequence;
import com.github.auties00.parley.payload.PacketizerConfig;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.session.FecConfig;
import com.github.auties00.parley.rtp.session.FeedbackMechanism;
import com.github.auties00.parley.rtp.session.KeyframeMethod;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;
import com.github.auties00.parley.rtp.session.RedConfig;
import com.github.auties00.parley.rtp.session.ReceiveStreamConfig;
import com.github.auties00.parley.rtp.session.RtcpConfig;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;

/// The production [PeerBackend]: one ICE agent, DTLS transport, SRTP transport, RTP session and congestion
/// controller per negotiated transport, one SCTP association for the data channels, and the wiring from senders and
/// receivers to RTP streams through the payload formats and jitter buffers.
///
/// @implNote This implementation creates the ICE agent and the DTLS and SRTP layers of a transport when a local
/// description first names it, so candidates trickle while the answer is on its way, and runs the DTLS handshake and
/// the SCTP association on a thread of the configured factory once ICE connects. The SCTP association exists from
/// the first data channel on, over a datagram path attached to the DTLS transport the negotiation picks, so channels
/// can be created before the first offer as the W3C API allows.
final class TransportBackend implements PeerBackend {
    private static final System.Logger LOGGER = System.getLogger(TransportBackend.class.getName());
    /// The lowest bitrate given to an audio encoding.
    private static final long MIN_AUDIO_BITRATE = 6_000;
    /// The lowest bitrate given to a video encoding.
    private static final long MIN_VIDEO_BITRATE = 30_000;

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
    /// The send streams of each sender, by RTP stream id (`""` without simulcast).
    private final Map<RtpSender, SenderBinding> senders = new ConcurrentHashMap<>();
    /// The receive bindings, by section and layer.
    private final Map<String, ReceiverBinding> receivers = new ConcurrentHashMap<>();
    /// The allocator that splits each target bitrate across the encodings.
    private final BitrateAllocator allocator = new BitrateAllocator();
    /// Guards the SCTP association's creation.
    private final ReentrantLock dataLock = new ReentrantLock();
    /// The datagram path of the SCTP association, attached to a DTLS transport after its handshake.
    private final DeferredDatagramTransport dataPath = new DeferredDatagramTransport();
    /// The data channels, opened locally or by the peer.
    private final List<DataChannel> channels = new CopyOnWriteArrayList<>();
    /// The SCTP association, or `null` before the first data channel or data section.
    private volatile SctpTransport sctp;
    /// The last negotiation applied.
    private volatile Negotiated negotiated;
    /// Whether the backend is closed.
    private volatile boolean closed;

    /// The objects of one transport.
    private static final class TransportRuntime {
        /// The transport id.
        final String id;
        /// The ICE agent.
        final IceAgent ice;
        /// The DTLS transport over the agent.
        final DtlsTransport dtls;
        /// The SRTP transport over the DTLS transport.
        final SrtpTransport srtp;
        /// The remote candidates handed to the agent.
        final Set<String> remoteCandidates = ConcurrentHashMap.newKeySet();
        /// The RTP session, once media is negotiated.
        volatile RtpSession session;
        /// The congestion controller of the session.
        volatile CongestionController congestion;
        /// The transport-wide feedback generator of the session, when transport-cc is negotiated.
        volatile TransportFeedbackGenerator feedback;
        /// The REMB generator of the session, when goog-remb is negotiated without transport-cc.
        volatile RembGenerator remb;
        /// The extension map of the session.
        volatile HeaderExtensionMap extensions = HeaderExtensionMap.empty();
        /// The thread connecting DTLS and SCTP, or `null`.
        volatile Thread connector;
        /// Serializes the creation of the RTP session with the wiring of streams to it.
        final ReentrantLock wiring = new ReentrantLock();
        /// The DTLS handshake keyed SRTP, so the RTP session may send.
        volatile boolean keyed;

        TransportRuntime(String id, IceAgent ice, DtlsTransport dtls, SrtpTransport srtp) {
            this.id = id;
            this.ice = ice;
            this.dtls = dtls;
            this.srtp = srtp;
        }
    }

    /// The send streams of a sender.
    ///
    /// @param mid         the section
    /// @param transportId the transport
    /// @param kind        the media kind
    /// @param payloadType the payload type sent
    /// @param streams     the streams by RTP stream id (`""` without simulcast)
    /// @param layers      the negotiated layers
    record SenderBinding(String mid, String transportId, MediaKind kind, int payloadType,
                         Map<String, RtpSendStream> streams, List<Negotiated.SendLayer> layers) {
    }

    /// One receive stream with its jitter buffer.
    ///
    /// @param mid         the section
    /// @param transportId the transport
    /// @param kind        the media kind
    /// @param rid         the layer
    /// @param stream      the receive stream
    /// @param receiver    the receiver it feeds
    /// @param playout     the audio playout buffer, or `null`
    /// @param assembler   the video frame assembler, or `null`
    /// @param payloadType the first negotiated payload type
    record ReceiverBinding(String mid, String transportId, MediaKind kind, Optional<String> rid, RtpReceiveStream stream,
                           RtpReceiver receiver, AudioPlayoutBuffer playout, VideoFrameAssembler assembler,
                           int payloadType) {
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
            var current = existing.ice.localParameters();
            if (!current.usernameFragment().equals(parameters.usernameFragment())
                    || !current.password().equals(parameters.password())) {
                existing.ice.restart(parameters);
            }
            return;
        }
        var agent = IceAgent.builder()
                .networkStack(networkStack)
                .clock(configuration.clock())
                .iceServers(configuration.iceServers())
                .transportPolicy(configuration.iceTransportPolicy())
                .hostCandidatePolicy(configuration.hostCandidatePolicy())
                .lite(configuration.iceLite())
                .candidatePoolSize(configuration.iceCandidatePoolSize())
                .tcpCandidates(configuration.tcpCandidates())
                .loopbackCandidates(configuration.loopbackCandidates())
                .localParameters(parameters)
                .eventListener(event -> onIceEvent(transportId, event))
                .build();
        var dtls = DtlsTransport.over(agent, DtlsConfig.of(certificates.getFirst())
                .withCertificates(certificates)
                .withSrtpProfiles(configuration.srtpProfiles())
                .withVersions(configuration.dtlsVersions())
                .withClock(configuration.clock())
                .withThreadFactory(configuration.threadFactory()));
        dtls.setStateListener(state -> listener.onDtlsState(transportId, state));
        transports.put(transportId, new TransportRuntime(transportId, agent, dtls, SrtpTransport.dtlsSrtp(dtls)));
        agent.gather();
    }

    /// Forwards an ICE event to the connection.
    private void onIceEvent(String transportId, IceEvent event) {
        switch (event) {
            case IceEvent.CandidateGathered(var candidate, _) -> listener.onLocalCandidate(transportId,
                    stripPrefix(candidate.toSdp()));
            case IceEvent.GatheringStateChanged(var state) -> listener.onGatheringState(transportId, state);
            case IceEvent.CandidateError(var server, _, var code, var reason) ->
                    listener.onCandidateError(transportId, server, code, reason);
            case IceEvent.StateChanged(var state) -> listener.onIceState(transportId, state);
            case IceEvent.SelectedPairChanged ignored -> {
            }
        }
    }

    /// {@return a candidate attribute value without its `candidate:` prefix}
    private static String stripPrefix(String candidate) {
        return candidate.startsWith("candidate:") ? candidate.substring("candidate:".length()) : candidate;
    }

    @Override
    public void apply(Negotiated outcome, boolean finalAnswer) {
        if (closed) {
            return;
        }
        negotiated = outcome;
        for (var transport : outcome.transports()) {
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
            prepare(runtime, transport, outcome);
        }
        if (finalAnswer) {
            var keep = outcome.transports().stream().map(Negotiated.Transport::id).toList();
            for (var id : List.copyOf(transports.keySet())) {
                if (!keep.contains(id)) {
                    close(transports.remove(id));
                }
            }
            for (var mid : outcome.closedMids()) {
                stopSection(mid);
            }
        }
        for (var runtime : transports.values()) {
            wire(runtime);
        }
    }

    /// Builds the RTP session of a keyed transport when it has none, then wires the streams of the last negotiation
    /// to it; does nothing before the DTLS handshake keys SRTP.
    private void wire(TransportRuntime runtime) {
        var outcome = negotiated;
        if (outcome == null || !runtime.keyed || closed) {
            return;
        }
        runtime.wiring.lock();
        try {
            var media = outcome.media().stream().filter(section -> section.transportId().equals(runtime.id))
                    .toList();
            if (media.isEmpty()) {
                return;
            }
            if (runtime.session == null) {
                buildSession(runtime, media);
            }
            for (var section : media) {
                wireSending(runtime, section);
                wireReceiving(runtime, section);
            }
            updateRoutes(runtime);
        } finally {
            runtime.wiring.unlock();
        }
    }

    /// Creates the SCTP association a transport needs, once, and starts its connection.
    private void prepare(TransportRuntime runtime, Negotiated.Transport transport, Negotiated outcome) {
        var media = outcome.media().stream().filter(section -> section.transportId().equals(transport.id())).toList();
        var data = outcome.data().filter(section -> section.transportId().equals(transport.id()));
        if (data.isPresent()) {
            sctp();
        }
        if (runtime.connector == null) {
            var hasMedia = !media.isEmpty();
            var thread = configuration.threadFactory().newThread(() -> connect(runtime, transport, data, hasMedia));
            runtime.connector = thread;
            thread.start();
        }
    }

    /// Creates the congestion controller, the RTP session and its feedback generators of a keyed transport.
    private void buildSession(TransportRuntime runtime, List<Negotiated.Media> media) {
        var extensions = new HashMap<Integer, URI>();
        media.forEach(section -> extensions.putAll(section.extensions()));
        runtime.extensions = HeaderExtensionMap.of(extensions).withAllowMixed(true);
        var congestion = CongestionController.gcc(CongestionConfig.defaults()
                .withBitrates(configuration.minBitrate(), configuration.startBitrate(), configuration.maxBitrate())
                .withClock(configuration.clock())
                .withThreadFactory(configuration.threadFactory()));
        congestion.setTargetListener(target -> allocate(runtime, target));
        runtime.congestion = congestion;
        var reducedSize = media.stream().allMatch(Negotiated.Media::reducedSizeRtcp);
        var webrtc = RtcpConfig.webrtc();
        var rtcp = new RtcpConfig(webrtc.avpf(), reducedSize, webrtc.extendedReports(), webrtc.minimumInterval(),
                webrtc.trrInterval(), webrtc.sessionBandwidthBps());
        var holder = new RtpSession[1];
        var transportCc = media.stream().anyMatch(section -> hasFeedback(section, "transport-cc"));
        var remb = !transportCc && media.stream().anyMatch(section -> hasFeedback(section, "goog-remb"));
        var session = RtpSession.builder(runtime.srtp)
                .clock(configuration.clock())
                .scheduler(congestion.pacer())
                .feedbackObserver(congestion)
                .arrivalObserver(arrival -> {
                    var feedback = runtime.feedback;
                    if (feedback != null && arrival.transportSequence().isPresent()) {
                        feedback.onPacketReceived(arrival.transportSequence().getAsInt(), arrival.ssrc(),
                                arrival.arrivalNanos());
                    }
                    var generator = runtime.remb;
                    if (generator != null && arrival.absSendTime().isPresent()) {
                        generator.onPacketReceived(arrival.ssrc(), arrival.absSendTime().getAsInt(),
                                arrival.sizeBytes(), arrival.arrivalNanos());
                    }
                })
                .rtcp(rtcp)
                .cname(media.getFirst().cname())
                .extensions(runtime.extensions)
                .threadFactory(configuration.threadFactory())
                .build();
        holder[0] = session;
        runtime.session = session;
        if (transportCc) {
            var generator = TransportFeedbackGenerator.create(session.localSsrc(), configuration.clock(),
                    packet -> sendRtcp(holder[0], packet));
            generator.start(configuration.threadFactory());
            runtime.feedback = generator;
        } else if (remb) {
            var generator = RembGenerator.create(session.localSsrc(), configuration.clock(),
                    packet -> sendRtcp(holder[0], packet));
            generator.start(configuration.threadFactory());
            runtime.remb = generator;
        }
    }

    /// {@return whether a section negotiated a feedback mechanism on its first codec}
    private static boolean hasFeedback(Negotiated.Media media, String type) {
        return !media.codecs().isEmpty() && media.codecs().getFirst().feedback().stream()
                .anyMatch(feedback -> feedback.type().equals(type));
    }

    /// Sends an RTCP packet a feedback generator produced.
    private static void sendRtcp(RtpSession session, com.github.auties00.parley.rtp.rtcp.RtcpPacket packet) {
        if (session == null) {
            return;
        }
        try {
            session.sendRtcp(packet);
        } catch (IOException | RuntimeException exception) {
            LOGGER.log(Level.DEBUG, "feedback could not be sent", exception);
        }
    }

    /// Waits for ICE, runs the DTLS handshake, then starts SCTP and accepts the peer's data channels.
    private void connect(TransportRuntime runtime, Negotiated.Transport transport, Optional<Negotiated.Data> data,
                         boolean hasMedia) {
        try {
            runtime.ice.awaitConnected(configuration.handshakeTimeout());
            var fingerprints = new ArrayList<DtlsFingerprint>();
            for (var fingerprint : transport.remoteFingerprints()) {
                fingerprints.add(DtlsFingerprint.parse(fingerprint.attributeValue().orElseThrow()));
            }
            if (hasMedia) {
                runtime.dtls.handshake(transport.dtlsRole(), fingerprints, configuration.handshakeTimeout());
                runtime.keyed = true;
                wire(runtime);
            } else {
                runtime.dtls.handshakeWithoutSrtp(transport.dtlsRole(), fingerprints,
                        configuration.handshakeTimeout());
                runtime.keyed = runtime.dtls.srtpKeys().isPresent();
                wire(runtime);
            }
            if (data.isPresent()) {
                var association = sctp();
                dataPath.attach(runtime.dtls.applicationData());
                association.start(transport.dtlsRole(), data.get().remotePort(), java.util.OptionalLong.of(data.get().remoteMaxMessageSize()),
                        configuration.handshakeTimeout());
                while (!closed) {
                    var channel = association.acceptDataChannel();
                    channels.add(channel);
                    listener.onDataChannel(channel);
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (IOException | RuntimeException exception) {
            if (!closed) {
                LOGGER.log(Level.WARNING, "transport " + transport.id() + " failed", exception);
                if (runtime.dtls.state() != DtlsState.CONNECTED) {
                    listener.onDtlsState(transport.id(), DtlsState.FAILED);
                }
            }
        }
    }

    /// {@return the SCTP association, created over the deferred datagram path on first use}
    private SctpTransport sctp() {
        var current = sctp;
        if (current != null) {
            return current;
        }
        dataLock.lock();
        try {
            if (sctp == null) {
                sctp = SctpTransport.overDatagrams(dataPath, SctpConfig.defaults()
                        .withLocalPort(JsepEngine.SCTP_PORT)
                        .withMaxMessageSize(JsepEngine.MAX_MESSAGE_SIZE)
                        .withThreadFactory(configuration.threadFactory()));
            }
            return sctp;
        } finally {
            dataLock.unlock();
        }
    }

    /// Creates the send streams of a section and wires its sender to them.
    private void wireSending(TransportRuntime runtime, Negotiated.Media media) {
        var sender = media.transceiver().sender();
        if (!media.direction().sends() || media.codecs().isEmpty()) {
            var previous = senders.remove(sender);
            if (previous != null) {
                sender.stopSending();
            }
            return;
        }
        var codec = media.codecs().getFirst();
        var previous = senders.get(sender);
        if (previous != null && previous.payloadType() == codec.payloadType()
                && previous.layers().equals(media.sendLayers())) {
            return;
        }
        var session = runtime.session;
        var streams = new HashMap<String, RtpSendStream>();
        for (var layer : media.sendLayers()) {
            var existing = previous == null ? null : previous.streams().get(layer.rid().orElse(""));
            if (existing != null) {
                try {
                    session.removeSendStream(existing);
                } catch (IOException | RuntimeException exception) {
                    LOGGER.log(Level.DEBUG, "an old send stream could not be removed", exception);
                }
            }
            var builder = SendStreamConfig.builder(media.mid(), layer.ssrc(), codec.payloadType(),
                    codec.codec().clockRate())
                    .extensions(runtime.extensions)
                    .feedback(feedbackOf(codec));
            layer.rid().ifPresent(builder::rid);
            if (codec.rtxPayloadType().isPresent() && layer.rtxSsrc().isPresent()) {
                builder.rtx(layer.rtxSsrc().getAsLong(), codec.rtxPayloadType().getAsInt());
            }
            if (media.kind() == MediaKind.AUDIO && media.redPayloadType().isPresent()) {
                builder.red(new RedConfig(media.redPayloadType().getAsInt(), 1));
            } else if (media.kind() == MediaKind.VIDEO && media.redPayloadType().isPresent()
                    && media.ulpfecPayloadType().isPresent()) {
                builder.fec(new FecConfig.Ulpfec(media.redPayloadType().getAsInt(),
                        media.ulpfecPayloadType().getAsInt(), 10));
            }
            var stream = session.createSendStream(builder.build());
            stream.setKeyframeRequestListener(request -> sender.track()
                    .ifPresent(track -> track.requestKeyframe(layer.rid())));
            streams.put(layer.rid().orElse(""), stream);
        }
        senders.put(sender, new SenderBinding(media.mid(), media.transportId(), media.kind(), codec.payloadType(),
                Map.copyOf(streams), media.sendLayers()));
        var format = PayloadFormat.of(codec.codec());
        var packetizers = new HashMap<String, com.github.auties00.parley.payload.Packetizer>();
        streams.keySet().forEach(rid -> packetizers.put(rid, format.packetizer(PacketizerConfig.defaults())));
        var priority = media.kind() == MediaKind.AUDIO ? OutgoingPacketScheduler.Priority.AUDIO
                : OutgoingPacketScheduler.Priority.VIDEO;
        var first = media.sendLayers().getFirst().rid().orElse("");
        var lastTimestamp = new long[1];
        sender.setPipeline((frame, rid) -> {
            var key = rid.orElse(first);
            var stream = streams.get(key);
            if (stream == null) {
                return;
            }
            try {
                var payloads = new ArrayList<RtpSendStream.Payload>();
                for (var payload : packetizers.get(key).packetize(frame)) {
                    payloads.add(new RtpSendStream.Payload(payload.payload(), payload.marker(), payload.extensions()));
                }
                if (!payloads.isEmpty()) {
                    lastTimestamp[0] = frame.rtpTimestamp();
                    stream.send(payloads, frame.rtpTimestamp(), priority);
                }
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a frame could not be sent", exception);
            }
        });
        var dtmf = sender.dtmf();
        if (dtmf.isPresent()) {
            var telephoneEvent = media.telephoneEvent();
            if (telephoneEvent.isPresent()) {
                var stream = streams.get(first);
                var eventPt = telephoneEvent.get().payloadType();
                var clockRate = telephoneEvent.get().codec().clockRate();
                dtmf.get().setSink((tone, duration) -> playTone(stream, eventPt, clockRate, lastTimestamp, tone,
                        duration));
            } else {
                dtmf.get().setSink(null);
            }
        }
    }

    /// Sends the RFC 4733 packets of one tone, paced at their send times, and returns after the last end packet.
    private void playTone(RtpSendStream stream, int payloadType, int clockRate, long[] lastTimestamp, char tone,
                          Duration duration) throws InterruptedException {
        var sequence = new DtmfToneSequence(String.valueOf(tone), duration, DtmfToneSequence.DEFAULT_INTER_TONE_GAP);
        var base = (lastTimestamp[0] + clockRate / 50) & 0xFFFF_FFFFL;
        var start = System.nanoTime();
        for (var packet : sequence.packets(clockRate)) {
            var wait = packet.sendTime().toNanos() - (System.nanoTime() - start);
            if (wait > 0) {
                Thread.sleep(Duration.ofNanos(wait));
            }
            try {
                stream.sendWithPayloadType(payloadType, List.of(new RtpSendStream.Payload(packet.event().toBuffer(),
                        packet.marker(), Map.of())), (base + packet.timestampOffset()) & 0xFFFF_FFFFL,
                        OutgoingPacketScheduler.Priority.AUDIO);
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a DTMF packet could not be sent", exception);
            }
        }
    }

    /// Creates the receive streams of a section and feeds its receiver from them.
    private void wireReceiving(TransportRuntime runtime, Negotiated.Media media) {
        if (!media.direction().receives() || media.codecs().isEmpty()) {
            return;
        }
        var receiver = media.transceiver().receiver();
        for (var layer : media.receiveLayers()) {
            var key = media.mid() + "/" + layer.rid().orElse("");
            if (receivers.containsKey(key)) {
                continue;
            }
            var first = media.codecs().getFirst();
            var builder = ReceiveStreamConfig.builder(first.payloadType(), first.codec().clockRate())
                    .mid(media.mid())
                    .extensions(runtime.extensions)
                    .feedback(feedbackOf(first));
            layer.rid().ifPresent(builder::rid);
            layer.ssrc().ifPresent(builder::ssrc);
            layer.rtxSsrc().ifPresent(builder::rtxSsrc);
            for (var codec : media.codecs()) {
                builder.payloadType(codec.payloadType(), codec.codec().clockRate());
                codec.rtxPayloadType().ifPresent(rtx -> builder.rtxPayloadType(rtx, codec.payloadType()));
            }
            if (media.kind() == MediaKind.AUDIO) {
                media.redPayloadType().ifPresent(builder::redPayloadType);
            } else if (media.redPayloadType().isPresent() && media.ulpfecPayloadType().isPresent()) {
                builder.fec(new FecConfig.Ulpfec(media.redPayloadType().getAsInt(),
                        media.ulpfecPayloadType().getAsInt(), 10));
            }
            media.telephoneEvent().ifPresent(event -> builder.payloadType(event.payloadType(),
                    event.codec().clockRate()));
            var stream = runtime.session.createReceiveStream(builder.build());
            receivers.put(key, startReceiving(runtime, media, layer, stream, receiver, first));
        }
    }

    /// Feeds a receive stream into the receiver's track: raw packets, or frames through a jitter buffer.
    private ReceiverBinding startReceiving(TransportRuntime runtime, Negotiated.Media media,
                                           Negotiated.ReceiveLayer layer, RtpReceiveStream stream,
                                           RtpReceiver receiver, Negotiated.CodecEntry codec) {
        var track = receiver.track();
        var clock = configuration.clock();
        var audioLevelId = runtime.extensions.idOf(CodecCatalog.AUDIO_LEVEL);
        if (track.mode() == RemoteTrackMode.RAW_PACKETS) {
            stream.setPacketReceiver(packet -> {
                record(receiver, packet, audioLevelId);
                track.deliver(new RemoteTrack.Packet(packet.copy(), layer.rid(), clock.nanos()));
            });
            return new ReceiverBinding(media.mid(), media.transportId(), media.kind(), layer.rid(), stream, receiver,
                    null, null, codec.payloadType());
        }
        var format = PayloadFormat.of(codec.codec());
        var depacketizer = depacketizerConfig(runtime.extensions);
        if (media.kind() == MediaKind.AUDIO) {
            var buffer = AudioPlayoutBuffer.create(format, codec.codec().clockRate(), AudioPlayoutConfig.defaults()
                    .withClock(clock)
                    .withJitterBufferTarget(receiver.jitterBufferTarget())
                    .withDepacketizer(depacketizer));
            stream.setPacketReceiver(packet -> {
                if (packet.payloadType() != codec.payloadType()) {
                    return;
                }
                record(receiver, packet, audioLevelId);
                buffer.insert(packet, clock.nanos());
            });
            configuration.threadFactory().newThread(() -> {
                try {
                    while (!closed && !track.isEnded()) {
                        var playout = buffer.next();
                        if (playout instanceof AudioPlayout.Frame(var frame, var ignored)) {
                            receiver.deliverFrame(frame);
                        } else {
                            track.deliver(playout);
                        }
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                } catch (RuntimeException exception) {
                    LOGGER.log(Level.DEBUG, "the audio playout loop stopped", exception);
                }
            }).start();
            return new ReceiverBinding(media.mid(), media.transportId(), media.kind(), layer.rid(), stream, receiver,
                    buffer, null, codec.payloadType());
        }
        var assembler = VideoFrameAssembler.create(format, VideoAssemblerConfig.defaults()
                .withClock(clock)
                .withRetransmissions(false)
                .withDepacketizer(depacketizer), new FeedbackSink() {
            @Override
            public void requestKeyframe() {
                try {
                    stream.requestKeyframe(KeyframeMethod.PLI);
                } catch (IOException | RuntimeException exception) {
                    LOGGER.log(Level.DEBUG, "a keyframe request could not be sent", exception);
                }
            }

            @Override
            public void requestRetransmission(List<Integer> sequences) {
                try {
                    stream.requestRetransmission(sequences);
                } catch (IOException | RuntimeException exception) {
                    LOGGER.log(Level.DEBUG, "a NACK could not be sent", exception);
                }
            }
        });
        stream.setPacketReceiver(packet -> {
            record(receiver, packet, audioLevelId);
            assembler.insert(packet, clock.nanos());
        });
        configuration.threadFactory().newThread(() -> {
            try {
                while (!closed && !track.isEnded()) {
                    receiver.deliverFrame(assembler.next());
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "the video assembly loop stopped", exception);
            }
        }).start();
        return new ReceiverBinding(media.mid(), media.transportId(), media.kind(), layer.rid(), stream, receiver, null,
                assembler, codec.payloadType());
    }

    /// {@return the depacketizer settings for the negotiated extension ids}
    private static DepacketizerConfig depacketizerConfig(HeaderExtensionMap extensions) {
        var config = new DepacketizerConfig(OptionalInt.empty(), OptionalInt.empty());
        var audioLevel = extensions.idOf(CodecCatalog.AUDIO_LEVEL);
        if (audioLevel.isPresent()) {
            config = config.withAudioLevelExtensionId(audioLevel.getAsInt());
        }
        var dependencyDescriptor = extensions.idOf(CodecCatalog.DEPENDENCY_DESCRIPTOR);
        if (dependencyDescriptor.isPresent()) {
            config = config.withDependencyDescriptorExtensionId(dependencyDescriptor.getAsInt());
        }
        return config;
    }

    /// Records the sources of a received packet on its receiver, with the RFC 6464 audio level when present.
    private static void record(RtpReceiver receiver, RtpPacket packet, OptionalInt audioLevelId) {
        var level = OptionalDouble.empty();
        if (audioLevelId.isPresent()) {
            var value = packet.extension(audioLevelId.getAsInt());
            if (value.isPresent() && value.get().hasRemaining()) {
                var dbov = value.get().get(value.get().position()) & 0x7F;
                level = OptionalDouble.of(Math.pow(10, -dbov / 20.0));
            }
        }
        receiver.recordSources(packet.ssrc(), packet.timestamp(), level, packet.csrcs());
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
    private void updateRoutes(TransportRuntime runtime) {
        var session = runtime.session;
        if (session == null) {
            return;
        }
        var streams = receivers.values().stream().filter(binding -> binding.transportId().equals(runtime.id))
                .map(ReceiverBinding::stream).toList();
        session.updateRoutes(RtpRoutingTable.of(runtime.extensions, streams));
    }

    /// Stops the streams of a rejected section and ends its jitter buffers.
    private void stopSection(String mid) {
        for (var entry : List.copyOf(receivers.entrySet())) {
            var binding = entry.getValue();
            if (!binding.mid().equals(mid)) {
                continue;
            }
            receivers.remove(entry.getKey());
            var runtime = transports.get(binding.transportId());
            if (runtime != null && runtime.session != null) {
                runtime.session.removeReceiveStream(binding.stream());
            }
            closeJitter(binding);
        }
        for (var entry : List.copyOf(senders.entrySet())) {
            var binding = entry.getValue();
            if (!binding.mid().equals(mid)) {
                continue;
            }
            senders.remove(entry.getKey());
            entry.getKey().stopSending();
            var runtime = transports.get(binding.transportId());
            if (runtime != null && runtime.session != null) {
                for (var stream : binding.streams().values()) {
                    try {
                        runtime.session.removeSendStream(stream);
                    } catch (IOException | RuntimeException exception) {
                        LOGGER.log(Level.DEBUG, "a send stream could not be removed", exception);
                    }
                }
            }
        }
    }

    /// Closes the jitter buffer of a receive binding.
    private static void closeJitter(ReceiverBinding binding) {
        if (binding.playout() != null) {
            binding.playout().close();
        }
        if (binding.assembler() != null) {
            binding.assembler().close();
        }
    }

    /// Splits a new target bitrate across the active encodings of a transport and tells their tracks.
    private void allocate(TransportRuntime runtime, TargetBitrate target) {
        var outcome = negotiated;
        if (outcome == null) {
            return;
        }
        var demands = new ArrayList<EncodingDemand>();
        var tracks = new HashMap<AllocationKey, LocalTrack>();
        for (var media : outcome.media()) {
            if (!media.transportId().equals(runtime.id) || !media.direction().sends()) {
                continue;
            }
            var sender = media.transceiver().sender();
            var track = sender.track();
            for (var layer : media.sendLayers()) {
                var encoding = layer.encoding();
                var key = new AllocationKey(media.mid(), layer.rid());
                var min = media.kind() == MediaKind.AUDIO ? MIN_AUDIO_BITRATE : MIN_VIDEO_BITRATE;
                var max = encoding.maxBitrate().orElse(configuration.maxBitrate());
                if (media.remoteBitrate().isPresent()) {
                    max = Math.min(max, media.remoteBitrate().getAsLong());
                }
                demands.add(new EncodingDemand(key, encoding.active() && track.isPresent(), min, Math.max(min, max),
                        encoding.priority().weight(), encoding.scaleResolutionDownBy().orElse(1)));
                track.ifPresent(value -> tracks.put(key, value));
            }
        }
        if (demands.isEmpty()) {
            return;
        }
        for (var entry : allocator.allocate(target.bitsPerSecond(), demands).entrySet()) {
            var track = tracks.get(entry.getKey());
            if (track != null) {
                track.updateTargetBitrate(entry.getKey().rid(), entry.getValue());
            }
        }
    }

    @Override
    public void addRemoteCandidate(String transportId, String candidate) {
        var runtime = transports.get(transportId);
        if (runtime == null || !runtime.remoteCandidates.add(candidate)) {
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
        try {
            var channel = sctp().createDataChannel(label, init);
            channels.add(channel);
            return channel;
        } catch (IOException exception) {
            throw new OperationErrorException("the data channel could not be created", exception);
        }
    }

    @Override
    public List<RtcStats> statistics(Instant now) {
        var views = new ArrayList<StatsMapper.TransportView>();
        for (var runtime : transports.values()) {
            views.add(new StatsMapper.TransportView(runtime.id, runtime.ice, runtime.dtls, runtime.srtp,
                    Optional.ofNullable(runtime.congestion)));
        }
        var sendViews = new ArrayList<StatsMapper.SendView>();
        senders.forEach((sender, binding) -> binding.streams().forEach((rid, stream) -> sendViews.add(
                new StatsMapper.SendView(binding.mid(), binding.transportId(), binding.kind(), binding.payloadType(),
                        stream, sender.track(), indexOf(binding.layers(), rid)))));
        var receiveViews = new ArrayList<StatsMapper.ReceiveView>();
        for (var binding : receivers.values()) {
            receiveViews.add(new StatsMapper.ReceiveView(binding.mid(), binding.transportId(), binding.kind(),
                    binding.payloadType(), binding.stream(), binding.receiver().track(),
                    Optional.ofNullable(binding.playout()), Optional.ofNullable(binding.assembler())));
        }
        return StatsMapper.map(now, views, sendViews, receiveViews, Optional.ofNullable(negotiated), channels,
                certificates);
    }

    /// {@return the index of the layer named `rid` (`""` for none)}
    private static int indexOf(List<Negotiated.SendLayer> layers, String rid) {
        for (var index = 0; index < layers.size(); index++) {
            if (layers.get(index).rid().orElse("").equals(rid)) {
                return index;
            }
        }
        return 0;
    }

    @Override
    public void updateEncodings(RtpSender sender, List<Encoding> encodings) {
        for (var runtime : transports.values()) {
            var congestion = runtime.congestion;
            if (congestion != null) {
                allocate(runtime, congestion.currentTarget());
            }
        }
    }

    @Override
    public void updateJitterBufferTarget(RtpReceiver receiver, Optional<Duration> target) {
        for (var binding : receivers.values()) {
            if (binding.receiver() == receiver && binding.playout() != null) {
                binding.playout().setJitterBufferTarget(target);
            }
        }
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
        for (AutoCloseable closeable : new AutoCloseable[]{runtime.feedback, runtime.remb, runtime.session,
                runtime.congestion, runtime.srtp, runtime.dtls, runtime.ice}) {
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
        var association = sctp;
        if (association != null) {
            association.close();
        }
        for (var binding : receivers.values()) {
            closeJitter(binding);
        }
        for (var runtime : transports.values()) {
            close(runtime);
        }
        transports.clear();
    }

    /// A datagram path that buffers its receiver until it is attached to the DTLS application data of the transport
    /// the data section is negotiated on.
    private static final class DeferredDatagramTransport implements DatagramTransport {
        /// The attached transport, or `null`.
        private volatile DatagramTransport target;
        /// The receiver to install on the target.
        private volatile PacketReceiver receiver = (packet, arrival) -> { };

        /// Attaches the path to `transport`, handing it the receiver.
        void attach(DatagramTransport transport) {
            target = Objects.requireNonNull(transport);
            transport.setReceiver(receiver);
        }

        @Override
        public void send(ByteBuffer datagram) throws IOException {
            var current = target;
            if (current == null) {
                throw new IOException("the data channel transport is not connected yet");
            }
            current.send(datagram);
        }

        @Override
        public void setReceiver(PacketReceiver newReceiver) {
            receiver = Objects.requireNonNull(newReceiver);
            var current = target;
            if (current != null) {
                current.setReceiver(newReceiver);
            }
        }

        @Override
        public int maxDatagramSize() {
            var current = target;
            return current == null ? 1200 : current.maxDatagramSize();
        }

        @Override
        public void close() {
            target = null;
        }
    }
}
