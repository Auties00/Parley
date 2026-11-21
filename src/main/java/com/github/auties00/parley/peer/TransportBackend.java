package com.github.auties00.parley.peer;

import com.github.auties00.parley.cc.AllocationKey;
import com.github.auties00.parley.cc.BitrateAllocator;
import com.github.auties00.parley.cc.CongestionConfig;
import com.github.auties00.parley.cc.CongestionControlFeedbackGenerator;
import com.github.auties00.parley.cc.CongestionController;
import com.github.auties00.parley.cc.EncodingDemand;
import com.github.auties00.parley.cc.RembGenerator;
import com.github.auties00.parley.cc.TargetBitrate;
import com.github.auties00.parley.cc.TransportFeedbackGenerator;
import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelEvent;
import com.github.auties00.parley.datachannel.DataChannelInit;
import com.github.auties00.parley.datachannel.SctpConfig;
import com.github.auties00.parley.datachannel.SctpTransport;
import com.github.auties00.parley.datachannel.SctpTransportState;
import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsConfig;
import com.github.auties00.parley.dtls.DtlsFingerprint;
import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.ice.IceAgent;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceEvent;
import com.github.auties00.parley.ice.IceException;
import com.github.auties00.parley.ice.IceParameters;
import com.github.auties00.parley.jitter.AudioPlayoutBuffer;
import com.github.auties00.parley.jitter.AudioPlayoutConfig;
import com.github.auties00.parley.jitter.FeedbackSink;
import com.github.auties00.parley.jitter.SyncGroup;
import com.github.auties00.parley.jitter.VideoAssemblerConfig;
import com.github.auties00.parley.jitter.VideoFrameAssembler;
import com.github.auties00.parley.media.AudioFrameMetadata;
import com.github.auties00.parley.media.Av1FrameMetadata;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.FrameMetadata;
import com.github.auties00.parley.media.GenericFrameMetadata;
import com.github.auties00.parley.media.H264FrameMetadata;
import com.github.auties00.parley.media.H265FrameMetadata;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Priority;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.media.Vp9FrameMetadata;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.payload.DepacketizerConfig;
import com.github.auties00.parley.payload.DtmfToneSequence;
import com.github.auties00.parley.payload.Packetizer;
import com.github.auties00.parley.payload.PacketizerConfig;
import com.github.auties00.parley.payload.PayloadFormat;
import com.github.auties00.parley.payload.PayloadFormatException;
import com.github.auties00.parley.payload.Vp8PayloadRewriter;
import com.github.auties00.parley.payload.Vp9PayloadRewriter;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.rtcp.Bye;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;
import com.github.auties00.parley.rtp.rtcp.SenderReport;
import com.github.auties00.parley.rtp.session.FecConfig;
import com.github.auties00.parley.rtp.session.FeedbackMechanism;
import com.github.auties00.parley.rtp.session.KeyframeMethod;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;
import com.github.auties00.parley.rtp.session.ReceiveStreamConfig;
import com.github.auties00.parley.rtp.session.RedConfig;
import com.github.auties00.parley.rtp.session.RtcpConfig;
import com.github.auties00.parley.rtp.session.RtpReceiveStream;
import com.github.auties00.parley.rtp.session.RtpRoutingTable;
import com.github.auties00.parley.rtp.session.RtpSendStream;
import com.github.auties00.parley.rtp.session.RtpSession;
import com.github.auties00.parley.rtp.session.SendStreamConfig;
import com.github.auties00.parley.rtp.session.SsrcChange;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.stats.RtcStats;
import com.github.auties00.parley.transport.SrtpOptions;
import com.github.auties00.parley.transport.SrtpTransport;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/// The production [PeerBackend]: one ICE agent, DTLS transport, SRTP transport, RTP session and congestion
/// controller per negotiated transport, one SCTP association for the data channels, and the wiring from senders and
/// receivers to RTP streams through the payload formats and jitter buffers.
///
/// @implNote This implementation creates the ICE agent and the DTLS and SRTP layers of a transport when a local
/// description first names it, so candidates trickle while the answer is on its way. One connector thread per
/// transport, from the configured factory, waits for ICE and runs the DTLS handshake; the SCTP association starts
/// separately, on its own thread, as soon as both a data section is negotiated on a connected transport and it has
/// not started, whichever comes last, so a data channel added to a media-only connection by a later negotiation
/// opens, and a later negotiation restarts an association the peer closed. The association exists from the first
/// data channel on, over a datagram path attached to the DTLS transport the negotiation picks, so channels can be
/// created before the first offer as the W3C API allows.
///
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.rfc-editor.org/rfc/rfc8834.html RFC 8834: Media Transport and Use of RTP in WebRTC
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc8261.html RFC 8261: Datagram Transport Layer Security (DTLS) Encapsulation of SCTP Packets
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
/// @spec https://www.rfc-editor.org/rfc/rfc7667.html RFC 7667: RTP Topologies
final class TransportBackend implements PeerBackend {
    private static final System.Logger LOGGER = System.getLogger(TransportBackend.class.getName());
    /// The lowest bitrate given to an audio encoding.
    private static final long MIN_AUDIO_BITRATE = 6_000;
    /// The lowest bitrate given to a video encoding.
    private static final long MIN_VIDEO_BITRATE = 30_000;
    /// The header extensions a send stream writes itself, which a forwarded packet's values never replace.
    private static final Set<URI> STREAM_OWNED_EXTENSIONS = Set.of(CodecCatalog.MID, CodecCatalog.RTP_STREAM_ID,
            CodecCatalog.REPAIRED_RTP_STREAM_ID, CodecCatalog.ABS_SEND_TIME, CodecCatalog.TRANSPORT_WIDE_CC);

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
    /// Guards the SCTP association's creation, start and replacement.
    private final ReentrantLock dataLock = new ReentrantLock();
    /// The datagram path of the SCTP association, attached to a DTLS transport after its handshake.
    private final DeferredDatagramTransport dataPath = new DeferredDatagramTransport();
    /// The data channels, opened locally or by the peer.
    private final List<DataChannel> channels = new CopyOnWriteArrayList<>();
    /// The data channels counted as opened and not yet as closed.
    private final Set<DataChannel> openChannels = ConcurrentHashMap.newKeySet();
    /// The A/V synchronization groups of the received streams, by remote `a=msid` stream id.
    private final Map<String, SyncGroup> syncGroups = new ConcurrentHashMap<>();
    /// The SCTP association, or `null` before the first data channel or data section.
    private volatile SctpTransport sctp;
    /// The association whose start was issued; guarded by [#dataLock].
    private SctpTransport startedAssociation;
    /// The thread starting the association and accepting its channels, or `null`.
    private volatile Thread sctpThread;
    /// The transport the data section runs on, or `null`.
    private volatile String dataTransportId;
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
        /// The DTLS transport over the agent; replaced when the peer restarts DTLS.
        volatile DtlsTransport dtls;
        /// The SRTP transport over the DTLS transport, created once the handshake keyed it with the negotiated
        /// options; `null` before.
        volatile SrtpTransport srtp;
        /// The application's view of the DTLS and ICE transports.
        final PeerDtlsTransportView view;
        /// The remote parameters the current DTLS handshake was started with, or `null` before the first one;
        /// guarded by [#wiring].
        HandshakeParameters handshake;
        /// The DSCP value applied to the agent's sockets, or `-1` before the first.
        volatile int trafficClass = -1;
        /// The remote candidates handed to the agent.
        final Set<String> remoteCandidates = ConcurrentHashMap.newKeySet();
        /// Serializes the creation of the RTP session with the wiring of streams to it, and with [#closed].
        final ReentrantLock wiring = new ReentrantLock();
        /// The RTP session, once media is negotiated.
        volatile RtpSession session;
        /// The congestion controller of the session.
        volatile CongestionController congestion;
        /// The transport-wide feedback generator of the session, when transport-cc is negotiated.
        volatile TransportFeedbackGenerator feedback;
        /// The REMB generator of the session, when goog-remb is negotiated without transport-cc.
        volatile RembGenerator remb;
        /// The RFC 8888 feedback generator of the session, when `ack ccfb` is negotiated.
        volatile CongestionControlFeedbackGenerator ccfb;
        /// The extension map of the session.
        volatile HeaderExtensionMap extensions = HeaderExtensionMap.empty();
        /// The thread connecting ICE and DTLS, or `null`.
        volatile Thread connector;
        /// The DTLS handshake keyed SRTP, so the RTP session may send.
        volatile boolean keyed;
        /// The DTLS handshake completed.
        volatile boolean dtlsConnected;
        /// Whether the transport was closed; written under [#wiring].
        volatile boolean closed;

        TransportRuntime(String id, IceAgent ice, DtlsTransport dtls, PeerDtlsTransportView view) {
            this.id = id;
            this.ice = ice;
            this.dtls = dtls;
            this.view = view;
        }
    }

    /// What decides whether a negotiation restarts a transport's DTLS association: the peer's `a=tls-id`, its
    /// fingerprints and the DTLS role.
    ///
    /// @param remoteTlsId        the remote `a=tls-id`, if any
    /// @param remoteFingerprints the remote fingerprints
    /// @param role               this side's DTLS role
    private record HandshakeParameters(Optional<String> remoteTlsId, List<SdpAttribute.Fingerprint> remoteFingerprints,
                                       DtlsRole role) {
        /// {@return the parameters a negotiated transport names}
        static HandshakeParameters of(Negotiated.Transport transport) {
            return new HandshakeParameters(transport.remoteTlsId(), transport.remoteFingerprints(),
                    transport.dtlsRole());
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
    /// @param feedback    the RTCP feedback the peer accepts for the stream's codec
    /// @param syncGroup   the remote `a=msid` stream id whose [SyncGroup] the jitter buffer joined, if any
    record ReceiverBinding(String mid, String transportId, MediaKind kind, Optional<String> rid, RtpReceiveStream stream,
                           RtpReceiver receiver, AudioPlayoutBuffer playout, VideoFrameAssembler assembler,
                           int payloadType, Set<FeedbackMechanism> feedback, Optional<String> syncGroup) {
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
        var iceView = new PeerIceTransportView[1];
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
                .eventListener(event -> onIceEvent(transportId, iceView[0], event))
                .build();
        var dtls = DtlsTransport.over(agent, DtlsConfig.of(certificates.getFirst())
                .withCertificates(certificates)
                .withSrtpProfiles(configuration.srtpProfiles())
                .withVersions(configuration.dtlsVersions())
                .withClock(configuration.clock())
                .withThreadFactory(configuration.threadFactory()));
        iceView[0] = new PeerIceTransportView(agent);
        var view = new PeerDtlsTransportView(dtls, iceView[0]);
        var runtime = new TransportRuntime(transportId, agent, dtls, view);
        listenTo(runtime, dtls);
        transports.put(transportId, runtime);
        agent.gather();
    }

    /// Reports the state changes of a transport's DTLS association while it is the transport's current one, so the
    /// closing of an association a restart replaced is not mistaken for the transport's.
    private void listenTo(TransportRuntime runtime, DtlsTransport dtls) {
        dtls.setStateListener(state -> {
            if (runtime.dtls != dtls) {
                return;
            }
            runtime.view.publish(state);
            listener.onDtlsState(runtime.id, state);
        });
    }

    /// Forwards an ICE event to the connection and to the transport's view.
    private void onIceEvent(String transportId, PeerIceTransportView view, IceEvent event) {
        switch (event) {
            case IceEvent.CandidateGathered(var candidate, var server) -> listener.onLocalCandidate(transportId,
                    stripPrefix(candidate.toSdp()), server, candidate.relayProtocol());
            case IceEvent.GatheringStateChanged(var state) -> {
                if (view != null) {
                    view.publish(new PeerIceTransportEvent.GatheringStateChanged(state));
                }
                listener.onGatheringState(transportId, state);
            }
            case IceEvent.CandidateError(var server, var localAddress, var code, var reason) ->
                    listener.onCandidateError(transportId,
                            localAddress.map(address -> address.getAddress().getHostAddress()),
                            localAddress.map(address -> OptionalInt.of(address.getPort())).orElseGet(OptionalInt::empty),
                            server, code, reason);
            case IceEvent.StateChanged(var state) -> {
                if (view != null) {
                    view.publish(new PeerIceTransportEvent.StateChanged(state));
                }
                listener.onIceState(transportId, state);
            }
            case IceEvent.SelectedPairChanged(var pair) -> {
                if (view != null) {
                    view.publish(new PeerIceTransportEvent.SelectedPairChanged(pair));
                }
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
            if (runtime == null) {
                continue;
            }
            runtime.ice.setRole(transport.iceRole());
            runtime.ice.setRemoteParameters(new IceParameters(transport.remote().usernameFragment(),
                    transport.remote().password(), transport.remoteLite()));
            for (var candidate : transport.remoteCandidates()) {
                addRemoteCandidate(transport.id(), candidate);
            }
            if (transport.remoteComplete()) {
                runtime.ice.endOfRemoteCandidates();
            }
            if (transport.dtlsRestart()) {
                restartDtls(runtime, transport);
            }
            prepare(runtime, outcome);
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
            applyTrafficClass(runtime);
        }
    }

    /// Replaces a transport's DTLS association with a new one, as RFC 8842 requires when the peer's `a=tls-id`,
    /// fingerprints or the DTLS role change: the media streams and the SCTP association of the transport are torn
    /// down, and a new connector handshakes again over the same ICE agent, keying a new SRTP transport and starting
    /// a new association. Does nothing when the handshake already running or done used the same parameters.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
    private void restartDtls(TransportRuntime runtime, Negotiated.Transport transport) {
        DtlsTransport replacement;
        Thread connector;
        runtime.wiring.lock();
        try {
            if (runtime.closed || closed || runtime.handshake == null
                    || runtime.handshake.equals(HandshakeParameters.of(transport))) {
                return;
            }
            runtime.handshake = null;
            runtime.keyed = false;
            runtime.dtlsConnected = false;
            detachMedia(runtime);
            replacement = runtime.dtls.restart();
            runtime.dtls = replacement;
            runtime.view.replace(replacement);
            listenTo(runtime, replacement);
            connector = runtime.connector;
            runtime.connector = null;
        } finally {
            runtime.wiring.unlock();
        }
        if (connector != null) {
            connector.interrupt();
        }
        restartSctp(runtime);
        runtime.view.publish(replacement.state());
        listener.onDtlsState(runtime.id, replacement.state());
    }

    /// Removes the send and receive streams of a transport and closes its RTP session, feedback generators,
    /// congestion controller and SRTP transport, so the next wiring builds them anew; the caller holds the
    /// transport's wiring lock.
    private void detachMedia(TransportRuntime runtime) {
        for (var entry : List.copyOf(senders.entrySet())) {
            if (entry.getValue().transportId().equals(runtime.id)) {
                senders.remove(entry.getKey());
                entry.getKey().stopSending();
            }
        }
        for (var entry : List.copyOf(receivers.entrySet())) {
            if (entry.getValue().transportId().equals(runtime.id)) {
                receivers.remove(entry.getKey());
                closeJitter(entry.getValue());
            }
        }
        closeQuietly(runtime.feedback, runtime.remb, runtime.ccfb, runtime.session, runtime.congestion,
                runtime.srtp);
        runtime.feedback = null;
        runtime.remb = null;
        runtime.ccfb = null;
        runtime.session = null;
        runtime.congestion = null;
        runtime.srtp = null;
        runtime.extensions = HeaderExtensionMap.empty();
    }

    /// Closes the SCTP association when it runs over `runtime`, so the next negotiation or handshake starts a new
    /// one over the transport's new DTLS association.
    private void restartSctp(TransportRuntime runtime) {
        SctpTransport previous;
        dataLock.lock();
        try {
            if (!runtime.id.equals(dataTransportId) || startedAssociation == null) {
                return;
            }
            previous = startedAssociation;
            startedAssociation = null;
            sctp = null;
            dataTransportId = null;
        } finally {
            dataLock.unlock();
        }
        try {
            previous.close();
        } catch (RuntimeException exception) {
            LOGGER.log(Level.DEBUG, "the SCTP association failed to close: " + exception);
        }
    }

    /// Closes each of `closeables` on its own, skipping `null`s; never throws.
    private static void closeQuietly(AutoCloseable... closeables) {
        for (var closeable : closeables) {
            if (closeable == null) {
                continue;
            }
            try {
                closeable.close();
            } catch (Exception exception) {
                LOGGER.log(Level.DEBUG, "a transport layer failed to close: " + exception);
            }
        }
    }

    /// Marks the sockets of a transport with the RFC 8837 DSCP value of its highest-priority flow, when it changed.
    ///
    /// @implNote This implementation marks every packet of a transport alike: the transport sends through one socket
    /// per candidate, shared by every flow BUNDLE puts on it, so the flow with the highest `networkPriority` decides
    /// (audio before video at equal priority, data channels last).
    /// @spec https://www.rfc-editor.org/rfc/rfc8837.html RFC 8837: Differentiated Services Code Point (DSCP) Packet Markings for WebRTC QoS
    private void applyTrafficClass(TransportRuntime runtime) {
        var outcome = negotiated;
        if (outcome == null || closed || runtime.closed) {
            return;
        }
        var best = -1;
        var dscp = 0;
        for (var media : outcome.media()) {
            if (!media.transportId().equals(runtime.id) || !media.direction().sends()) {
                continue;
            }
            var layers = media.transceiver().sender().currentLayers();
            for (var layer : layers.isEmpty() ? media.sendLayers() : layers) {
                var priority = layer.encoding().networkPriority();
                var rank = priority.ordinal() * 3 + (media.kind() == MediaKind.AUDIO ? 2 : 1);
                if (rank > best) {
                    best = rank;
                    dscp = dscpOf(Optional.of(media.kind()), priority);
                }
            }
        }
        if (best < 0 && outcome.data().filter(data -> data.transportId().equals(runtime.id)).isPresent()) {
            dscp = dscpOf(Optional.empty(), Priority.LOW);
        }
        if (runtime.trafficClass == dscp) {
            return;
        }
        runtime.trafficClass = dscp;
        if (!runtime.ice.setTrafficClass(dscp) && dscp != 0) {
            LOGGER.log(Level.DEBUG, "the platform did not mark transport " + runtime.id + " with DSCP " + dscp);
        }
    }

    /// {@return the RFC 8837 DSCP value of a flow of `kind`, or of data channels when `kind` is empty}
    private static int dscpOf(Optional<MediaKind> kind, Priority priority) {
        var audio = kind.filter(MediaKind.AUDIO::equals).isPresent();
        var video = kind.filter(MediaKind.VIDEO::equals).isPresent();
        return switch (priority) {
            case VERY_LOW -> 8;
            case LOW -> 0;
            case MEDIUM -> audio ? 46 : video ? 36 : 10;
            case HIGH -> audio ? 46 : video ? 34 : 18;
        };
    }

    /// Creates the SCTP association a data section needs, starts the transport's connector once, and starts SCTP
    /// when the transport is already connected.
    private void prepare(TransportRuntime runtime, Negotiated outcome) {
        if (outcome.data().filter(section -> section.transportId().equals(runtime.id)).isPresent()) {
            sctp();
        }
        if (runtime.connector == null) {
            var thread = configuration.threadFactory().newThread(() -> connect(runtime));
            runtime.connector = thread;
            thread.start();
        }
        startSctpIfReady(runtime);
    }

    /// Builds the RTP session of a keyed transport when it has none, then wires the streams of the last negotiation
    /// to it; does nothing before the DTLS handshake keys SRTP, or once the transport closed.
    private void wire(TransportRuntime runtime) {
        var outcome = negotiated;
        if (outcome == null || !runtime.keyed || closed) {
            return;
        }
        runtime.wiring.lock();
        try {
            if (runtime.closed || closed) {
                return;
            }
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

    /// Creates the congestion controller, the RTP session and its feedback generators of a keyed transport; the
    /// caller holds the transport's wiring lock.
    private void buildSession(TransportRuntime runtime, List<Negotiated.Media> media) {
        var extensions = new HashMap<Integer, URI>();
        media.forEach(section -> extensions.putAll(section.extensions()));
        runtime.extensions = HeaderExtensionMap.of(extensions).withAllowMixed(true);
        var bitrates = configuration.bitrates();
        var congestion = CongestionController.gcc(CongestionConfig.defaults()
                .withBitrates(bitrates.minBps(), bitrates.startBps(), bitrates.maxBps())
                .withClock(configuration.clock())
                .withThreadFactory(configuration.threadFactory())
                .withTargetListener(target -> allocate(runtime, target))
                .withFailureListener(cause -> onPacerFailed(runtime, cause)));
        runtime.congestion = congestion;
        var reducedSize = media.stream().allMatch(Negotiated.Media::reducedSizeRtcp);
        var webrtc = RtcpConfig.webrtc();
        var rtcp = new RtcpConfig(webrtc.avpf(), reducedSize, webrtc.extendedReports(), webrtc.minimumInterval(),
                webrtc.trrInterval(), webrtc.sessionBandwidthBps());
        var holder = new RtpSession[1];
        var ccfb = media.stream().anyMatch(Negotiated.Media::congestionControlFeedback);
        var transportCc = !ccfb && media.stream().anyMatch(section -> hasFeedback(section, "transport-cc"));
        var remb = !ccfb && !transportCc && media.stream().anyMatch(section -> hasFeedback(section, "goog-remb"));
        var session = RtpSession.builder(runtime.srtp)
                .clock(configuration.clock())
                .scheduler(congestion.pacer())
                .feedbackObserver(congestion)
                .arrivalObserver(arrival -> {
                    var feedback = runtime.feedback;
                    if (feedback != null && arrival.transportSequence().isPresent()) {
                        feedback.onPacketReceived(arrival.transportSequence().getAsInt(), arrival.ssrc(),
                                arrival.sizeBytes(), arrival.arrivalNanos());
                    }
                    var congestionFeedback = runtime.ccfb;
                    if (congestionFeedback != null) {
                        congestionFeedback.onPacketReceived(arrival.ssrc(), arrival.sequence(), arrival.arrivalNanos());
                    }
                    var generator = runtime.remb;
                    if (generator != null && arrival.absSendTime().isPresent()) {
                        generator.onPacketReceived(arrival.ssrc(), arrival.absSendTime().getAsInt(),
                                arrival.sizeBytes(), arrival.arrivalNanos());
                    }
                })
                .rtcpListener(packet -> onRtcp(runtime, packet))
                .ssrcChangedListener(change -> onSsrcChanged(runtime, change))
                .rtcp(rtcp)
                .cname(media.getFirst().cname())
                .extensions(runtime.extensions)
                .threadFactory(configuration.threadFactory())
                .build();
        holder[0] = session;
        runtime.session = session;
        if (ccfb) {
            var generator = CongestionControlFeedbackGenerator.create(session.localSsrc(), configuration.clock(),
                    packet -> sendRtcp(holder[0], packet));
            generator.start(configuration.threadFactory());
            runtime.ccfb = generator;
        } else if (transportCc) {
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

    /// Mutes the remote tracks whose sources the peer said goodbye to, and hands each sender report's clock mapping
    /// to the jitter buffer of its stream, which dates captured media by it.
    private void onRtcp(TransportRuntime runtime, RtcpPacket packet) {
        switch (packet) {
            case Bye bye -> {
                for (var binding : receivers.values()) {
                    if (!binding.transportId().equals(runtime.id)) {
                        continue;
                    }
                    var ssrc = binding.stream().statistics().ssrc();
                    if (ssrc.isPresent() && bye.ssrcs().contains(ssrc.getAsLong())) {
                        binding.receiver().track().mute();
                    }
                }
            }
            case SenderReport report -> {
                for (var binding : receivers.values()) {
                    if (!binding.transportId().equals(runtime.id)) {
                        continue;
                    }
                    var ssrc = binding.stream().statistics().ssrc();
                    if (ssrc.isEmpty() || ssrc.getAsLong() != report.ssrc()) {
                        continue;
                    }
                    binding.stream().senderClock().ifPresent(mapping -> {
                        if (binding.playout() != null) {
                            binding.playout().setSenderClock(mapping);
                        }
                        if (binding.assembler() != null) {
                            binding.assembler().setSenderClock(mapping);
                        }
                    });
                }
            }
            default -> {
            }
        }
    }

    /// Moves a sender's layer to the SSRC the RTP session picked after an RFC 3550 collision, so the next offer
    /// announces it, and asks for that offer with `negotiationneeded`.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc3550.html#section-8.2 RFC 3550 section 8.2: Collision Resolution and Loop Detection
    private void onSsrcChanged(TransportRuntime runtime, SsrcChange change) {
        for (var entry : senders.entrySet()) {
            var binding = entry.getValue();
            if (!binding.transportId().equals(runtime.id)) {
                continue;
            }
            var updated = binding.layers().stream().map(layer -> layer.withReplacedSsrc(change.oldSsrc(),
                    change.newSsrc())).toList();
            if (updated.equals(binding.layers())) {
                continue;
            }
            senders.replace(entry.getKey(), binding, new SenderBinding(binding.mid(), binding.transportId(),
                    binding.kind(), binding.payloadType(), binding.streams(), updated));
            var sender = entry.getKey();
            configuration.threadFactory().newThread(() -> listener.onSsrcChanged(sender, change.oldSsrc(),
                    change.newSsrc())).start();
        }
    }

    /// Fails the connection when a transport's pacer stopped, since none of its media can leave any more.
    private void onPacerFailed(TransportRuntime runtime, Throwable cause) {
        if (closed || runtime.closed) {
            return;
        }
        LOGGER.log(Level.WARNING, "the pacer of transport " + runtime.id + " failed", cause);
        configuration.threadFactory().newThread(() -> listener.onTransportFailed(runtime.id)).start();
    }

    /// {@return whether a section negotiated a feedback mechanism on its first codec}
    private static boolean hasFeedback(Negotiated.Media media, String type) {
        return !media.codecs().isEmpty() && media.codecs().getFirst().feedback().stream()
                .anyMatch(feedback -> feedback.type().equals(type));
    }

    /// Sends an RTCP packet a feedback generator produced.
    private static void sendRtcp(RtpSession session, RtcpPacket packet) {
        if (session == null) {
            return;
        }
        try {
            session.sendRtcp(packet);
        } catch (IOException | RuntimeException exception) {
            LOGGER.log(Level.DEBUG, "feedback could not be sent: " + exception);
        }
    }

    /// Waits for ICE, then runs the DTLS handshake with the transport's current negotiation, wires the media and
    /// starts SCTP if a data section is negotiated.
    ///
    /// A restart replaces the transport's DTLS association while this runs: the connector of the replaced one then
    /// ends quietly, and the restart's own connector handshakes over the new one.
    private void connect(TransportRuntime runtime) {
        var dtls = runtime.dtls;
        try {
            if (!runtime.ice.awaitConnected(configuration.handshakeTimeout())) {
                throw new IceException("ICE did not connect within " + configuration.handshakeTimeout());
            }
            var transport = currentTransport(runtime.id).orElseThrow(() -> new ClosedChannelException());
            var fingerprints = transport.remoteFingerprints().stream()
                    .flatMap(fingerprint -> fingerprint.attributeValue().stream())
                    .flatMap(value -> DtlsFingerprint.tryParse(value).stream())
                    .toList();
            var outcome = negotiated;
            var media = outcome == null ? List.<Negotiated.Media>of() : outcome.media().stream()
                    .filter(section -> section.transportId().equals(runtime.id)).toList();
            runtime.wiring.lock();
            try {
                if (runtime.dtls != dtls || runtime.closed) {
                    return;
                }
                runtime.handshake = HandshakeParameters.of(transport);
            } finally {
                runtime.wiring.unlock();
            }
            if (!media.isEmpty()) {
                dtls.handshake(transport.dtlsRole(), fingerprints, configuration.handshakeTimeout());
            } else {
                dtls.handshakeWithoutSrtp(transport.dtlsRole(), fingerprints, configuration.handshakeTimeout());
            }
            runtime.wiring.lock();
            try {
                if (runtime.dtls != dtls || runtime.closed) {
                    return;
                }
                if (dtls.srtpKeys().isPresent()) {
                    var cryptex = !media.isEmpty() && media.stream().allMatch(Negotiated.Media::cryptex);
                    runtime.srtp = SrtpTransport.dtlsSrtp(dtls, SrtpOptions.DEFAULT.withCryptex(cryptex));
                    runtime.keyed = true;
                }
                runtime.dtlsConnected = true;
            } finally {
                runtime.wiring.unlock();
            }
            wire(runtime);
            startSctpIfReady(runtime);
        } catch (InterruptedException exception) {
            if (runtime.dtls == dtls) {
                Thread.currentThread().interrupt();
            }
        } catch (IOException | RuntimeException exception) {
            if (closed || runtime.closed || runtime.dtls != dtls) {
                LOGGER.log(Level.DEBUG, "transport " + runtime.id + " ended while connecting: " + exception);
            } else if (dtls.state() != DtlsState.CONNECTED) {
                LOGGER.log(Level.DEBUG, "transport " + runtime.id + " failed: " + exception);
                runtime.view.publish(DtlsState.FAILED);
                listener.onDtlsState(runtime.id, DtlsState.FAILED);
            } else {
                LOGGER.log(Level.WARNING, "transport " + runtime.id + " could not be wired", exception);
            }
        }
    }

    /// {@return the transport `transportId` of the last negotiation}
    private Optional<Negotiated.Transport> currentTransport(String transportId) {
        var outcome = negotiated;
        if (outcome == null) {
            return Optional.empty();
        }
        return outcome.transports().stream().filter(transport -> transport.id().equals(transportId)).findFirst();
    }

    /// Starts the SCTP association on a transport when the last negotiation put the data section on it, its DTLS
    /// handshake completed, and the current association has not started; a closed association is replaced first.
    private void startSctpIfReady(TransportRuntime runtime) {
        var outcome = negotiated;
        if (outcome == null || closed || runtime.closed || !runtime.dtlsConnected) {
            return;
        }
        var data = outcome.data().filter(section -> section.transportId().equals(runtime.id));
        if (data.isEmpty()) {
            return;
        }
        var role = runtime.dtls.role().orElse(currentTransport(runtime.id).map(Negotiated.Transport::dtlsRole)
                .orElse(DtlsRole.CLIENT));
        SctpTransport association;
        dataLock.lock();
        try {
            association = sctpLocked();
            if (association == null || startedAssociation == association) {
                return;
            }
            startedAssociation = association;
            dataTransportId = runtime.id;
            var thread = configuration.threadFactory().newThread(() -> runSctp(runtime, association, data.get(),
                    role));
            sctpThread = thread;
            thread.start();
        } finally {
            dataLock.unlock();
        }
    }

    /// Starts an association over a transport, then accepts the channels the peer opens until it ends.
    private void runSctp(TransportRuntime runtime, SctpTransport association, Negotiated.Data data, DtlsRole role) {
        try {
            dataPath.attach(runtime.dtls.applicationData());
            association.start(role, data.remotePort(), data.remoteMaxMessageSize(), configuration.handshakeTimeout());
            while (!closed) {
                var channel = association.acceptDataChannel();
                channels.add(channel);
                listener.onDataChannel(channel);
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (IOException | RuntimeException exception) {
            if (closed || runtime.closed || association.state() == SctpTransportState.CLOSED) {
                LOGGER.log(Level.DEBUG, "the SCTP association ended: " + exception);
            } else {
                LOGGER.log(Level.WARNING, "the SCTP association failed: " + exception);
            }
        }
    }

    /// {@return the SCTP association, created over the deferred datagram path on first use}
    private SctpTransport sctp() {
        dataLock.lock();
        try {
            return sctpLocked();
        } finally {
            dataLock.unlock();
        }
    }

    /// {@return the current SCTP association, created when there is none and replacing one that was started and has
    /// closed since (the peer closed it), or `null` once the backend is closed}; the caller holds [#dataLock]
    private SctpTransport sctpLocked() {
        if (closed) {
            return sctp;
        }
        var current = sctp;
        if (current == null || (current == startedAssociation && current.state() == SctpTransportState.CLOSED)) {
            current = SctpTransport.overDatagrams(dataPath, SctpConfig.defaults()
                    .withLocalPort(JsepEngine.SCTP_PORT)
                    .withMaxMessageSize(JsepEngine.MAX_MESSAGE_SIZE)
                    .withThreadFactory(configuration.threadFactory())
                    .withChannelEventListener(this::onChannelEvent));
            sctp = current;
        }
        return current;
    }

    /// Counts a data channel that opened, or one that was open and closed, for the connection's statistics.
    ///
    /// Runs with the channel's lock held, on whichever thread changed its state, so it only counts.
    private void onChannelEvent(DataChannel channel, DataChannelEvent event) {
        switch (event) {
            case DataChannelEvent.Opened _ -> {
                if (openChannels.add(channel)) {
                    listener.onDataChannelOpened();
                }
            }
            case DataChannelEvent.Closed _ -> {
                if (openChannels.remove(channel)) {
                    listener.onDataChannelClosed();
                }
            }
            default -> {
            }
        }
    }

    /// Creates the send streams of a section and wires its sender to them; the caller holds the wiring lock.
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
                    LOGGER.log(Level.DEBUG, "an old send stream could not be removed: " + exception);
                }
            }
            var builder = SendStreamConfig.builder(media.mid(), layer.ssrc(), codec.payloadType(),
                    codec.codec().clockRate())
                    .extensions(runtime.extensions)
                    .feedback(feedbackOf(codec))
                    .keyframeRequestListener(request -> sender.track()
                            .ifPresent(track -> track.requestKeyframe(layer.rid())));
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
            streams.put(layer.rid().orElse(""), stream);
        }
        senders.put(sender, new SenderBinding(media.mid(), media.transportId(), media.kind(), codec.payloadType(),
                Map.copyOf(streams), media.sendLayers()));
        var pipeline = new SendPipeline(sender, media, runtime.extensions, Map.copyOf(streams));
        sender.setPipeline(pipeline, media.sendLayers());
        var dtmf = sender.dtmf();
        if (dtmf.isPresent()) {
            var telephoneEvent = media.telephoneEvent();
            if (telephoneEvent.isPresent()) {
                var stream = streams.get(pipeline.first);
                var eventPt = telephoneEvent.get().payloadType();
                var clockRate = telephoneEvent.get().codec().clockRate();
                dtmf.get().setSink((tone, duration) -> playTone(stream, eventPt, clockRate, pipeline.lastTimestamp,
                        tone, duration));
            } else {
                dtmf.get().setSink(null);
            }
        }
    }

    /// Sends the RFC 4733 packets of one tone, paced by the configured clock, and returns after the last end packet.
    private void playTone(RtpSendStream stream, int payloadType, int clockRate, AtomicLong lastTimestamp, char tone,
                          Duration duration) throws InterruptedException {
        var sequence = new DtmfToneSequence(String.valueOf(tone), duration, DtmfToneSequence.DEFAULT_INTER_TONE_GAP);
        var base = (lastTimestamp.get() + clockRate / 50) & 0xFFFF_FFFFL;
        var clock = configuration.clock();
        var start = clock.nanos();
        for (var packet : sequence.packets(clockRate)) {
            var elapsed = clock.nanos() - start;
            var wait = packet.sendTime().toNanos() - elapsed;
            if (wait > 0) {
                DtmfSender.sleep(clock, Duration.ofNanos(wait));
            }
            try {
                stream.sendWithPayloadType(payloadType, List.of(new RtpSendStream.Payload(packet.event().toBuffer(),
                        packet.marker(), Map.of())), (base + packet.timestampOffset()) & 0xFFFF_FFFFL,
                        OutgoingPacketScheduler.Priority.AUDIO);
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a DTMF packet could not be sent: " + exception);
            }
        }
    }

    /// The pipeline of a negotiated sender: packetizes written frames, or forwards packets, onto its send streams.
    ///
    /// Each layer sends the codec its encoding's `codec` member names, or the first negotiated codec without one.
    private final class SendPipeline implements FrameSink {
        /// The sender, whose current encodings decide which layers are active and which codec each sends.
        private final RtpSender sender;
        /// The negotiated section.
        private final Negotiated.Media media;
        /// The send streams by RTP stream id.
        private final Map<String, RtpSendStream> streams;
        /// The packetizers by RTP stream id and payload type.
        private final Map<String, Packetizer> packetizers = new ConcurrentHashMap<>();
        /// The forwarders by RTP stream id, created on the first forwarded packet.
        private final Map<String, Forwarder> forwarders = new ConcurrentHashMap<>();
        /// The scheduling priority of the section's packets.
        private final OutgoingPacketScheduler.Priority priority;
        /// The RTP stream id of the first layer (`""` without simulcast).
        private final String first;
        /// Whether the dependency descriptor extension is negotiated, which AV1 packetizers then write.
        private final boolean dependencyDescriptor;
        /// The RTP timestamp of the last frame sent, which DTMF events continue from.
        private final AtomicLong lastTimestamp = new AtomicLong();

        SendPipeline(RtpSender sender, Negotiated.Media media, HeaderExtensionMap extensions,
                     Map<String, RtpSendStream> streams) {
            this.sender = sender;
            this.media = media;
            this.streams = streams;
            this.priority = media.kind() == MediaKind.AUDIO ? OutgoingPacketScheduler.Priority.AUDIO
                    : OutgoingPacketScheduler.Priority.VIDEO;
            this.first = media.sendLayers().getFirst().rid().orElse("");
            this.dependencyDescriptor = media.extensions().containsValue(CodecCatalog.DEPENDENCY_DESCRIPTOR)
                    && extensions.idOf(CodecCatalog.DEPENDENCY_DESCRIPTOR).isPresent();
        }

        @Override
        public boolean accept(EncodedFrame frame, Optional<String> rid) {
            var key = rid.orElse(first);
            var stream = streams.get(key);
            if (stream == null || !sender.isLayerActive(key)) {
                return false;
            }
            var codec = codecOf(key);
            var packetizer = packetizers.computeIfAbsent(key + "/" + codec.payloadType(),
                    ignored -> newPacketizer(codec.codec()));
            try {
                var payloads = new ArrayList<RtpSendStream.Payload>();
                synchronized (packetizer) {
                    for (var payload : packetizer.packetize(frame)) {
                        payloads.add(new RtpSendStream.Payload(payload.header(), payload.body(), payload.marker(),
                                payload.extensions()));
                    }
                }
                if (!payloads.isEmpty()) {
                    lastTimestamp.set(frame.rtpTimestamp());
                    if (codec.payloadType() == stream.config().payloadType()) {
                        var resolution = resolutionOf(frame.metadata());
                        stream.send(payloads, frame.rtpTimestamp(), priority, new RtpSendStream.FrameInfo(
                                frame.keyframe(), resolution.map(size -> OptionalInt.of(size.width()))
                                .orElseGet(OptionalInt::empty), resolution.map(size -> OptionalInt.of(size.height()))
                                .orElseGet(OptionalInt::empty)));
                    } else {
                        stream.sendWithPayloadType(codec.payloadType(), payloads, frame.rtpTimestamp(), priority);
                    }
                }
                return true;
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a frame could not be sent: " + exception);
                return true;
            }
        }

        /// {@return the negotiated codec the layer named `key` sends: the one its encoding's `codec` member names,
        /// or the first negotiated codec}
        private Negotiated.CodecEntry codecOf(String key) {
            for (var layer : sender.currentLayers()) {
                if (!layer.rid().orElse("").equals(key) || layer.encoding().codec().isEmpty()) {
                    continue;
                }
                var wanted = layer.encoding().codec().get();
                for (var entry : media.codecs()) {
                    if (CodecCatalog.matches(entry.codec(), wanted)) {
                        return entry;
                    }
                }
            }
            return media.codecs().getFirst();
        }

        /// {@return a packetizer for `codec`, writing the AV1 dependency descriptor when it is negotiated}
        private Packetizer newPacketizer(Codec codec) {
            var config = PacketizerConfig.defaults();
            if (dependencyDescriptor && codec.name().equalsIgnoreCase("AV1")) {
                config = config.withDependencyDescriptor(true);
            }
            return PayloadFormat.of(codec).packetizer(config);
        }

        @Override
        public boolean forward(Forwarded packet) {
            var key = packet.rid().filter(streams::containsKey).orElse(first);
            var stream = streams.get(key);
            if (stream == null || !sender.isLayerActive(key)) {
                return false;
            }
            var forwarder = forwarders.computeIfAbsent(key, ignored -> new Forwarder(sender, key, stream, media));
            return forwarder.forward(packet);
        }

        @Override
        public boolean isSending() {
            return true;
        }
    }

    /// {@return the picture size a frame's metadata carries, if any}
    private static Optional<Resolution> resolutionOf(FrameMetadata metadata) {
        return switch (metadata) {
            case Vp8FrameMetadata vp8 -> vp8.resolution();
            case Vp9FrameMetadata vp9 -> vp9.resolution();
            case H264FrameMetadata h264 -> h264.resolution();
            case H265FrameMetadata h265 -> h265.resolution();
            case Av1FrameMetadata av1 -> av1.resolution();
            case GenericFrameMetadata generic -> generic.resolution();
            case AudioFrameMetadata ignored -> Optional.empty();
        };
    }

    /// Forwards packets of any source onto one send stream through [RtpSendStream#forward], which continues the
    /// stream's own sequence and timestamp spaces across sources.
    ///
    /// This class maps the payload type by codec and the header extensions by URI, renumbers the VP8 and VP9 picture
    /// ids so they continue across sources, and holds back a new source until a packet a decoder can start on,
    /// asking the track for a key frame meanwhile.
    ///
    // TODO: carry the AV1 dependency descriptor's frame numbers across source switches.
    private final class Forwarder {
        /// The sender whose track is asked for key frames.
        private final RtpSender sender;
        /// The layer the forwarder feeds.
        private final String rid;
        /// The send stream.
        private final RtpSendStream stream;
        /// The negotiated section, for payload types and extension ids.
        private final Negotiated.Media media;
        /// The source currently forwarded, or `-1`.
        private long source = -1;
        /// The VP8 picture id rewriter, created for a VP8 stream.
        private Vp8PayloadRewriter vp8;
        /// The VP9 picture id rewriter, created for a VP9 stream.
        private Vp9PayloadRewriter vp9;

        Forwarder(RtpSender sender, String rid, RtpSendStream stream, Negotiated.Media media) {
            this.sender = sender;
            this.rid = rid;
            this.stream = stream;
            this.media = media;
        }

        /// {@return whether the packet was sent, or held back for a switch point}
        synchronized boolean forward(FrameSink.Forwarded forwarded) {
            var packet = forwarded.packet();
            var codec = codecOf(forwarded, packet.payloadType());
            if (codec.isEmpty()) {
                return false;
            }
            var entry = codec.get();
            var switchPoint = media.kind() != MediaKind.VIDEO || isSwitchPoint(entry.codec(), packet);
            if (packet.ssrc() != source) {
                if (!switchPoint) {
                    sender.track().ifPresent(track -> track.requestKeyframe(rid.isEmpty()
                            ? Optional.empty() : Optional.of(rid)));
                    return false;
                }
                if (source != -1) {
                    if (vp8 != null) {
                        vp8.switchSource();
                    }
                    if (vp9 != null) {
                        vp9.switchSource();
                    }
                }
                source = packet.ssrc();
            }
            RtpPacket output;
            try {
                output = rewritePayload(entry.codec(), packet);
            } catch (PayloadFormatException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a malformed forwarded payload was dropped: " + exception);
                return true;
            }
            try {
                stream.forward(output, entry.payloadType(), extensionsOf(forwarded), switchPoint,
                        configuration.clock().nanos());
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a forwarded packet could not be sent: " + exception);
            }
            return true;
        }

        /// {@return the packet to send: a copy whose VP8 or VP9 picture ids continue across sources, the packet
        /// itself for any other codec}
        private RtpPacket rewritePayload(Codec codec, RtpPacket packet) throws PayloadFormatException {
            var name = codec.name().toLowerCase(java.util.Locale.ROOT);
            if (!name.equals("vp8") && !name.equals("vp9")) {
                return packet;
            }
            var bytes = ByteBuffer.allocate(packet.length()).put(packet.buffer().duplicate()).flip();
            var payload = bytes.duplicate().position(packet.headerLength())
                    .limit(packet.length() - packet.paddingLength()).slice();
            if (name.equals("vp8")) {
                if (vp8 == null) {
                    vp8 = new Vp8PayloadRewriter();
                }
                vp8.rewrite(payload);
            } else {
                if (vp9 == null) {
                    vp9 = new Vp9PayloadRewriter();
                }
                vp9.rewrite(payload);
            }
            try {
                return RtpPacket.parse(bytes);
            } catch (RtpFormatException exception) {
                throw new PayloadFormatException("the rewritten packet does not parse", exception);
            }
        }

        /// {@return the negotiated codec entry a forwarded packet maps to, or an empty optional to drop it}
        private Optional<Negotiated.CodecEntry> codecOf(FrameSink.Forwarded forwarded, int payloadType) {
            if (forwarded.codec().isPresent()) {
                var codec = forwarded.codec().get();
                return media.codecs().stream().filter(entry -> CodecCatalog.matches(entry.codec(), codec))
                        .findFirst();
            }
            return media.codecs().stream().filter(entry -> entry.payloadType() == payloadType).findFirst()
                    .or(() -> media.codecs().stream().findFirst());
        }

        /// {@return whether a decoder can start on the packet}
        private static boolean isSwitchPoint(Codec codec, RtpPacket packet) {
            try {
                return PayloadFormat.of(codec).isKeyframe(packet.payload());
            } catch (IllegalArgumentException exception) {
                return true;
            }
        }

        /// {@return the forwarded packet's header extension values by URI, limited to those the section negotiated
        /// and the stream does not write itself}
        private Map<URI, ByteBuffer> extensionsOf(FrameSink.Forwarded forwarded) {
            var packet = forwarded.packet();
            if (!packet.hasExtension()) {
                return Map.of();
            }
            var source = forwarded.extensions().orElse(media.extensions());
            var negotiatedUris = media.extensions().values();
            var result = new HashMap<URI, ByteBuffer>();
            for (var id : packet.extensionIds()) {
                var uri = source.get(id);
                if (uri == null || STREAM_OWNED_EXTENSIONS.contains(uri) || !negotiatedUris.contains(uri)) {
                    continue;
                }
                packet.extension(id).ifPresent(value -> result.put(uri, value));
            }
            return result;
        }
    }

    /// Creates the receive streams of a section and feeds its receiver from them; the caller holds the wiring lock.
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
        var feedback = feedbackOf(codec);
        if (track.mode() == RemoteTrackMode.RAW_PACKETS) {
            var codecs = new HashMap<Integer, Codec>();
            media.codecs().forEach(entry -> codecs.put(entry.payloadType(), entry.codec()));
            var extensions = Map.copyOf(media.extensions());
            stream.setPacketReceiver(packet -> {
                record(receiver, packet, audioLevelId);
                track.received();
                track.deliverPacket(new RemoteTrack.Packet(packet.copy(), layer.rid(), clock.nanos(),
                        Optional.ofNullable(codecs.get(packet.payloadType())), extensions));
            });
            return new ReceiverBinding(media.mid(), media.transportId(), media.kind(), layer.rid(), stream, receiver,
                    null, null, codec.payloadType(), feedback, Optional.empty());
        }
        var format = PayloadFormat.of(codec.codec());
        var depacketizer = depacketizerConfig(runtime.extensions);
        var syncGroup = media.remoteStreams().stream().filter(id -> !id.equals("-")).findFirst();
        if (media.kind() == MediaKind.AUDIO) {
            var playoutConfig = AudioPlayoutConfig.defaults().withClock(clock).withDepacketizer(depacketizer);
            var jitterTarget = receiver.jitterBufferTarget();
            var buffer = AudioPlayoutBuffer.create(format, codec.codec().clockRate(), jitterTarget.isPresent()
                    ? playoutConfig.withJitterBufferTarget(jitterTarget.get()) : playoutConfig);
            syncGroup.ifPresent(id -> syncGroups.computeIfAbsent(id, ignored -> SyncGroup.create()).add(buffer));
            stream.setPacketReceiver(packet -> {
                track.received();
                if (packet.payloadType() != codec.payloadType()) {
                    return;
                }
                record(receiver, packet, audioLevelId);
                buffer.insert(packet, clock.nanos());
            });
            configuration.threadFactory().newThread(() -> {
                try {
                    while (!closed && !track.isEnded()) {
                        receiver.deliverPlayout(buffer.next());
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                } catch (RuntimeException exception) {
                    LOGGER.log(Level.DEBUG, "the audio playout loop stopped: " + exception);
                }
            }).start();
            return new ReceiverBinding(media.mid(), media.transportId(), media.kind(), layer.rid(), stream, receiver,
                    buffer, null, codec.payloadType(), feedback, syncGroup);
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
                    LOGGER.log(Level.DEBUG, "a keyframe request could not be sent: " + exception);
                }
            }

            @Override
            public void requestRetransmission(List<Integer> sequences) {
                try {
                    stream.requestRetransmission(sequences);
                } catch (IOException | RuntimeException exception) {
                    LOGGER.log(Level.DEBUG, "a NACK could not be sent: " + exception);
                }
            }
        });
        syncGroup.ifPresent(id -> syncGroups.computeIfAbsent(id, ignored -> SyncGroup.create()).add(assembler));
        stream.setPacketReceiver(packet -> {
            record(receiver, packet, audioLevelId);
            track.received();
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
                LOGGER.log(Level.DEBUG, "the video assembly loop stopped: " + exception);
            }
        }).start();
        return new ReceiverBinding(media.mid(), media.transportId(), media.kind(), layer.rid(), stream, receiver, null,
                assembler, codec.payloadType(), feedback, syncGroup);
    }

    /// {@return the depacketizer settings for the negotiated extension ids}
    private static DepacketizerConfig depacketizerConfig(HeaderExtensionMap extensions) {
        var config = DepacketizerConfig.none();
        var audioLevel = extensions.idOf(CodecCatalog.AUDIO_LEVEL);
        if (audioLevel.isPresent()) {
            config = config.withAudioLevelExtensionId(audioLevel.getAsInt());
        }
        var dependencyDescriptor = extensions.idOf(CodecCatalog.DEPENDENCY_DESCRIPTOR);
        if (dependencyDescriptor.isPresent()) {
            config = config.withDependencyDescriptorExtensionId(dependencyDescriptor.getAsInt());
        }
        var absCaptureTime = extensions.idOf(CodecCatalog.ABS_CAPTURE_TIME);
        if (absCaptureTime.isPresent()) {
            config = config.withAbsCaptureTimeExtensionId(absCaptureTime.getAsInt());
        }
        var playoutDelay = extensions.idOf(CodecCatalog.PLAYOUT_DELAY);
        if (playoutDelay.isPresent()) {
            config = config.withPlayoutDelayExtensionId(playoutDelay.getAsInt());
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
                        LOGGER.log(Level.DEBUG, "a send stream could not be removed: " + exception);
                    }
                }
            }
        }
    }

    /// Closes the jitter buffer of a receive binding and takes it out of its synchronization group.
    private void closeJitter(ReceiverBinding binding) {
        var group = binding.syncGroup().map(syncGroups::get);
        if (binding.playout() != null) {
            group.ifPresent(value -> value.remove(binding.playout()));
            binding.playout().close();
        }
        if (binding.assembler() != null) {
            group.ifPresent(value -> value.remove(binding.assembler()));
            binding.assembler().close();
        }
        binding.syncGroup().ifPresent(id -> syncGroups.computeIfPresent(id, (ignored, value) -> value.size() == 0
                ? null : value));
    }

    /// Splits a new target bitrate across the active encodings of a transport and tells their tracks.
    ///
    /// Runs on the congestion controller's thread and takes no connection lock: it reads the sender's track and
    /// encodings from their lock-free snapshots.
    private void allocate(TransportRuntime runtime, TargetBitrate target) {
        var outcome = negotiated;
        if (outcome == null) {
            return;
        }
        var demands = new ArrayList<EncodingDemand>();
        var tracks = new HashMap<AllocationKey, LocalTrack>();
        var ceilings = new HashMap<String, Long>();
        for (var media : outcome.media()) {
            if (!media.transportId().equals(runtime.id) || !media.direction().sends()) {
                continue;
            }
            var sender = media.transceiver().sender();
            var track = sender.track();
            var current = sender.currentLayers();
            media.maxBitrate().ifPresent(ceiling -> ceilings.put(media.mid(), ceiling));
            for (var layer : media.sendLayers()) {
                var encoding = current.stream().filter(candidate -> candidate.rid().equals(layer.rid()))
                        .map(Negotiated.SendLayer::encoding).findFirst().orElse(layer.encoding());
                var key = new AllocationKey(media.mid(), layer.rid());
                var min = media.kind() == MediaKind.AUDIO ? MIN_AUDIO_BITRATE : MIN_VIDEO_BITRATE;
                var max = Math.max(min, encoding.maxBitrate().orElse(configuration.bitrates().maxBps()));
                demands.add(new EncodingDemand(key, encoding.active() && track.isPresent(), min, max,
                        encoding.priority().weight(), encoding.scaleResolutionDownBy().orElse(1)));
                track.ifPresent(value -> tracks.put(key, value));
            }
        }
        if (demands.isEmpty()) {
            return;
        }
        for (var entry : allocator.allocate(target.bitsPerSecond(), demands, ceilings).entrySet()) {
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
            LOGGER.log(Level.DEBUG, "an unusable remote candidate was skipped");
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
            var association = sctp();
            if (association == null || closed) {
                throw new InvalidStateException("the connection is closed");
            }
            var channel = association.createDataChannel(label, init);
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
            views.add(new StatsMapper.TransportView(runtime.id, runtime.ice, runtime.dtls,
                    Optional.ofNullable(runtime.congestion)));
        }
        var sendViews = new ArrayList<StatsMapper.SendView>();
        senders.forEach((sender, binding) -> binding.streams().forEach((rid, stream) -> {
            var index = indexOf(binding.layers(), rid);
            var encoding = sender.currentLayers().stream().filter(layer -> layer.rid().orElse("").equals(rid))
                    .map(Negotiated.SendLayer::encoding).findFirst()
                    .orElse(binding.layers().get(index).encoding());
            sendViews.add(new StatsMapper.SendView(binding.mid(), binding.transportId(), binding.kind(),
                    binding.payloadType(), stream, sender.track(), index, encoding));
        }));
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
            applyTrafficClass(runtime);
        }
    }

    @Override
    public void updateJitterBufferTarget(RtpReceiver receiver, Optional<Duration> target) {
        for (var binding : receivers.values()) {
            if (binding.receiver() == receiver && binding.playout() != null) {
                if (target.isPresent()) {
                    binding.playout().setJitterBufferTarget(target.get());
                } else {
                    binding.playout().clearJitterBufferTarget();
                }
            }
        }
    }

    @Override
    public void requestKeyFrame(RtpReceiver receiver, Optional<String> rid) {
        for (var binding : receivers.values()) {
            if (binding.receiver() != receiver || (rid.isPresent() && !binding.rid().equals(rid))) {
                continue;
            }
            var method = binding.feedback().contains(FeedbackMechanism.PLI) ? Optional.of(KeyframeMethod.PLI)
                    : binding.feedback().contains(FeedbackMechanism.FIR) ? Optional.of(KeyframeMethod.FIR)
                    : Optional.<KeyframeMethod>empty();
            if (method.isEmpty()) {
                continue;
            }
            try {
                binding.stream().requestKeyframe(method.get());
            } catch (IOException | RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a key frame request could not be sent: " + exception);
            }
        }
    }

    @Override
    public Optional<PeerDtlsTransport> dtlsTransport(String transportId) {
        var runtime = transports.get(transportId);
        return runtime == null ? Optional.empty() : Optional.of(runtime.view);
    }

    @Override
    public Optional<PeerSctpTransport> sctpTransport() {
        var outcome = negotiated;
        if (outcome == null || outcome.data().isEmpty() || sctp == null) {
            return Optional.empty();
        }
        var runtime = transports.get(outcome.data().get().transportId());
        if (runtime == null) {
            return Optional.empty();
        }
        return Optional.of(new PeerSctpTransportView(() -> sctp, runtime.view));
    }

    /// Closes the layers of one transport, each on its own; never throws.
    private void close(TransportRuntime runtime) {
        if (runtime == null) {
            return;
        }
        runtime.wiring.lock();
        try {
            runtime.closed = true;
        } finally {
            runtime.wiring.unlock();
        }
        var connector = runtime.connector;
        if (connector != null) {
            connector.interrupt();
        }
        closeQuietly(runtime.feedback, runtime.remb, runtime.ccfb, runtime.session, runtime.congestion, runtime.srtp,
                runtime.dtls, runtime.ice);
        runtime.view.end();
    }

    @Override
    public void close() {
        closed = true;
        for (var channel : channels) {
            try {
                channel.close();
            } catch (RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a data channel failed to close: " + exception);
            }
        }
        SctpTransport association;
        dataLock.lock();
        try {
            association = sctp;
        } finally {
            dataLock.unlock();
        }
        if (association != null) {
            try {
                association.close();
            } catch (RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "the SCTP association failed to close: " + exception);
            }
        }
        var starter = sctpThread;
        if (starter != null) {
            starter.interrupt();
        }
        for (var binding : receivers.values()) {
            try {
                closeJitter(binding);
            } catch (RuntimeException exception) {
                LOGGER.log(Level.DEBUG, "a jitter buffer failed to close: " + exception);
            }
        }
        for (var runtime : transports.values()) {
            close(runtime);
        }
        transports.clear();
        try {
            dataPath.close();
        } catch (RuntimeException exception) {
            LOGGER.log(Level.DEBUG, "the data path failed to close: " + exception);
        }
    }

    /// A datagram path that buffers its receiver until it is attached to the DTLS application data of the transport
    /// the data section is negotiated on.
    private static final class DeferredDatagramTransport implements DatagramTransport {
        /// The attached transport, or `null`.
        private volatile DatagramTransport target;
        /// The receiver to install on the target.
        private volatile PacketReceiver receiver = (packet, arrival) -> { };
        /// Whether the path is closed.
        private volatile boolean closed;

        /// Attaches the path to `transport`, handing it the receiver.
        void attach(DatagramTransport transport) {
            target = Objects.requireNonNull(transport);
            transport.setReceiver(receiver);
        }

        /// Sends through the attached transport.
        ///
        /// @throws ClosedChannelException if the path is closed, not attached yet, or the DTLS association under it
        ///                                is not connected
        @Override
        public void send(ByteBuffer datagram) throws IOException {
            var current = target;
            if (closed || current == null) {
                throw new ClosedChannelException();
            }
            try {
                current.send(datagram);
            } catch (IllegalStateException exception) {
                var closedChannel = new ClosedChannelException();
                closedChannel.initCause(exception);
                throw closedChannel;
            }
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
            closed = true;
            target = null;
        }
    }
}
