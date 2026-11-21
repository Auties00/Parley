package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.stats.StatsReport;

import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/// The sending half of a transceiver, the W3C `RTCRtpSender`: it sends the frames of its [LocalTrack] with the
/// negotiated codec, one RTP stream per encoding.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.w3.org/TR/webrtc-extensions/ WebRTC Extensions
/// @spec https://www.w3.org/TR/webrtc-svc/ Scalable Video Coding (SVC) Extension for WebRTC
/// @spec https://www.w3.org/TR/webrtc-encoded-transform/ WebRTC Encoded Transform
public final class RtpSender {
    private static final System.Logger LOGGER = System.getLogger(RtpSender.class.getName());
    /// The scalability modes the webrtc-svc mode table defines that use temporal layers only, which every video
    /// codec Parley negotiates can carry.
    private static final Set<String> TEMPORAL_MODES = Set.of("L1T1", "L1T2", "L1T3");
    /// The codecs whose payload formats carry spatial layers, and so every mode of the webrtc-svc table.
    private static final Set<String> SPATIAL_CODECS = Set.of("vp9", "av1");
    /// The sink a sender's frames go to before it is negotiated, or while it does not send.
    private static final FrameSink IDLE = new FrameSink() {
        @Override
        public boolean accept(EncodedFrame frame, Optional<String> rid) {
            return false;
        }

        @Override
        public boolean forward(Forwarded packet) {
            return false;
        }

        @Override
        public boolean isSending() {
            return false;
        }
    };

    /// The connection the sender belongs to.
    private final PeerConnection connection;
    /// The media kind.
    private final MediaKind kind;
    /// The track id `a=msid` carries when no track is attached.
    private final String fallbackTrackId = UUID.randomUUID().toString();
    /// The DTMF sender of an audio sender, `null` for video.
    private final DtmfSender dtmf;
    /// The frames a throwing transform dropped.
    private final AtomicLong transformFailures = new AtomicLong();
    /// The attached track, or `null`; written under the connection's lock, read without it.
    private volatile LocalTrack track;
    /// The media stream ids; guarded by the connection's lock.
    private List<String> streams;
    /// The encodings with their sources, an immutable list; written under the connection's lock, read without it.
    private volatile List<Negotiated.SendLayer> layers;
    /// The transaction id of the last `getParameters()`, or `null`.
    private String transactionId;
    /// The encoded transform, or `null`.
    private volatile FrameTransform transform;
    /// Where frames go once the sender is negotiated to send; [#IDLE] before and after.
    private volatile FrameSink pipeline = IDLE;
    /// The sink the attached track writes into.
    private final FrameSink sink = new FrameSink() {
        @Override
        public boolean accept(EncodedFrame frame, Optional<String> rid) {
            return send(frame, rid);
        }

        @Override
        public boolean forward(Forwarded packet) {
            return pipeline.forward(packet);
        }

        @Override
        public boolean isSending() {
            return pipeline.isSending();
        }
    };

    /// Creates a sender with its initial encodings; the caller holds the connection's lock.
    RtpSender(PeerConnection connection, MediaKind kind, List<String> streams, List<Encoding> encodings) {
        this.connection = connection;
        this.kind = kind;
        this.streams = List.copyOf(streams);
        var configuration = connection.configuration();
        this.dtmf = kind == MediaKind.AUDIO
                ? new DtmfSender(this, configuration.threadFactory(), configuration.clock()) : null;
        var initial = encodings.isEmpty() ? List.of(Encoding.defaults()) : encodings;
        var result = new ArrayList<Negotiated.SendLayer>();
        for (var encoding : initial) {
            result.add(connection.allocateLayer(encoding));
        }
        this.layers = List.copyOf(result);
    }

    /// {@return the media kind}
    public MediaKind kind() {
        return kind;
    }

    /// {@return the attached track, or an empty optional when none is}
    public Optional<LocalTrack> track() {
        return Optional.ofNullable(track);
    }

    /// {@return the DTLS transport the sender's RTP goes over, the W3C `RTCRtpSender.transport`, or an empty
    /// optional before the sender's media section is negotiated}
    public Optional<PeerDtlsTransport> transport() {
        return connection.transportOf(this);
    }

    /// Attaches another track without renegotiation, the W3C `replaceTrack`.
    ///
    /// The new track must be of the sender's kind; frames written to the old track are no longer sent.
    ///
    /// @param newTrack the track
    /// @throws IllegalArgumentException if the track's kind differs from the sender's
    /// @throws InvalidStateException    if the connection is closed or the transceiver stopped
    public void replaceTrack(LocalTrack newTrack) {
        Objects.requireNonNull(newTrack, "newTrack cannot be null");
        if (newTrack.kind() != kind) {
            throw new IllegalArgumentException("a " + kind + " sender cannot send a " + newTrack.kind() + " track");
        }
        synchronized (connection.lock()) {
            connection.checkOpen();
            setTrack(newTrack);
        }
    }

    /// Detaches the track without renegotiation, the W3C `replaceTrack(null)`; the sender sends nothing until a
    /// track is attached again.
    ///
    /// @throws InvalidStateException if the connection is closed
    public void clearTrack() {
        synchronized (connection.lock()) {
            connection.checkOpen();
            setTrack(null);
        }
    }

    /// Swaps the track; the caller holds the lock.
    void setTrack(LocalTrack newTrack) {
        var old = track;
        if (old != null) {
            old.detach(sink);
        }
        track = newTrack;
        if (newTrack != null) {
            newTrack.attach(sink);
            for (var layer : layers) {
                newTrack.encodingChanged(layer.rid(), layer.encoding());
            }
        }
    }

    /// {@return the ids of the media streams the track is announced in}
    public List<String> streams() {
        synchronized (connection.lock()) {
            return streams;
        }
    }

    /// Changes the media streams the track is announced in, the W3C `setStreams`; takes effect at the next
    /// negotiation.
    ///
    /// @param newStreams the stream ids
    /// @throws InvalidStateException if the connection is closed
    public void setStreams(List<String> newStreams) {
        var copy = List.copyOf(newStreams);
        synchronized (connection.lock()) {
            connection.checkOpen();
            streams = copy;
            connection.updateNegotiationNeeded();
        }
    }

    /// {@return the current parameters, with a fresh transaction id that [#setParameters(RtpSendParameters)]
    /// requires}
    public RtpSendParameters getParameters() {
        synchronized (connection.lock()) {
            transactionId = UUID.randomUUID().toString();
            return connection.sendParameters(this, transactionId);
        }
    }

    /// Changes the encoding parameters without renegotiation, the W3C `setParameters`.
    ///
    /// Only the activity, bitrate and frame rate caps, resolution divisor, priorities and scalability mode of each
    /// encoding may change. Each encoding that changes raises a [LocalTrackEvent.EncodingChanged] on the attached
    /// track, so the encoder can follow it; an inactive encoding's frames are dropped.
    ///
    /// @param parameters the parameters a `getParameters()` call returned, edited
    /// @throws InvalidStateException        if no `getParameters()` call preceded this one, or the connection is
    ///                                      closed
    /// @throws InvalidModificationException if the transaction id, the number of encodings or an RTP stream id
    ///                                      differs from the last `getParameters()` result
    /// @throws OperationErrorException      if a scalability mode is not one the webrtc-svc mode table defines for
    ///                                      the sender's codec (audio has none)
    public void setParameters(RtpSendParameters parameters) {
        Objects.requireNonNull(parameters, "parameters cannot be null");
        List<Negotiated.SendLayer> changed;
        LocalTrack current;
        synchronized (connection.lock()) {
            connection.checkOpen();
            if (transactionId == null) {
                throw new InvalidStateException("setParameters needs a preceding getParameters");
            }
            if (!transactionId.equals(parameters.transactionId())) {
                throw new InvalidModificationException("stale transaction id");
            }
            var encodings = parameters.encodings();
            if (encodings.size() != layers.size()) {
                throw new InvalidModificationException("the number of encodings cannot change");
            }
            var codecs = connection.sendCodecNames(this);
            var updated = new ArrayList<Negotiated.SendLayer>();
            changed = new ArrayList<>();
            for (var index = 0; index < encodings.size(); index++) {
                var layer = layers.get(index);
                var encoding = encodings.get(index);
                if (!encoding.rid().equals(layer.rid())) {
                    throw new InvalidModificationException("an encoding's rid cannot change");
                }
                encoding.scalabilityMode().ifPresent(mode -> checkScalabilityMode(mode, codecs));
                // TODO: validate encoding.codec() against the negotiated codecs (OperationErrorException) once
                //  Encoding carries the per-encoding codec member.
                var next = new Negotiated.SendLayer(layer.rid(), layer.ssrc(), layer.rtxSsrc(), encoding);
                updated.add(next);
                if (!encoding.equals(layer.encoding())) {
                    changed.add(next);
                }
            }
            layers = List.copyOf(updated);
            transactionId = null;
            current = track;
            connection.backend().updateEncodings(this, encodings);
        }
        if (current != null) {
            for (var layer : changed) {
                current.encodingChanged(layer.rid(), layer.encoding());
            }
        }
    }

    /// Fails unless `mode` is a webrtc-svc mode one of the sender's codecs can carry.
    ///
    /// @param codecs the lowercase names of the codecs the sender negotiated, or may negotiate before an exchange
    private void checkScalabilityMode(String mode, Set<String> codecs) {
        if (kind == MediaKind.AUDIO) {
            throw new OperationErrorException("an audio encoding has no scalability mode: " + mode);
        }
        if (TEMPORAL_MODES.contains(mode)) {
            return;
        }
        if (isSpatialMode(mode) && codecs.stream().anyMatch(SPATIAL_CODECS::contains)) {
            return;
        }
        throw new OperationErrorException("unsupported scalability mode for " + codecs + ": " + mode);
    }

    /// {@return whether `mode` is one of the spatial modes of the webrtc-svc table: `LxTy`, `LxTyh`, `SxTy`,
    /// `SxTyh` with x in 2..3 and y in 1..3, and the `_KEY` and `_KEY_SHIFT` variants of `L2T2`, `L2T3`, `L3T2` and
    /// `L3T3`}
    private static boolean isSpatialMode(String mode) {
        if (mode.length() < 4) {
            return false;
        }
        var prefix = mode.charAt(0);
        var spatial = mode.charAt(1);
        var temporal = mode.charAt(3);
        if ((prefix != 'L' && prefix != 'S') || mode.charAt(2) != 'T' || spatial < '2' || spatial > '3'
                || temporal < '1' || temporal > '3') {
            return false;
        }
        var suffix = mode.substring(4);
        return switch (suffix) {
            case "", "h" -> true;
            case "_KEY", "_KEY_SHIFT" -> prefix == 'L' && temporal >= '2';
            default -> false;
        };
    }

    /// Asks the attached track's encoder for a key frame on every layer, the W3C `RTCRtpScriptTransformer`
    /// `generateKeyFrame`: the track raises a [LocalTrackEvent.KeyframeRequested] per layer.
    ///
    /// @throws InvalidStateException if no track is attached
    public void generateKeyFrame() {
        var current = track;
        if (current == null) {
            throw new InvalidStateException("no track is attached");
        }
        List<Negotiated.SendLayer> snapshot;
        synchronized (connection.lock()) {
            snapshot = layers;
        }
        for (var layer : snapshot) {
            current.requestKeyframe(layer.rid());
        }
    }

    /// Asks the attached track's encoder for a key frame on the layer named `rid`.
    ///
    /// @param rid the RTP stream id of the layer
    /// @throws InvalidStateException    if no track is attached
    /// @throws IllegalArgumentException if the sender has no layer named `rid`
    public void generateKeyFrame(String rid) {
        Objects.requireNonNull(rid, "rid cannot be null");
        var current = track;
        if (current == null) {
            throw new InvalidStateException("no track is attached");
        }
        boolean known;
        synchronized (connection.lock()) {
            known = layers.stream().anyMatch(layer -> layer.rid().filter(rid::equals).isPresent());
        }
        if (!known) {
            throw new IllegalArgumentException("no encoding has rid " + rid);
        }
        current.requestKeyframe(Optional.of(rid));
    }

    /// {@return the DTMF sender of an audio sender, or an empty optional for video}
    public Optional<DtmfSender> dtmf() {
        return Optional.ofNullable(dtmf);
    }

    /// {@return the encoded transform, or an empty optional when frames are sent as written}
    public Optional<FrameTransform> transform() {
        return Optional.ofNullable(transform);
    }

    /// Installs an encoded transform that runs on every frame before packetization.
    ///
    /// @param newTransform the transform
    public void setTransform(FrameTransform newTransform) {
        transform = Objects.requireNonNull(newTransform, "newTransform cannot be null");
    }

    /// Removes the encoded transform.
    public void clearTransform() {
        transform = null;
    }

    /// {@return the frames dropped because the encoded transform threw}
    public long transformFailures() {
        return transformFailures.get();
    }

    /// {@return the statistics of this sender: its outbound streams, their remote views, media source, codecs and
    /// transport, the W3C sender stats selection}
    public StatsReport getStats() {
        return connection.getStats(this);
    }

    /// {@return the codecs and header extensions a sender of `kind` can negotiate by default}
    ///
    /// @param kind the media kind
    public static RtpCapabilities getCapabilities(MediaKind kind) {
        Objects.requireNonNull(kind, "kind cannot be null");
        return new RtpCapabilities(CodecCatalog.ofKind(CodecCatalog.defaultCodecs(), kind),
                CodecCatalog.defaultHeaderExtensions().stream()
                        .filter(extension -> CodecCatalog.extensionApplies(extension.uri(), kind)).toList());
    }

    /// Runs the transform on a frame the track wrote and hands its output to the pipeline.
    ///
    /// @return whether the frame was taken: the sender sends, and the transform (if any) did not throw
    private boolean send(EncodedFrame frame, Optional<String> rid) {
        var target = pipeline;
        if (!target.isSending()) {
            return false;
        }
        var current = transform;
        if (current == null) {
            return target.accept(frame, rid);
        }
        try {
            current.transform(frame, output -> pipeline.accept(Objects.requireNonNull(output), rid));
            return true;
        } catch (RuntimeException exception) {
            transformFailures.incrementAndGet();
            LOGGER.log(Level.DEBUG, "an encoded transform threw; the frame is dropped", exception);
            return false;
        }
    }

    /// {@return the track id `a=msid` announces}
    String msidTrackId() {
        var current = track;
        return current != null ? current.id() : fallbackTrackId;
    }

    /// {@return the attached track, or `null`}
    LocalTrack trackOrNull() {
        return track;
    }

    /// {@return the encodings with their sources; the caller holds the lock}
    List<Negotiated.SendLayer> layers() {
        return layers;
    }

    /// {@return the encodings with their sources, read without the lock, for the media path}
    List<Negotiated.SendLayer> currentLayers() {
        return layers;
    }

    /// {@return whether the encoding named `rid` (`""` without simulcast) is active; an unknown one is}
    boolean isLayerActive(String rid) {
        for (var layer : layers) {
            if (layer.rid().orElse("").equals(rid)) {
                return layer.encoding().active();
            }
        }
        return true;
    }

    /// Installs where negotiated frames go, and tells the track the negotiated encodings.
    void setPipeline(FrameSink newPipeline, List<Negotiated.SendLayer> negotiatedLayers) {
        pipeline = Objects.requireNonNull(newPipeline);
        var current = track;
        if (current != null) {
            for (var layer : negotiatedLayers) {
                current.encodingChanged(layer.rid(), layer.encoding());
            }
        }
    }

    /// Stops sending, as when the transceiver stops or a negotiation drops the sending direction; cancels the DTMF
    /// tones not yet played.
    void stopSending() {
        pipeline = IDLE;
        if (dtmf != null) {
            dtmf.cancel();
        }
    }

    /// Stops sending for good, as when the connection closes: also ends the DTMF sender's events.
    void close() {
        stopSending();
        if (dtmf != null) {
            dtmf.close();
        }
    }

    /// {@return the connection the sender belongs to}
    PeerConnection connection() {
        return connection;
    }
}
