package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.stats.StatsReport;

import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/// The sending half of a transceiver, the W3C `RTCRtpSender`: it sends the frames of its [LocalTrack] with the
/// negotiated codec, one RTP stream per encoding.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.w3.org/TR/webrtc-extensions/ WebRTC Extensions
/// @spec https://www.w3.org/TR/webrtc-svc/ Scalable Video Coding (SVC) Extension for WebRTC
public final class RtpSender {
    private static final System.Logger LOGGER = System.getLogger(RtpSender.class.getName());

    /// The connection the sender belongs to.
    private final PeerConnection connection;
    /// The media kind.
    private final MediaKind kind;
    /// The track id `a=msid` carries when no track is attached.
    private final String fallbackTrackId = UUID.randomUUID().toString();
    /// The DTMF sender of an audio sender, `null` for video.
    private final DtmfSender dtmf;
    /// The attached track, or `null`; guarded by the connection's lock.
    private LocalTrack track;
    /// The media stream ids; guarded by the connection's lock.
    private List<String> streams;
    /// The encodings with their sources; guarded by the connection's lock.
    private List<Negotiated.SendLayer> layers;
    /// The transaction id of the last `getParameters()`, or `null`.
    private String transactionId;
    /// The encoded transform, or `null`.
    private volatile FrameTransform transform;
    /// The sink the attached track writes into.
    private final FrameSink sink = this::send;
    /// Where frames go once the sender is negotiated; drops them before.
    private volatile FrameSink pipeline = (frame, rid) -> { };

    /// Creates a sender with its initial encodings.
    RtpSender(PeerConnection connection, MediaKind kind, List<String> streams, List<Encoding> encodings) {
        this.connection = connection;
        this.kind = kind;
        this.streams = List.copyOf(streams);
        this.dtmf = kind == MediaKind.AUDIO ? new DtmfSender(this) : null;
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
        synchronized (connection.lock()) {
            return Optional.ofNullable(track);
        }
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
        if (track != null) {
            track.detach(sink);
        }
        track = newTrack;
        if (newTrack != null) {
            newTrack.attach(sink);
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
    /// encoding may change.
    ///
    /// @param parameters the parameters a `getParameters()` call returned, edited
    /// @throws InvalidStateException        if no `getParameters()` call preceded this one, or the connection is
    ///                                      closed
    /// @throws InvalidModificationException if the transaction id, the number of encodings or an RTP stream id
    ///                                      differs from the last `getParameters()` result
    public void setParameters(RtpSendParameters parameters) {
        Objects.requireNonNull(parameters, "parameters cannot be null");
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
            var updated = new ArrayList<Negotiated.SendLayer>();
            for (var index = 0; index < encodings.size(); index++) {
                var layer = layers.get(index);
                var encoding = encodings.get(index);
                if (!encoding.rid().equals(layer.rid())) {
                    throw new InvalidModificationException("an encoding's rid cannot change");
                }
                updated.add(new Negotiated.SendLayer(layer.rid(), layer.ssrc(), layer.rtxSsrc(), encoding));
            }
            layers = List.copyOf(updated);
            transactionId = null;
            connection.backend().updateEncodings(this, encodings);
        }
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

    /// Runs the transform on a frame the track wrote and hands it to the pipeline.
    private void send(EncodedFrame frame, Optional<String> rid) {
        var current = transform;
        var outgoing = frame;
        if (current != null) {
            try {
                outgoing = current.apply(frame);
            } catch (RuntimeException exception) {
                LOGGER.log(Level.WARNING, "an encoded transform threw; the frame is dropped", exception);
                return;
            }
        }
        pipeline.accept(outgoing, rid);
    }

    /// {@return the track id `a=msid` announces}
    String msidTrackId() {
        return track != null ? track.id() : fallbackTrackId;
    }

    /// {@return the attached track, or `null`; the caller holds the lock}
    LocalTrack trackOrNull() {
        return track;
    }

    /// {@return the encodings with their sources; the caller holds the lock}
    List<Negotiated.SendLayer> layers() {
        return layers;
    }

    /// Installs where negotiated frames go.
    void setPipeline(FrameSink newPipeline) {
        pipeline = Objects.requireNonNull(newPipeline);
    }

    /// Stops sending, as when the transceiver stops.
    void stopSending() {
        pipeline = (frame, rid) -> { };
    }

    /// {@return the connection the sender belongs to}
    PeerConnection connection() {
        return connection;
    }
}
