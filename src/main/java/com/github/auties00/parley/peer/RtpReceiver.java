package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.stats.StatsReport;

import java.lang.System.Logger.Level;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.concurrent.ConcurrentHashMap;

/// The receiving half of a transceiver, the W3C `RTCRtpReceiver`: it receives the peer's RTP streams for one media
/// section and delivers them through its [RemoteTrack].
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.w3.org/TR/webrtc-extensions/ WebRTC Extensions
public final class RtpReceiver {
    private static final System.Logger LOGGER = System.getLogger(RtpReceiver.class.getName());
    /// How long a source stays listed after its last packet, as the W3C specification requires.
    private static final Duration SOURCE_LIFETIME = Duration.ofSeconds(10);

    /// The connection the receiver belongs to.
    private final PeerConnection connection;
    /// The track the receiver delivers to.
    private final RemoteTrack track;
    /// The last packet of each synchronization source.
    private final Map<Long, SynchronizationSource> synchronizationSources = new ConcurrentHashMap<>();
    /// The last packet of each contributing source.
    private final Map<Long, ContributingSource> contributingSources = new ConcurrentHashMap<>();
    /// The encoded transform, or `null`.
    private volatile FrameTransform transform;
    /// The jitter buffer target the application asked for, or `null`.
    private volatile Duration jitterBufferTarget;

    /// Creates a receiver whose track has `trackId`.
    RtpReceiver(PeerConnection connection, MediaKind kind, String trackId, RemoteTrackMode mode) {
        this.connection = connection;
        this.track = new RemoteTrack(trackId, kind, mode);
    }

    /// {@return the track the receiver delivers to}
    public RemoteTrack track() {
        return track;
    }

    /// {@return the negotiated parameters}
    public RtpReceiveParameters getParameters() {
        return connection.receiveParameters(this);
    }

    /// {@return the sources that sent media in the last ten seconds, the W3C `getSynchronizationSources`}
    public List<SynchronizationSource> getSynchronizationSources() {
        var cutoff = Instant.now().minus(SOURCE_LIFETIME);
        var result = new ArrayList<SynchronizationSource>();
        for (var source : synchronizationSources.values()) {
            if (source.timestamp().isAfter(cutoff)) {
                result.add(source);
            }
        }
        return List.copyOf(result);
    }

    /// {@return the contributing sources a mixer listed in the last ten seconds, the W3C `getContributingSources`}
    public List<ContributingSource> getContributingSources() {
        var cutoff = Instant.now().minus(SOURCE_LIFETIME);
        var result = new ArrayList<ContributingSource>();
        for (var source : contributingSources.values()) {
            if (source.timestamp().isAfter(cutoff)) {
                result.add(source);
            }
        }
        return List.copyOf(result);
    }

    /// {@return the jitter buffer target the application set, or an empty optional when the jitter buffer adapts on
    /// its own}
    public Optional<Duration> jitterBufferTarget() {
        return Optional.ofNullable(jitterBufferTarget);
    }

    /// Sets the playout delay the jitter buffer aims for, the W3C `jitterBufferTarget`.
    ///
    /// @param target the target, `0` to 4000 ms
    /// @throws IllegalArgumentException if `target` is negative or above 4000 ms
    public void setJitterBufferTarget(Duration target) {
        Objects.requireNonNull(target, "target cannot be null");
        if (target.isNegative() || target.compareTo(Duration.ofMillis(4000)) > 0) {
            throw new IllegalArgumentException("jitterBufferTarget must be within 0..4000 ms");
        }
        jitterBufferTarget = target;
        connection.backend().updateJitterBufferTarget(this, Optional.of(target));
    }

    /// Lets the jitter buffer choose its delay again.
    public void clearJitterBufferTarget() {
        jitterBufferTarget = null;
        connection.backend().updateJitterBufferTarget(this, Optional.empty());
    }

    /// {@return the encoded transform, or an empty optional when frames are delivered as assembled}
    public Optional<FrameTransform> transform() {
        return Optional.ofNullable(transform);
    }

    /// Installs an encoded transform that runs on every assembled frame before the application reads it.
    ///
    /// @param newTransform the transform
    public void setTransform(FrameTransform newTransform) {
        transform = Objects.requireNonNull(newTransform, "newTransform cannot be null");
    }

    /// Removes the encoded transform.
    public void clearTransform() {
        transform = null;
    }

    /// {@return the statistics of this receiver: its inbound streams, their remote views, codecs and transport, the
    /// W3C receiver stats selection}
    public StatsReport getStats() {
        return connection.getStats(this);
    }

    /// {@return the codecs and header extensions a receiver of `kind` can negotiate by default}
    ///
    /// @param kind the media kind
    public static RtpCapabilities getCapabilities(MediaKind kind) {
        return RtpSender.getCapabilities(kind);
    }

    /// Delivers an assembled frame through the transform to the track.
    void deliverFrame(EncodedFrame frame) {
        var current = transform;
        var incoming = frame;
        if (current != null) {
            try {
                incoming = current.apply(frame);
            } catch (RuntimeException exception) {
                LOGGER.log(Level.WARNING, "an encoded transform threw; the frame is dropped", exception);
                return;
            }
        }
        track.deliver(incoming);
    }

    /// Records the last packet of a synchronization source and of the contributing sources it lists.
    void recordSources(long ssrc, long rtpTimestamp, OptionalDouble audioLevel, List<Long> csrcs) {
        var now = Instant.now();
        synchronizationSources.put(ssrc, new SynchronizationSource(ssrc, now, rtpTimestamp, audioLevel));
        for (var csrc : csrcs) {
            contributingSources.put(csrc, new ContributingSource(csrc, now, rtpTimestamp, OptionalDouble.empty()));
        }
    }

    /// {@return the connection the receiver belongs to}
    PeerConnection connection() {
        return connection;
    }
}
