package com.github.auties00.parley.peer;

import com.github.auties00.parley.event.EventSource;
import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/// A source of encoded media the application writes into, the counterpart of a W3C `MediaStreamTrack` attached to a
/// sender.
///
/// Parley does not capture or encode: the application encodes frames with its own codec and writes them with
/// [#write(EncodedFrame)]; every sender the track is attached to packetizes and sends them. A
/// [forwarded track][#forwarded(String, MediaKind)] instead takes RTP packets received from another peer, as an SFU
/// does. In the other direction the track tells the encoder what the network asks for through its
/// [events][#events()]: a key frame after a picture loss indication or full intra request from the peer, the target
/// bitrate the congestion controller allocates, and the encoding parameters the application or the negotiation set.
///
/// {@snippet lang = java :
/// var video = LocalTrack.video("camera");
/// var events = video.events();            // opened first: it also gets what addTrack raises
/// peerConnection.addTrack(video, "stream-1");
/// Thread.ofVirtual().start(() -> {
///     try (events) {
///         for (var event : events) {
///             switch (event) {
///                 case LocalTrackEvent.KeyframeRequested(var rid) -> encoder.forceKeyframe(rid);
///                 case LocalTrackEvent.TargetBitrateChanged(var rid, var bps) -> encoder.setBitrate(rid, bps);
///                 case LocalTrackEvent.EncodingChanged(var rid, var encoding) -> encoder.configure(rid, encoding);
///                 case LocalTrackEvent.Ended() -> { }
///             }
///         }
///     }
/// });
/// while (capturing) {
///     video.write(encoder.encode(camera.grab()));
/// }
/// }
///
/// # Threading
///
/// Every method is safe for concurrent use. [#write(EncodedFrame)] packetizes on the calling thread and hands the
/// packets to the pacer without waiting for the network. The track starts no thread of its own.
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
/// @spec https://www.w3.org/TR/webrtc-encoded-transform/ WebRTC Encoded Transform
public abstract sealed class LocalTrack permits LocalAudioTrack, LocalVideoTrack, LocalForwardedTrack {
    /// The track id, which `a=msid` carries.
    private final String id;
    /// The media kind.
    private final MediaKind kind;
    /// The senders the track feeds.
    private final CopyOnWriteArrayList<FrameSink> sinks = new CopyOnWriteArrayList<>();
    /// The track events; bitrate and encoding changes of one layer coalesce.
    private final EventSource<LocalTrackEvent> events = new EventSource<>(EventSource.DEFAULT_CAPACITY,
            LocalTrack::coalescingKey);
    /// The last target bitrate per encoding, keyed by RTP stream id (`""` without simulcast).
    private final Map<String, Long> targets = new ConcurrentHashMap<>();
    /// The frames written.
    private final AtomicLong framesWritten = new AtomicLong();
    /// The key frames written.
    private final AtomicLong keyFramesWritten = new AtomicLong();
    /// The frames or packets no sender took.
    private final AtomicLong framesDropped = new AtomicLong();
    /// Whether frames are sent.
    private volatile boolean enabled = true;
    /// Whether the track has ended.
    private volatile boolean ended;

    /// Creates a track.
    LocalTrack(String id, MediaKind kind) {
        this.id = Objects.requireNonNull(id, "id cannot be null");
        this.kind = Objects.requireNonNull(kind, "kind cannot be null");
        if (id.isEmpty() || id.length() > 64 || id.chars().anyMatch(c -> c <= ' ' || c > '~')) {
            throw new IllegalArgumentException("a track id is 1 to 64 visible ASCII characters: " + id);
        }
    }

    /// {@return a new audio track}
    ///
    /// @param id the track id, 1 to 64 visible ASCII characters, which the peer sees in `a=msid`
    /// @throws IllegalArgumentException if `id` is not a valid track id
    public static LocalAudioTrack audio(String id) {
        return new LocalAudioTrack(id);
    }

    /// {@return a new video track}
    ///
    /// @param id the track id, 1 to 64 visible ASCII characters, which the peer sees in `a=msid`
    /// @throws IllegalArgumentException if `id` is not a valid track id
    public static LocalVideoTrack video(String id) {
        return new LocalVideoTrack(id);
    }

    /// {@return a new track that forwards RTP packets received from another peer, as an SFU does}
    ///
    /// @param id   the track id, 1 to 64 visible ASCII characters, which the peer sees in `a=msid`
    /// @param kind the media kind of the packets
    /// @throws IllegalArgumentException if `id` is not a valid track id
    public static LocalForwardedTrack forwarded(String id, MediaKind kind) {
        return new LocalForwardedTrack(id, kind);
    }

    /// {@return the track id}
    public String id() {
        return id;
    }

    /// {@return the media kind}
    public MediaKind kind() {
        return kind;
    }

    /// {@return whether written frames are sent}
    public boolean isEnabled() {
        return enabled;
    }

    /// Enables or disables the track; a disabled track drops the frames written to it, and the application should
    /// write silence or black frames instead if the peer must keep receiving media.
    ///
    /// @param enabled whether written frames are sent
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /// {@return whether the track has ended}
    public boolean isEnded() {
        return ended;
    }

    /// {@return whether a frame written now would be sent: the track is enabled, not ended, and attached to a
    /// sender whose transceiver is negotiated to send}
    public boolean isSending() {
        if (!enabled || ended) {
            return false;
        }
        for (var sink : sinks) {
            if (sink.isSending()) {
                return true;
            }
        }
        return false;
    }

    /// Ends the track: writes fail from now on, its senders send nothing more, and its event streams end after an
    /// [LocalTrackEvent.Ended] event. Idempotent.
    public void stop() {
        if (!ended) {
            ended = true;
            events.publish(new LocalTrackEvent.Ended());
            events.end();
        }
    }

    /// Writes one encoded frame to every sender the track is attached to.
    ///
    /// A frame no sender takes is dropped and counted in [#framesDropped()]: the track is disabled, attached to no
    /// sender, or its senders are not negotiated yet or do not send. On a simulcast sender the frame goes to the
    /// first encoding; [LocalVideoTrack#write(EncodedFrame, String)] targets a layer.
    ///
    /// @param frame the frame, whose RTP timestamp is in the clock rate of the negotiated codec
    /// @throws IllegalArgumentException if the frame's kind differs from the track's
    /// @throws IllegalStateException    if the track has ended
    public void write(EncodedFrame frame) {
        write(frame, Optional.empty());
    }

    /// Writes a frame to one encoding, or to the first one when `rid` is empty.
    void write(EncodedFrame frame, Optional<String> rid) {
        Objects.requireNonNull(frame, "frame cannot be null");
        if (frame.kind() != kind) {
            throw new IllegalArgumentException("a " + kind + " track cannot carry a " + frame.kind() + " frame");
        }
        checkNotEnded();
        framesWritten.incrementAndGet();
        if (frame.keyframe()) {
            keyFramesWritten.incrementAndGet();
        }
        var taken = false;
        if (enabled) {
            for (var sink : sinks) {
                taken |= sink.accept(frame, rid);
            }
        }
        if (!taken) {
            framesDropped.incrementAndGet();
        }
    }

    /// Forwards a packet to every sender the track is attached to, counting it as dropped when none takes it.
    void forward(FrameSink.Forwarded packet) {
        checkNotEnded();
        var taken = false;
        if (enabled) {
            for (var sink : sinks) {
                taken |= sink.forward(packet);
            }
        }
        if (!taken) {
            framesDropped.incrementAndGet();
        }
    }

    /// Fails when the track has ended.
    private void checkNotEnded() {
        if (ended) {
            throw new IllegalStateException("the track has ended");
        }
    }

    /// {@return a stream of the track's events: key frame requests, target bitrates, encoding changes and the end}
    ///
    /// The first stream opened also gets every event raised since the track was created.
    public EventStream<LocalTrackEvent> events() {
        return events.open();
    }

    /// Waits for the next key frame request raised after this call.
    ///
    /// @param timeout the longest time to wait
    /// @return the request, or an empty optional when the timeout elapsed or the track ended
    /// @throws InterruptedException if the calling thread is interrupted while waiting
    public Optional<LocalTrackEvent.KeyframeRequested> awaitKeyframeRequest(Duration timeout)
            throws InterruptedException {
        Objects.requireNonNull(timeout, "timeout cannot be null");
        var deadline = System.nanoTime() + timeout.toNanos();
        var stream = events.open();
        try (stream) {
            while (true) {
                var left = deadline - System.nanoTime();
                if (left <= 0) {
                    return Optional.empty();
                }
                var event = stream.next(Duration.ofNanos(left));
                if (event.isEmpty()) {
                    return Optional.empty();
                }
                if (event.get() instanceof LocalTrackEvent.KeyframeRequested request) {
                    return Optional.of(request);
                }
            }
        }
    }

    /// {@return the last target bitrate allocated to the track's only or first encoding, in bits per second, or an
    /// empty optional before the first estimate}
    public OptionalLong targetBitrate() {
        var value = targets.get("");
        if (value == null && !targets.isEmpty()) {
            value = targets.values().iterator().next();
        }
        return value == null ? OptionalLong.empty() : OptionalLong.of(value);
    }

    /// {@return the last target bitrate allocated to the encoding named `rid`, or an empty optional before the first
    /// estimate}
    ///
    /// @param rid the RTP stream id
    public OptionalLong targetBitrate(String rid) {
        var value = targets.get(Objects.requireNonNull(rid, "rid cannot be null"));
        return value == null ? OptionalLong.empty() : OptionalLong.of(value);
    }

    /// {@return the frames written to the track}
    public long framesWritten() {
        return framesWritten.get();
    }

    /// {@return the key frames written to the track}
    long keyFramesWritten() {
        return keyFramesWritten.get();
    }

    /// {@return the frames (or, for a forwarded track, packets) written that no sender took: the track was disabled,
    /// attached to no sender, its senders were not negotiated or not sending, or the layer was inactive}
    public long framesDropped() {
        return framesDropped.get();
    }

    /// Attaches a sender.
    void attach(FrameSink sink) {
        sinks.addIfAbsent(sink);
    }

    /// Detaches a sender.
    void detach(FrameSink sink) {
        sinks.remove(sink);
    }

    /// Raises a key frame request for an encoding.
    void requestKeyframe(Optional<String> rid) {
        if (!ended) {
            events.publish(new LocalTrackEvent.KeyframeRequested(rid));
        }
    }

    /// Records and raises a new target bitrate for an encoding, when it changed.
    void updateTargetBitrate(Optional<String> rid, long bitsPerSecond) {
        var previous = targets.put(rid.orElse(""), bitsPerSecond);
        if (!ended && (previous == null || previous != bitsPerSecond)) {
            events.publish(new LocalTrackEvent.TargetBitrateChanged(rid, bitsPerSecond));
        }
    }

    /// Raises the parameters of an encoding the track feeds.
    void encodingChanged(Optional<String> rid, Encoding encoding) {
        if (!ended) {
            events.publish(new LocalTrackEvent.EncodingChanged(rid, encoding));
        }
    }

    /// {@return the key under which an event replaces an undelivered one of the same layer}
    private static Optional<?> coalescingKey(LocalTrackEvent event) {
        return switch (event) {
            case LocalTrackEvent.TargetBitrateChanged(var rid, var ignored) -> Optional.of(List.of("bitrate", rid));
            case LocalTrackEvent.EncodingChanged(var rid, var ignored) -> Optional.of(List.of("encoding", rid));
            case LocalTrackEvent.KeyframeRequested ignored -> Optional.empty();
            case LocalTrackEvent.Ended ignored -> Optional.empty();
        };
    }

    /// {@return the kind and id of the track}
    @Override
    public String toString() {
        return getClass().getSimpleName() + "[id=" + id + "]";
    }
}
