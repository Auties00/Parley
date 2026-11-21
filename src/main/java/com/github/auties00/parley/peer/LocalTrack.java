package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;

import java.time.Duration;
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
/// [#write(EncodedFrame)]; every sender the track is attached to packetizes and sends them. In the other direction the
/// track tells the encoder what the network asks for through its [events][#events()]: a key frame after a picture
/// loss indication or full intra request from the peer, and the target bitrate the congestion controller allocates.
///
/// {@snippet lang = java :
/// var video = LocalTrack.video("camera");
/// peerConnection.addTrack(video, List.of("stream-1"));
/// Thread.ofVirtual().start(() -> {
///     try (var events = video.events()) {
///         for (var event : events) {
///             switch (event) {
///                 case LocalTrackEvent.KeyframeRequested(var rid) -> encoder.forceKeyframe(rid);
///                 case LocalTrackEvent.TargetBitrateChanged(var rid, var bps) -> encoder.setBitrate(rid, bps);
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
/// packets to the pacer without waiting for the network.
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
/// @spec https://www.w3.org/TR/webrtc-encoded-transform/ WebRTC Encoded Transform
public abstract sealed class LocalTrack permits LocalAudioTrack, LocalVideoTrack {
    /// The track id, which `a=msid` carries.
    private final String id;
    /// The media kind.
    private final MediaKind kind;
    /// The senders the track feeds.
    private final CopyOnWriteArrayList<FrameSink> sinks = new CopyOnWriteArrayList<>();
    /// The track events.
    private final EventHub<LocalTrackEvent> events = new EventHub<>(Thread.ofVirtual().name("parley-track-", 0).factory());
    /// The last target bitrate per encoding, keyed by RTP stream id (`""` without simulcast).
    private final Map<String, Long> targets = new ConcurrentHashMap<>();
    /// The frames written.
    private final AtomicLong framesWritten = new AtomicLong();
    /// The key frames written.
    private final AtomicLong keyFramesWritten = new AtomicLong();
    /// The frames dropped because the track was disabled or attached to no sender.
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
    /// A frame written while the track is disabled or attached to no negotiated sender is dropped. On a simulcast
    /// sender the frame goes to the first encoding; [LocalVideoTrack#write(EncodedFrame, String)] targets a layer.
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
        if (ended) {
            throw new IllegalStateException("the track has ended");
        }
        framesWritten.incrementAndGet();
        if (frame.keyframe()) {
            keyFramesWritten.incrementAndGet();
        }
        if (!enabled || sinks.isEmpty()) {
            framesDropped.incrementAndGet();
            return;
        }
        for (var sink : sinks) {
            sink.accept(frame, rid);
        }
    }

    /// {@return a stream of the events raised from now on: key frame requests, target bitrates and the end}
    public EventStream<LocalTrackEvent> events() {
        return events.open();
    }

    /// Waits for the next key frame request.
    ///
    /// @param timeout the longest time to wait
    /// @return the request, or an empty optional when the timeout elapsed or the track ended
    /// @throws InterruptedException if the calling thread is interrupted while waiting
    public Optional<LocalTrackEvent.KeyframeRequested> awaitKeyframeRequest(Duration timeout)
            throws InterruptedException {
        var deadline = System.nanoTime() + timeout.toNanos();
        try (var stream = events.open()) {
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

    /// {@return the frames dropped because the track was disabled or attached to no sender}
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

    /// {@return the kind and id of the track}
    @Override
    public String toString() {
        return getClass().getSimpleName() + "[id=" + id + "]";
    }
}
