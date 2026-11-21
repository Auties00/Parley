package com.github.auties00.parley.peer;

import com.github.auties00.parley.jitter.AudioPlayout;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.RtpPacket;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/// The media a receiver gets from the peer, the counterpart of a W3C remote `MediaStreamTrack`: encoded frames the
/// application decodes, or raw RTP packets an SFU forwards.
///
/// The [mode][#mode()] is fixed by the peer connection's configuration:
///
/// - [RemoteTrackMode#JITTER_BUFFERED]: [#read()] returns encoded frames in decode order after the jitter buffer
///   (video frames once complete and decodable, audio frames at their playout time); for audio, [#readPlayout()]
///   also reports the gaps the application must conceal.
/// - [RemoteTrackMode#RAW_PACKETS]: [#readPacket()] returns each RTP packet as it arrives, after SRTP and
///   retransmission recovery, with the RTP stream id of its simulcast layer.
///
/// {@snippet lang = java :
/// var track = transceiver.receiver().track();
/// while (true) {
///     EncodedFrame frame = track.read();       // blocks until the next decodable frame
///     decoder.decode(frame);
/// }
/// }
///
/// The track keeps at most 1024 undelivered items; when the application reads too slowly the oldest are dropped and
/// counted in [#dropped()].
///
/// # Threading
///
/// Reads may come from any thread; each item goes to one reader.
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public final class RemoteTrack {
    /// The capacity of the delivery queue.
    private static final int CAPACITY = 1024;

    /// A received RTP packet, as [RemoteTrack#readPacket()] returns it.
    ///
    /// @param packet       a copy of the packet, which the reader owns
    /// @param rid          the RTP stream id of the simulcast layer it belongs to, or an empty optional
    /// @param arrivalNanos when it arrived, in the connection's monotonic clock
    public record Packet(RtpPacket packet, Optional<String> rid, long arrivalNanos) {
        /// Creates the packet.
        ///
        /// @param packet       the packet
        /// @param rid          the layer, or an empty optional
        /// @param arrivalNanos the arrival time
        public Packet {
            Objects.requireNonNull(packet, "packet cannot be null");
            Objects.requireNonNull(rid, "rid cannot be null");
        }
    }

    /// The track id, from the peer's `a=msid`, or random when it sent none.
    private final String id;
    /// The media kind.
    private final MediaKind kind;
    /// The delivery mode.
    private final RemoteTrackMode mode;
    /// Guards [#queue], [#ended] and [#muted].
    private final ReentrantLock lock = new ReentrantLock();
    /// Signals a new item or the end.
    private final Condition available = lock.newCondition();
    /// The undelivered frames, playout outcomes or packets.
    private final ArrayDeque<Object> queue = new ArrayDeque<>();
    /// The items dropped because the queue was full.
    private final AtomicLong dropped = new AtomicLong();
    /// Whether the track has ended.
    private boolean ended;
    /// Whether the track has received nothing since the peer last stopped sending.
    private boolean muted = true;

    /// Creates a track.
    RemoteTrack(String id, MediaKind kind, RemoteTrackMode mode) {
        this.id = Objects.requireNonNull(id);
        this.kind = Objects.requireNonNull(kind);
        this.mode = Objects.requireNonNull(mode);
    }

    /// {@return the track id}
    public String id() {
        return id;
    }

    /// {@return the media kind}
    public MediaKind kind() {
        return kind;
    }

    /// {@return the delivery mode}
    public RemoteTrackMode mode() {
        return mode;
    }

    /// {@return whether the track is muted: nothing has arrived yet, or the peer stopped sending}
    public boolean isMuted() {
        lock.lock();
        try {
            return muted;
        } finally {
            lock.unlock();
        }
    }

    /// {@return whether the track has ended: its transceiver stopped or the connection closed}
    public boolean isEnded() {
        lock.lock();
        try {
            return ended;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the items dropped because the application read too slowly}
    public long dropped() {
        return dropped.get();
    }

    /// Waits for the next encoded frame.
    ///
    /// For audio, the gaps [#readPlayout()] would report are skipped.
    ///
    /// @return the frame
    /// @throws IllegalStateException if the mode is not `JITTER_BUFFERED`, or the track has ended and every frame was
    ///                               read
    /// @throws InterruptedException  if the calling thread is interrupted while waiting
    public EncodedFrame read() throws InterruptedException {
        requireMode(RemoteTrackMode.JITTER_BUFFERED);
        while (true) {
            var item = take(Long.MAX_VALUE).orElseThrow(() -> new IllegalStateException("the track has ended"));
            var frame = asFrame(item);
            if (frame.isPresent()) {
                return frame.get();
            }
        }
    }

    /// Waits up to `timeout` for the next encoded frame.
    ///
    /// @param timeout the longest time to wait
    /// @return the frame, or an empty optional when the timeout elapsed or the track has ended
    /// @throws IllegalStateException if the mode is not `JITTER_BUFFERED`
    /// @throws InterruptedException  if the calling thread is interrupted while waiting
    public Optional<EncodedFrame> read(Duration timeout) throws InterruptedException {
        requireMode(RemoteTrackMode.JITTER_BUFFERED);
        var deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            var item = take(deadline);
            if (item.isEmpty()) {
                return Optional.empty();
            }
            var frame = asFrame(item.get());
            if (frame.isPresent()) {
                return frame;
            }
        }
    }

    /// Waits for the next playout outcome of an audio track: a frame to decode, a gap to conceal, or silence while
    /// the peer sends no audio (DTX).
    ///
    /// @return the outcome
    /// @throws IllegalStateException if the track is not an audio track in `JITTER_BUFFERED` mode, or it has ended
    ///                               and every outcome was read
    /// @throws InterruptedException  if the calling thread is interrupted while waiting
    public AudioPlayout readPlayout() throws InterruptedException {
        requireMode(RemoteTrackMode.JITTER_BUFFERED);
        if (kind != MediaKind.AUDIO) {
            throw new IllegalStateException("only an audio track has playout outcomes");
        }
        var item = take(Long.MAX_VALUE).orElseThrow(() -> new IllegalStateException("the track has ended"));
        return item instanceof AudioPlayout playout ? playout : new AudioPlayout.Frame((EncodedFrame) item,
                java.time.Duration.ZERO);
    }

    /// Waits for the next RTP packet.
    ///
    /// @return the packet
    /// @throws IllegalStateException if the mode is not `RAW_PACKETS`, or the track has ended and every packet was
    ///                               read
    /// @throws InterruptedException  if the calling thread is interrupted while waiting
    public Packet readPacket() throws InterruptedException {
        requireMode(RemoteTrackMode.RAW_PACKETS);
        return (Packet) take(Long.MAX_VALUE).orElseThrow(() -> new IllegalStateException("the track has ended"));
    }

    /// Waits up to `timeout` for the next RTP packet.
    ///
    /// @param timeout the longest time to wait
    /// @return the packet, or an empty optional when the timeout elapsed or the track has ended
    /// @throws IllegalStateException if the mode is not `RAW_PACKETS`
    /// @throws InterruptedException  if the calling thread is interrupted while waiting
    public Optional<Packet> readPacket(Duration timeout) throws InterruptedException {
        requireMode(RemoteTrackMode.RAW_PACKETS);
        return take(System.nanoTime() + timeout.toNanos()).map(Packet.class::cast);
    }

    /// Fails unless the track delivers in `expected` mode.
    private void requireMode(RemoteTrackMode expected) {
        if (mode != expected) {
            throw new IllegalStateException("the track delivers in " + mode + " mode");
        }
    }

    /// {@return the frame an item carries, if any}
    private static Optional<EncodedFrame> asFrame(Object item) {
        return switch (item) {
            case EncodedFrame frame -> Optional.of(frame);
            case AudioPlayout.Frame(var frame, var ignored) -> Optional.of(frame);
            default -> Optional.empty();
        };
    }

    /// Takes the next item, waiting until `deadlineNanos` (`Long.MAX_VALUE` for no deadline).
    private Optional<Object> take(long deadlineNanos) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (queue.isEmpty()) {
                if (ended) {
                    return Optional.empty();
                }
                if (deadlineNanos == Long.MAX_VALUE) {
                    available.await();
                } else {
                    var left = deadlineNanos - System.nanoTime();
                    if (left <= 0) {
                        return Optional.empty();
                    }
                    available.awaitNanos(left);
                }
            }
            return Optional.of(queue.removeFirst());
        } finally {
            lock.unlock();
        }
    }

    /// Queues a frame, playout outcome or packet for the reader, unmuting the track.
    void deliver(Object item) {
        Objects.requireNonNull(item);
        lock.lock();
        try {
            if (ended) {
                return;
            }
            if (queue.size() >= CAPACITY) {
                queue.removeFirst();
                dropped.incrementAndGet();
            }
            queue.addLast(item);
            muted = false;
            available.signal();
        } finally {
            lock.unlock();
        }
    }

    /// Mutes the track, as when the peer stops sending.
    void mute() {
        lock.lock();
        try {
            muted = true;
        } finally {
            lock.unlock();
        }
    }

    /// Ends the track; readers get the queued items, then the end.
    void end() {
        lock.lock();
        try {
            ended = true;
            muted = true;
            available.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// {@return the kind and id of the track}
    @Override
    public String toString() {
        return "RemoteTrack[id=" + id + ", kind=" + kind + "]";
    }
}
