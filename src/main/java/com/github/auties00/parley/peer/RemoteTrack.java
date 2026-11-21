package com.github.auties00.parley.peer;

import com.github.auties00.parley.event.EventSource;
import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.jitter.AudioPlayout;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.RtpPacket;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/// The media a receiver gets from the peer, the counterpart of a W3C remote `MediaStreamTrack`: encoded frames the
/// application decodes, or raw RTP packets an SFU forwards.
///
/// The [mode][#mode()] decides what the track delivers:
///
/// - [RemoteTrackMode#JITTER_BUFFERED]: [#frames()] streams encoded frames in decode order after the jitter buffer
///   (video frames once complete and decodable, audio frames at their playout time); for audio, [#playout()] also
///   streams the gaps the application must conceal.
/// - [RemoteTrackMode#RAW_PACKETS]: [#packets()] streams each RTP packet as it arrives, after SRTP and retransmission
///   recovery, with the RTP stream id of its simulcast layer, its codec and its header extension map, ready for
///   [LocalForwardedTrack#write(RemoteTrack.Packet)].
///
/// {@snippet lang = java :
/// var track = transceiver.receiver().track();
/// try (var frames = track.frames()) {
///     for (var frame : frames) {      // ends when the track ends
///         decoder.decode(frame);
///     }
/// }
/// }
///
/// Each stream holds at most [EventSource#DEFAULT_CAPACITY] undelivered items; when the application reads too slowly
/// the oldest are dropped and counted in [EventStream#dropped()]. The first stream of each kind opened also gets
/// what the track received before it was opened, within that bound.
///
/// # Events
///
/// A track starts muted. [#events()] raises [RemoteTrackEvent.Unmuted] when RTP arrives while it is muted,
/// [RemoteTrackEvent.Muted] when the peer sends an RTCP BYE or a negotiation stops its sending direction, and
/// [RemoteTrackEvent.Ended] when its transceiver stops or the connection closes; every stream of the track ends
/// then.
///
/// # Threading
///
/// Every method is safe for concurrent use; each stream is meant for one reader.
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public final class RemoteTrack {
    /// A received RTP packet, as [RemoteTrack#packets()] delivers it.
    ///
    /// @param packet       a copy of the packet, which the reader owns
    /// @param rid          the RTP stream id of the simulcast layer it belongs to, or an empty optional
    /// @param arrivalNanos when it arrived, in the connection's monotonic clock
    /// @param codec        the codec its payload type was negotiated for, or an empty optional for a payload type
    ///                     the receiver did not negotiate
    /// @param extensions   the header extension ids negotiated on the receiving section, mapped to their URIs, so a
    ///                     forwarder can renumber them for another peer
    public record Packet(RtpPacket packet, Optional<String> rid, long arrivalNanos, Optional<Codec> codec,
                         Map<Integer, URI> extensions) {
        /// Creates the packet, copying the map.
        ///
        /// @param packet       the packet
        /// @param rid          the layer, or an empty optional
        /// @param arrivalNanos the arrival time
        /// @param codec        the codec, or an empty optional
        /// @param extensions   the extension map
        public Packet {
            Objects.requireNonNull(packet, "packet cannot be null");
            Objects.requireNonNull(rid, "rid cannot be null");
            Objects.requireNonNull(codec, "codec cannot be null");
            extensions = Map.copyOf(extensions);
        }
    }

    /// The track id, from the peer's `a=msid`, or random when it sent none.
    private final String id;
    /// The media kind.
    private final MediaKind kind;
    /// The delivery mode.
    private final RemoteTrackMode mode;
    /// The frames, in `JITTER_BUFFERED` mode; `null` otherwise.
    private final EventSource<EncodedFrame> frames;
    /// The audio playout outcomes, for an audio track in `JITTER_BUFFERED` mode; `null` otherwise.
    private final EventSource<AudioPlayout> playout;
    /// The packets, in `RAW_PACKETS` mode; `null` otherwise.
    private final EventSource<Packet> packets;
    /// The mute, unmute and end events.
    private final EventSource<RemoteTrackEvent> events = new EventSource<>();
    /// Guards the transitions of [#muted] and [#ended].
    private final Object stateLock = new Object();
    /// Whether the track has received nothing since it was created or last muted.
    private volatile boolean muted = true;
    /// Whether the track has ended.
    private volatile boolean ended;

    /// Creates a track.
    RemoteTrack(String id, MediaKind kind, RemoteTrackMode mode) {
        this.id = Objects.requireNonNull(id);
        this.kind = Objects.requireNonNull(kind);
        this.mode = Objects.requireNonNull(mode);
        var buffered = mode == RemoteTrackMode.JITTER_BUFFERED;
        this.frames = buffered ? new EventSource<>() : null;
        this.playout = buffered && kind == MediaKind.AUDIO ? new EventSource<>() : null;
        this.packets = buffered ? null : new EventSource<>();
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
        return muted;
    }

    /// {@return whether the track has ended: its transceiver stopped or the connection closed}
    public boolean isEnded() {
        return ended;
    }

    /// Opens a stream of the encoded frames, in decode order, ending when the track ends.
    ///
    /// For audio, the gaps [#playout()] reports are skipped.
    ///
    /// @return the stream, which the caller should close when done
    /// @throws InvalidStateException if the mode is not `JITTER_BUFFERED`
    public EventStream<EncodedFrame> frames() {
        requireMode(RemoteTrackMode.JITTER_BUFFERED);
        return frames.open();
    }

    /// Opens a stream of the playout outcomes of an audio track: a frame to decode, a gap to conceal, or silence
    /// while the peer sends no audio (DTX), one per packet time, ending when the track ends.
    ///
    /// @return the stream, which the caller should close when done
    /// @throws InvalidStateException if the track is not an audio track in `JITTER_BUFFERED` mode
    public EventStream<AudioPlayout> playout() {
        requireMode(RemoteTrackMode.JITTER_BUFFERED);
        if (playout == null) {
            throw new InvalidStateException("only an audio track has playout outcomes");
        }
        return playout.open();
    }

    /// Opens a stream of the RTP packets as they arrive, ending when the track ends.
    ///
    /// @return the stream, which the caller should close when done
    /// @throws InvalidStateException if the mode is not `RAW_PACKETS`
    public EventStream<Packet> packets() {
        requireMode(RemoteTrackMode.RAW_PACKETS);
        return packets.open();
    }

    /// {@return a stream of the track's mute, unmute and end events}
    ///
    /// The first stream opened also gets the events raised since the track was created.
    public EventStream<RemoteTrackEvent> events() {
        return events.open();
    }

    /// Fails unless the track delivers in `expected` mode.
    private void requireMode(RemoteTrackMode expected) {
        if (mode != expected) {
            throw new InvalidStateException("the track delivers in " + mode + " mode");
        }
    }

    /// Delivers an assembled frame, in `JITTER_BUFFERED` mode.
    void deliverFrame(EncodedFrame frame) {
        if (frames != null) {
            frames.publish(frame);
        }
    }

    /// Delivers an audio playout outcome; a frame outcome also reaches [#frames()].
    void deliverPlayout(AudioPlayout outcome) {
        if (playout != null) {
            playout.publish(outcome);
        }
        if (outcome instanceof AudioPlayout.Frame(var frame, var ignored)) {
            deliverFrame(frame);
        }
    }

    /// Delivers a packet, in `RAW_PACKETS` mode.
    void deliverPacket(Packet packet) {
        if (packets != null) {
            packets.publish(packet);
        }
    }

    /// Notes that RTP arrived, unmuting the track if it was muted; cheap when it is not.
    void received() {
        if (!muted) {
            return;
        }
        synchronized (stateLock) {
            if (!muted || ended) {
                return;
            }
            muted = false;
            events.publish(new RemoteTrackEvent.Unmuted());
        }
    }

    /// Mutes the track, as when the peer sends a BYE or stops sending.
    void mute() {
        synchronized (stateLock) {
            if (muted || ended) {
                return;
            }
            muted = true;
            events.publish(new RemoteTrackEvent.Muted());
        }
    }

    /// Ends the track: every stream delivers what it queued, then ends; idempotent.
    void end() {
        synchronized (stateLock) {
            if (ended) {
                return;
            }
            ended = true;
            muted = true;
            events.publish(new RemoteTrackEvent.Ended());
        }
        events.end();
        if (frames != null) {
            frames.end();
        }
        if (playout != null) {
            playout.end();
        }
        if (packets != null) {
            packets.end();
        }
    }

    /// {@return the kind and id of the track}
    @Override
    public String toString() {
        return "RemoteTrack[id=" + id + ", kind=" + kind + "]";
    }
}
