package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// A pair of an [RtpSender] and an [RtpReceiver] sharing one media section, the W3C `RTCRtpTransceiver`.
///
/// The transceiver is bound to a media section by its identification tag once a description that contains it is
/// applied; until then [#mid()] is empty. Its [direction][#direction()] is the application's preference, its
/// [current direction][#currentDirection()] what the last answer negotiated.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public final class RtpTransceiver {
    /// The connection the transceiver belongs to.
    private final PeerConnection connection;
    /// The media kind.
    private final MediaKind kind;
    /// The sender.
    private final RtpSender sender;
    /// The receiver.
    private final RtpReceiver receiver;

    // The fields below are guarded by the connection's lock.

    /// The preferred direction.
    TransceiverDirection direction;
    /// The negotiated direction, or `null` before the first answer.
    TransceiverDirection currentDirection;
    /// The identification tag of the bound media section, or `null`.
    String mid;
    /// The index of the bound media section, or `-1`.
    int mLineIndex = -1;
    /// Whether `stop()` was called and the section is not yet rejected.
    boolean stopping;
    /// Whether the transceiver stopped for good.
    boolean stopped;
    /// Whether the transceiver was created by a remote offer rather than by the application.
    boolean createdByRemote;
    /// Whether `addTrack` reused or created this transceiver, which keeps a remotely created one across a rollback.
    boolean usedByAddTrack;
    /// Whether the receiver's track was announced to the application and not withdrawn since.
    boolean receiving;
    /// The codec preferences, empty for the connection's default.
    List<Codec> codecPreferences = List.of();
    /// The last negotiated media section, or `null`.
    Negotiated.Media negotiated;

    /// Creates a transceiver.
    RtpTransceiver(PeerConnection connection, MediaKind kind, TransceiverDirection direction, RtpSender sender,
                   RtpReceiver receiver) {
        this.connection = connection;
        this.kind = kind;
        this.direction = direction;
        this.sender = sender;
        this.receiver = receiver;
    }

    /// {@return the media kind}
    public MediaKind kind() {
        return kind;
    }

    /// {@return the sender}
    public RtpSender sender() {
        return sender;
    }

    /// {@return the receiver}
    public RtpReceiver receiver() {
        return receiver;
    }

    /// {@return the identification tag of the media section the transceiver is bound to, or an empty optional before
    /// a description containing it is applied}
    public Optional<String> mid() {
        synchronized (connection.lock()) {
            return Optional.ofNullable(mid);
        }
    }

    /// {@return the preferred direction; `STOPPED` once [#stop()] was called}
    public TransceiverDirection direction() {
        synchronized (connection.lock()) {
            return stopping || stopped ? TransceiverDirection.STOPPED : direction;
        }
    }

    /// Changes the preferred direction; the change takes effect at the next negotiation, which it may make needed.
    ///
    /// @param newDirection the direction
    /// @throws IllegalArgumentException if `newDirection` is `STOPPED`; use [#stop()]
    /// @throws InvalidStateException    if the connection is closed or the transceiver is stopping or stopped
    public void setDirection(TransceiverDirection newDirection) {
        Objects.requireNonNull(newDirection, "newDirection cannot be null");
        if (newDirection == TransceiverDirection.STOPPED) {
            throw new IllegalArgumentException("use stop() to stop a transceiver");
        }
        synchronized (connection.lock()) {
            connection.checkOpen();
            if (stopping || stopped) {
                throw new InvalidStateException("the transceiver is stopped");
            }
            if (direction != newDirection) {
                direction = newDirection;
                connection.updateNegotiationNeeded();
            }
        }
    }

    /// {@return the direction the last answer negotiated, `STOPPED` once stopped, or an empty optional before the
    /// first answer}
    public Optional<TransceiverDirection> currentDirection() {
        synchronized (connection.lock()) {
            return stopped ? Optional.of(TransceiverDirection.STOPPED) : Optional.ofNullable(currentDirection);
        }
    }

    /// Stops the transceiver for good: the sender stops sending, the receiver's track ends, and the next negotiation
    /// rejects the media section. Idempotent.
    ///
    /// @throws InvalidStateException if the connection is closed
    public void stop() {
        synchronized (connection.lock()) {
            connection.checkOpen();
            if (stopping || stopped) {
                return;
            }
            stopping = true;
            sender.stopSending();
            receiver.track().end();
            if (mid == null) {
                stopped = true;
            }
            connection.updateNegotiationNeeded();
        }
    }

    /// {@return the codec preferences, empty when the connection's defaults apply}
    public List<Codec> codecPreferences() {
        synchronized (connection.lock()) {
            return codecPreferences;
        }
    }

    /// Sets the codecs the next negotiation offers or accepts for this transceiver, in preference order, the W3C
    /// `setCodecPreferences`.
    ///
    /// Each codec must be one of [RtpSender#getCapabilities(MediaKind)] or [RtpReceiver#getCapabilities(MediaKind)]
    /// for the transceiver's kind; retransmission, redundancy and FEC codecs may be left out to disable them. An empty
    /// list restores the defaults.
    ///
    /// @param codecs the codecs
    /// @throws InvalidModificationException if a codec is not a capability of the transceiver's kind, or only
    ///                                      retransmission, redundancy or FEC codecs are given
    public void setCodecPreferences(List<Codec> codecs) {
        var copy = List.copyOf(codecs);
        synchronized (connection.lock()) {
            var capabilities = connection.codecCapabilities(kind);
            var result = new ArrayList<Codec>();
            for (var codec : copy) {
                if (capabilities.stream().noneMatch(capability -> CodecCatalog.matches(capability, codec))) {
                    throw new InvalidModificationException("not a " + kind + " capability: " + codec.mimeType());
                }
                if (!result.contains(codec)) {
                    result.add(codec);
                }
            }
            if (!result.isEmpty() && result.stream().allMatch(CodecCatalog::isAuxiliary)) {
                throw new InvalidModificationException("the preferences hold no media codec");
            }
            codecPreferences = List.copyOf(result);
        }
    }

    /// {@return the connection the transceiver belongs to}
    PeerConnection connection() {
        return connection;
    }

    /// {@return the kind, tag and direction of the transceiver}
    @Override
    public String toString() {
        return "RtpTransceiver[kind=" + kind + ", mid=" + mid + ", direction=" + direction + "]";
    }
}
