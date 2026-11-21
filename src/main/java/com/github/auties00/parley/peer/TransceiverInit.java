package com.github.auties00.parley.peer;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// The options of [PeerConnection#addTransceiver(com.github.auties00.parley.media.MediaKind, TransceiverInit)], the
/// W3C `RTCRtpTransceiverInit` with two Parley additions: how the remote track delivers media, and the bitrate this
/// side asks the peer to stay under.
///
/// {@snippet lang = java :
/// var init = TransceiverInit.builder()
///         .direction(TransceiverDirection.SENDONLY)
///         .streams(List.of("stream-1"))
///         .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("l").withScaleResolutionDownBy(4)))
///         .receiveBitrateCap(1_500_000)
///         .build();
/// }
///
/// @param direction         the initial direction
/// @param streams           the ids of the media streams the sent track belongs to
/// @param sendEncodings     the encodings to send, one per simulcast layer; empty for one default encoding
/// @param remoteTrackMode   how the transceiver's remote track delivers what it receives, or an empty optional for
///                          the connection's default
/// @param receiveBitrateCap the payload bitrate in bits per second the peer is asked not to exceed on this section,
///                          written as `b=TIAS` in every description, or an empty optional for no cap
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
/// @spec https://www.rfc-editor.org/rfc/rfc3890.html RFC 3890: A Transport Independent Bandwidth Modifier for the Session Description Protocol (SDP)
public record TransceiverInit(TransceiverDirection direction, List<String> streams, List<Encoding> sendEncodings,
                              Optional<RemoteTrackMode> remoteTrackMode, OptionalLong receiveBitrateCap) {
    /// Creates the options, copying the lists.
    ///
    /// @param direction         the initial direction
    /// @param streams           the stream ids
    /// @param sendEncodings     the encodings
    /// @param remoteTrackMode   the remote track mode, or an empty optional
    /// @param receiveBitrateCap the receive cap, or an empty optional
    /// @throws IllegalArgumentException if `direction` is `STOPPED`, an encoding lacks an RTP stream id while
    ///                                  there are several, two encodings share one, or `receiveBitrateCap` is not
    ///                                  positive
    public TransceiverInit {
        Objects.requireNonNull(direction, "direction cannot be null");
        Objects.requireNonNull(remoteTrackMode, "remoteTrackMode cannot be null");
        Objects.requireNonNull(receiveBitrateCap, "receiveBitrateCap cannot be null");
        if (direction == TransceiverDirection.STOPPED) {
            throw new IllegalArgumentException("a transceiver cannot start stopped");
        }
        if (receiveBitrateCap.isPresent() && receiveBitrateCap.getAsLong() <= 0) {
            throw new IllegalArgumentException("receiveBitrateCap must be positive");
        }
        streams = List.copyOf(streams);
        sendEncodings = List.copyOf(sendEncodings);
        if (sendEncodings.size() > 1) {
            var rids = new ArrayList<String>();
            for (var encoding : sendEncodings) {
                var rid = encoding.rid().orElseThrow(
                        () -> new IllegalArgumentException("every simulcast encoding needs an rid"));
                if (rids.contains(rid)) {
                    throw new IllegalArgumentException("duplicate rid: " + rid);
                }
                rids.add(rid);
            }
        }
    }

    /// {@return options with `direction`, no streams, one default encoding, the default remote track mode and no
    /// receive cap}
    ///
    /// @param direction the initial direction
    /// @throws IllegalArgumentException if `direction` is `STOPPED`
    public static TransceiverInit of(TransceiverDirection direction) {
        return new TransceiverInit(direction, List.of(), List.of(), Optional.empty(), OptionalLong.empty());
    }

    /// {@return a builder starting from `SENDRECV`, no streams, one default encoding, the default remote track mode
    /// and no receive cap}
    public static Builder builder() {
        return new Builder();
    }

    /// Builds [TransceiverInit]s.
    public static final class Builder {
        /// The direction.
        private TransceiverDirection direction = TransceiverDirection.SENDRECV;
        /// The stream ids.
        private List<String> streams = List.of();
        /// The encodings.
        private List<Encoding> sendEncodings = List.of();
        /// The remote track mode, or an empty optional for the connection's default.
        private Optional<RemoteTrackMode> remoteTrackMode = Optional.empty();
        /// The receive cap in bits per second, or an empty optional for none.
        private OptionalLong receiveBitrateCap = OptionalLong.empty();

        /// Creates a builder.
        private Builder() {
        }

        /// Sets the initial direction.
        ///
        /// @param direction the direction
        /// @return this builder
        public Builder direction(TransceiverDirection direction) {
            this.direction = Objects.requireNonNull(direction, "direction cannot be null");
            return this;
        }

        /// Sets the media stream ids.
        ///
        /// @param streams the stream ids
        /// @return this builder
        public Builder streams(List<String> streams) {
            this.streams = List.copyOf(streams);
            return this;
        }

        /// Sets the encodings.
        ///
        /// @param sendEncodings the encodings
        /// @return this builder
        public Builder sendEncodings(List<Encoding> sendEncodings) {
            this.sendEncodings = List.copyOf(sendEncodings);
            return this;
        }

        /// Sets how the transceiver's remote track delivers media, overriding the connection's default.
        ///
        /// @param mode the mode
        /// @return this builder
        public Builder remoteTrackMode(RemoteTrackMode mode) {
            this.remoteTrackMode = Optional.of(mode);
            return this;
        }

        /// Asks the peer to keep the payload bitrate it sends on this section under a cap, written as `b=TIAS`.
        ///
        /// @param bitsPerSecond the cap, positive
        /// @return this builder
        /// @throws IllegalArgumentException if `bitsPerSecond` is not positive
        public Builder receiveBitrateCap(long bitsPerSecond) {
            if (bitsPerSecond <= 0) {
                throw new IllegalArgumentException("receiveBitrateCap must be positive");
            }
            this.receiveBitrateCap = OptionalLong.of(bitsPerSecond);
            return this;
        }

        /// {@return the options}
        ///
        /// @throws IllegalArgumentException as the record constructor does
        public TransceiverInit build() {
            return new TransceiverInit(direction, streams, sendEncodings, remoteTrackMode, receiveBitrateCap);
        }
    }
}
