package com.github.auties00.parley.peer;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// The options of [PeerConnection#addTransceiver(com.github.auties00.parley.media.MediaKind, TransceiverInit)], the
/// W3C `RTCRtpTransceiverInit`.
///
/// {@snippet lang = java :
/// var init = TransceiverInit.builder()
///         .direction(TransceiverDirection.SENDONLY)
///         .streams(List.of("stream-1"))
///         .sendEncodings(List.of(Encoding.rid("h"), Encoding.rid("l").scaleDown(4)))
///         .build();
/// }
///
/// @param direction     the initial direction
/// @param streams       the ids of the media streams the sent track belongs to
/// @param sendEncodings the encodings to send, one per simulcast layer; empty for one default encoding
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
public record TransceiverInit(TransceiverDirection direction, List<String> streams, List<Encoding> sendEncodings) {
    /// Creates the options, copying the lists.
    ///
    /// @param direction     the initial direction
    /// @param streams       the stream ids
    /// @param sendEncodings the encodings
    /// @throws IllegalArgumentException if `direction` is `STOPPED`, an encoding lacks an RTP stream id while
    ///                                  there are several, or two encodings share one
    public TransceiverInit {
        Objects.requireNonNull(direction, "direction cannot be null");
        if (direction == TransceiverDirection.STOPPED) {
            throw new IllegalArgumentException("a transceiver cannot start stopped");
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

    /// {@return options with `direction`, no streams and one default encoding}
    ///
    /// @param direction the initial direction
    public static TransceiverInit of(TransceiverDirection direction) {
        return new TransceiverInit(direction, List.of(), List.of());
    }

    /// {@return a builder starting from `SENDRECV`, no streams and one default encoding}
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

        /// {@return the options}
        ///
        /// @throws IllegalArgumentException as the record constructor does
        public TransceiverInit build() {
            return new TransceiverInit(direction, streams, sendEncodings);
        }
    }
}
