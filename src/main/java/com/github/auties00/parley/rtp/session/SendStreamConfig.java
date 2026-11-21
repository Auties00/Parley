package com.github.auties00.parley.rtp.session;

import java.util.function.Consumer;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;

/// The negotiated parameters of one outgoing RTP stream: one encoding of one m-section, so a simulcast sender has
/// one per RID.
///
/// @param mid            the MID of the m-section, written in the MID header extension when negotiated
/// @param rid            the RID of the encoding, written in the RID header extension when negotiated; empty without
///                       simulcast
/// @param ssrc           the media SSRC, an unsigned 32-bit value
/// @param rtxSsrc        the RTX SSRC (`a=ssrc-group:FID`), present exactly when `rtxPayloadType` is
/// @param payloadType    the media payload type, `0..127`
/// @param rtxPayloadType the RTX payload type whose `apt` is the media (or, with ULPFEC, the RED) payload type
/// @param clockRate      the RTP clock rate of the payload type, in hertz
/// @param extensions     the negotiated header extension ids
/// @param feedback       the negotiated feedback mechanisms; without [FeedbackMechanism#NACK] no history is kept
/// @param red            redundant audio, if negotiated and wanted; exclusive with [FecConfig.Ulpfec]
/// @param fec            forward error correction, if negotiated and wanted
/// @param historyLength  how long sent packets stay available for retransmission (`rtx-time`)
/// @param keyframeRequestListener told of every PLI and new FIR the peer sends about the stream, on the transport's
///                       RTCP reader thread; it must not block
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
/// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
public record SendStreamConfig(String mid, Optional<String> rid, long ssrc, OptionalLong rtxSsrc, int payloadType,
                               OptionalInt rtxPayloadType, int clockRate, HeaderExtensionMap extensions,
                               Set<FeedbackMechanism> feedback, Optional<RedConfig> red, Optional<FecConfig> fec,
                               Duration historyLength, Consumer<? super KeyframeRequest> keyframeRequestListener) {
    /// The history length browsers default to, the `rtx-time` RFC 4588 suggests for interactive video.
    public static final Duration DEFAULT_HISTORY_LENGTH = Duration.ofSeconds(1);

    /// Validates the fields and copies `feedback`.
    ///
    /// @throws IllegalArgumentException if a field is out of range, only one of `rtxSsrc` and `rtxPayloadType` is
    ///                                  present, RED and ULPFEC are both configured, or `historyLength` is not
    ///                                  positive
    public SendStreamConfig {
        Objects.requireNonNull(mid, "mid cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        SessionChecks.ssrc(ssrc, "ssrc");
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        rtxSsrc.ifPresent(value -> SessionChecks.ssrc(value, "rtxSsrc"));
        SessionChecks.payloadType(payloadType, "payloadType");
        Objects.requireNonNull(rtxPayloadType, "rtxPayloadType cannot be null");
        rtxPayloadType.ifPresent(value -> SessionChecks.payloadType(value, "rtxPayloadType"));
        if (rtxSsrc.isPresent() != rtxPayloadType.isPresent()) {
            throw new IllegalArgumentException("rtxSsrc and rtxPayloadType go together");
        }
        SessionChecks.clockRate(clockRate);
        Objects.requireNonNull(extensions, "extensions cannot be null");
        feedback = feedback.isEmpty() ? Set.of() : Set.copyOf(EnumSet.copyOf(feedback));
        Objects.requireNonNull(red, "red cannot be null");
        Objects.requireNonNull(fec, "fec cannot be null");
        if (red.isPresent() && fec.isPresent() && fec.get() instanceof FecConfig.Ulpfec) {
            throw new IllegalArgumentException("RED audio and ULPFEC cannot be combined");
        }
        Objects.requireNonNull(historyLength, "historyLength cannot be null");
        if (historyLength.isNegative() || historyLength.isZero()) {
            throw new IllegalArgumentException("historyLength must be positive: " + historyLength);
        }
        Objects.requireNonNull(keyframeRequestListener, "keyframeRequestListener cannot be null");
    }

    /// {@return a copy with one SSRC (media, RTX or FlexFEC) replaced, after an SSRC change}
    SendStreamConfig withReplacedSsrc(long oldSsrc, long newSsrc) {
        var media = ssrc == oldSsrc ? newSsrc : ssrc;
        var rtx = rtxSsrc.isPresent() && rtxSsrc.getAsLong() == oldSsrc ? OptionalLong.of(newSsrc) : rtxSsrc;
        var repair = fec.map(value -> value instanceof FecConfig.Flexfec flexfec && flexfec.ssrc() == oldSsrc
                ? new FecConfig.Flexfec(flexfec.payloadType(), newSsrc, flexfec.draft03(),
                flexfec.protectionPercent(), flexfec.scheme()) : value);
        return new SendStreamConfig(mid, rid, media, rtx, payloadType, rtxPayloadType, clockRate, extensions, feedback,
                red, repair, historyLength, keyframeRequestListener);
    }

    /// {@return a builder with the required fields set and the rest empty or default}
    ///
    /// @param mid         the MID of the m-section
    /// @param ssrc        the media SSRC
    /// @param payloadType the media payload type
    /// @param clockRate   the RTP clock rate in hertz
    public static Builder builder(String mid, long ssrc, int payloadType, int clockRate) {
        return new Builder(mid, ssrc, payloadType, clockRate);
    }

    /// Builds a [SendStreamConfig] field by field.
    public static final class Builder {
        private final String mid;
        private final long ssrc;
        private final int payloadType;
        private final int clockRate;
        private Optional<String> rid = Optional.empty();
        private OptionalLong rtxSsrc = OptionalLong.empty();
        private OptionalInt rtxPayloadType = OptionalInt.empty();
        private HeaderExtensionMap extensions = HeaderExtensionMap.empty();
        private Set<FeedbackMechanism> feedback = Set.of();
        private Optional<RedConfig> red = Optional.empty();
        private Optional<FecConfig> fec = Optional.empty();
        private Duration historyLength = DEFAULT_HISTORY_LENGTH;
        private Consumer<? super KeyframeRequest> keyframeRequestListener = _ -> {
        };

        private Builder(String mid, long ssrc, int payloadType, int clockRate) {
            this.mid = mid;
            this.ssrc = ssrc;
            this.payloadType = payloadType;
            this.clockRate = clockRate;
        }

        /// Sets the RID of a simulcast encoding.
        ///
        /// @param rid the RID
        /// @return this builder
        public Builder rid(String rid) {
            this.rid = Optional.of(rid);
            return this;
        }

        /// Enables RTX.
        ///
        /// @param rtxSsrc        the RTX SSRC
        /// @param rtxPayloadType the RTX payload type
        /// @return this builder
        public Builder rtx(long rtxSsrc, int rtxPayloadType) {
            this.rtxSsrc = OptionalLong.of(rtxSsrc);
            this.rtxPayloadType = OptionalInt.of(rtxPayloadType);
            return this;
        }

        /// Sets the negotiated header extensions.
        ///
        /// @param extensions the extension ids
        /// @return this builder
        public Builder extensions(HeaderExtensionMap extensions) {
            this.extensions = Objects.requireNonNull(extensions, "extensions cannot be null");
            return this;
        }

        /// Sets the negotiated feedback mechanisms.
        ///
        /// @param feedback the mechanisms
        /// @return this builder
        public Builder feedback(Set<FeedbackMechanism> feedback) {
            this.feedback = Objects.requireNonNull(feedback, "feedback cannot be null");
            return this;
        }

        /// Enables redundant audio.
        ///
        /// @param red the RED parameters
        /// @return this builder
        public Builder red(RedConfig red) {
            this.red = Optional.of(red);
            return this;
        }

        /// Enables forward error correction.
        ///
        /// @param fec the FEC parameters
        /// @return this builder
        public Builder fec(FecConfig fec) {
            this.fec = Optional.of(fec);
            return this;
        }

        /// Sets the retransmission history length.
        ///
        /// @param historyLength the history length
        /// @return this builder
        public Builder historyLength(Duration historyLength) {
            this.historyLength = Objects.requireNonNull(historyLength, "historyLength cannot be null");
            return this;
        }

        /// Sets the listener told of PLI and FIR requests from the peer; a FIR retransmitted with an unchanged
        /// command sequence number is reported once. None by default.
        ///
        /// @param listener the listener, called on the transport's RTCP reader thread; it must not block
        /// @return this builder
        public Builder keyframeRequestListener(Consumer<? super KeyframeRequest> listener) {
            this.keyframeRequestListener = Objects.requireNonNull(listener, "listener cannot be null");
            return this;
        }

        /// {@return the configuration}
        ///
        /// @throws IllegalArgumentException if the fields are inconsistent, as [SendStreamConfig] checks
        public SendStreamConfig build() {
            return new SendStreamConfig(mid, rid, ssrc, rtxSsrc, payloadType, rtxPayloadType, clockRate, extensions,
                    feedback, red, fec, historyLength, keyframeRequestListener);
        }
    }
}
