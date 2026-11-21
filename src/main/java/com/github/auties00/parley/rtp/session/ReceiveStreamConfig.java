package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;

/// The negotiated parameters of one incoming RTP stream: one encoding of one m-section, so an SFU receiving
/// simulcast creates one per RID.
///
/// A stream is found by the session's demultiplexer through its MID and RID, its SSRCs, or its payload types (see
/// [RtpDemuxer]); a stream signaled without SSRC learns it from the first packet routed to it.
///
/// @param mid             the MID of the m-section, if any
/// @param rid             the RID of the encoding, if any
/// @param ssrc            the media SSRC, if signaled
/// @param rtxSsrc         the RTX SSRC, if signaled; otherwise learned from RTX packets that carry the repaired RID
///                        or route by MID
/// @param payloadTypes    the media payload types and their clock rates in hertz, at least one
/// @param rtxPayloadTypes each RTX payload type and the payload type it repairs (`apt`)
/// @param redPayloadType  the RED payload type, for RED audio or ULPFEC video
/// @param fec             forward error correction, if negotiated; its protection rate is ignored
/// @param extensions      the negotiated header extension ids
/// @param feedback        the negotiated feedback mechanisms: [FeedbackMechanism#NACK] enables NACK generation,
///                        [FeedbackMechanism#PLI] or [FeedbackMechanism#FIR] the keyframe fallback
/// @param reorderDelay    how long a packet after a gap is held for the missing ones before being delivered out of
///                        a gap; zero delivers every packet as it arrives (recovered packets then arrive late)
/// @param nackMaxRetries  how many NACKs are sent for one missing packet before giving up, `1..255`
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
public record ReceiveStreamConfig(Optional<String> mid, Optional<String> rid, OptionalLong ssrc,
                                  OptionalLong rtxSsrc, Map<Integer, Integer> payloadTypes,
                                  Map<Integer, Integer> rtxPayloadTypes, OptionalInt redPayloadType,
                                  Optional<FecConfig> fec, HeaderExtensionMap extensions,
                                  Set<FeedbackMechanism> feedback, Duration reorderDelay, int nackMaxRetries) {
    /// The NACK retries browsers allow per missing packet.
    public static final int DEFAULT_NACK_MAX_RETRIES = 10;

    /// Validates the fields and copies the collections.
    ///
    /// @throws IllegalArgumentException if a field is out of range, no payload type is given, or `reorderDelay` is
    ///                                  negative
    public ReceiveStreamConfig {
        Objects.requireNonNull(mid, "mid cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        Objects.requireNonNull(ssrc, "ssrc cannot be null");
        ssrc.ifPresent(value -> SessionChecks.ssrc(value, "ssrc"));
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        rtxSsrc.ifPresent(value -> SessionChecks.ssrc(value, "rtxSsrc"));
        payloadTypes = Map.copyOf(payloadTypes);
        if (payloadTypes.isEmpty()) {
            throw new IllegalArgumentException("at least one payload type is required");
        }
        payloadTypes.forEach((payloadType, clockRate) -> {
            SessionChecks.payloadType(payloadType, "payloadType");
            SessionChecks.clockRate(clockRate);
        });
        rtxPayloadTypes = Map.copyOf(rtxPayloadTypes);
        rtxPayloadTypes.forEach((rtx, apt) -> {
            SessionChecks.payloadType(rtx, "rtxPayloadType");
            SessionChecks.payloadType(apt, "apt");
        });
        Objects.requireNonNull(redPayloadType, "redPayloadType cannot be null");
        redPayloadType.ifPresent(value -> SessionChecks.payloadType(value, "redPayloadType"));
        Objects.requireNonNull(fec, "fec cannot be null");
        Objects.requireNonNull(extensions, "extensions cannot be null");
        feedback = feedback.isEmpty() ? Set.of() : Set.copyOf(EnumSet.copyOf(feedback));
        Objects.requireNonNull(reorderDelay, "reorderDelay cannot be null");
        if (reorderDelay.isNegative()) {
            throw new IllegalArgumentException("reorderDelay cannot be negative: " + reorderDelay);
        }
        if (nackMaxRetries < 1 || nackMaxRetries > 255) {
            throw new IllegalArgumentException("nackMaxRetries must be in 1..255: " + nackMaxRetries);
        }
    }

    /// {@return a builder for a stream with one media payload type}
    ///
    /// @param payloadType the media payload type
    /// @param clockRate   its clock rate in hertz
    public static Builder builder(int payloadType, int clockRate) {
        return new Builder(payloadType, clockRate);
    }

    /// {@return the clock rate of the first media payload type, the one reception statistics use when the packet's
    /// own payload type is unknown}
    int defaultClockRate() {
        return payloadTypes.values().iterator().next();
    }

    /// Builds a [ReceiveStreamConfig] field by field.
    public static final class Builder {
        private Optional<String> mid = Optional.empty();
        private Optional<String> rid = Optional.empty();
        private OptionalLong ssrc = OptionalLong.empty();
        private OptionalLong rtxSsrc = OptionalLong.empty();
        private final Map<Integer, Integer> payloadTypes = new java.util.LinkedHashMap<>();
        private final Map<Integer, Integer> rtxPayloadTypes = new java.util.LinkedHashMap<>();
        private OptionalInt redPayloadType = OptionalInt.empty();
        private Optional<FecConfig> fec = Optional.empty();
        private HeaderExtensionMap extensions = HeaderExtensionMap.empty();
        private Set<FeedbackMechanism> feedback = Set.of();
        private Duration reorderDelay = Duration.ZERO;
        private int nackMaxRetries = DEFAULT_NACK_MAX_RETRIES;

        private Builder(int payloadType, int clockRate) {
            payloadTypes.put(payloadType, clockRate);
        }

        /// Sets the MID.
        ///
        /// @param mid the MID
        /// @return this builder
        public Builder mid(String mid) {
            this.mid = Optional.of(mid);
            return this;
        }

        /// Sets the RID.
        ///
        /// @param rid the RID
        /// @return this builder
        public Builder rid(String rid) {
            this.rid = Optional.of(rid);
            return this;
        }

        /// Sets the signaled media SSRC.
        ///
        /// @param ssrc the SSRC
        /// @return this builder
        public Builder ssrc(long ssrc) {
            this.ssrc = OptionalLong.of(ssrc);
            return this;
        }

        /// Sets the signaled RTX SSRC.
        ///
        /// @param rtxSsrc the RTX SSRC
        /// @return this builder
        public Builder rtxSsrc(long rtxSsrc) {
            this.rtxSsrc = OptionalLong.of(rtxSsrc);
            return this;
        }

        /// Adds a media payload type.
        ///
        /// @param payloadType the payload type
        /// @param clockRate   its clock rate in hertz
        /// @return this builder
        public Builder payloadType(int payloadType, int clockRate) {
            payloadTypes.put(payloadType, clockRate);
            return this;
        }

        /// Adds an RTX payload type.
        ///
        /// @param rtxPayloadType the RTX payload type
        /// @param apt            the payload type it repairs
        /// @return this builder
        public Builder rtxPayloadType(int rtxPayloadType, int apt) {
            rtxPayloadTypes.put(rtxPayloadType, apt);
            return this;
        }

        /// Sets the RED payload type.
        ///
        /// @param redPayloadType the payload type
        /// @return this builder
        public Builder redPayloadType(int redPayloadType) {
            this.redPayloadType = OptionalInt.of(redPayloadType);
            return this;
        }

        /// Sets the forward error correction.
        ///
        /// @param fec the FEC parameters
        /// @return this builder
        public Builder fec(FecConfig fec) {
            this.fec = Optional.of(fec);
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

        /// Sets the reorder delay.
        ///
        /// @param reorderDelay the delay
        /// @return this builder
        public Builder reorderDelay(Duration reorderDelay) {
            this.reorderDelay = Objects.requireNonNull(reorderDelay, "reorderDelay cannot be null");
            return this;
        }

        /// Sets the NACK retries per missing packet.
        ///
        /// @param nackMaxRetries the retries
        /// @return this builder
        public Builder nackMaxRetries(int nackMaxRetries) {
            this.nackMaxRetries = nackMaxRetries;
            return this;
        }

        /// {@return the configuration}
        ///
        /// @throws IllegalArgumentException if a field is out of range, as [ReceiveStreamConfig] checks
        public ReceiveStreamConfig build() {
            return new ReceiveStreamConfig(mid, rid, ssrc, rtxSsrc, payloadTypes, rtxPayloadTypes, redPayloadType,
                    fec, extensions, feedback, reorderDelay, nackMaxRetries);
        }
    }
}
