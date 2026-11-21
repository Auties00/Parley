package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;

/// A codec bound to an RTP payload type, with the RTCP feedback negotiated for it: what one `a=rtpmap` line, its
/// `a=fmtp` line and its `a=rtcp-fb` lines describe together.
///
/// @param payloadType the dynamic or static payload type, `0..127`
/// @param codec       the codec
/// @param feedback    the feedback mechanisms, unmodifiable
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
public record RtpCodecParameters(int payloadType, Codec codec, List<RtcpFeedback> feedback) {
    /// Creates codec parameters.
    ///
    /// @param payloadType the payload type
    /// @param codec       the codec
    /// @param feedback    the feedback mechanisms, copied
    /// @throws IllegalArgumentException if `payloadType` is outside `0..127`
    public RtpCodecParameters {
        if (payloadType < 0 || payloadType > 127) {
            throw new IllegalArgumentException("payload type out of range: " + payloadType);
        }
        Objects.requireNonNull(codec, "codec cannot be null");
        feedback = List.copyOf(feedback);
    }

    /// {@return codec parameters without feedback}
    ///
    /// @param payloadType the payload type, `0..127`
    /// @param codec       the codec
    public static RtpCodecParameters of(int payloadType, Codec codec) {
        return new RtpCodecParameters(payloadType, codec, List.of());
    }

    /// {@return whether the codec negotiated a feedback mechanism}
    ///
    /// @param mechanism the mechanism, such as [RtcpFeedback#PLI]
    public boolean hasFeedback(RtcpFeedback mechanism) {
        return feedback.contains(mechanism);
    }
}
