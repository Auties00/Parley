package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.RtpCodecParameters;

import java.util.List;
import java.util.Objects;

/// The parameters of a sender, the W3C `RTCRtpSendParameters`, which [RtpSender#getParameters()] returns and
/// [RtpSender#setParameters(RtpSendParameters)] applies.
///
/// Only the encodings can be changed, and only in their caps, activity, priorities and scalability modes: a call
/// with another transaction id, another encoding count or other RTP stream ids fails.
///
/// @param transactionId    the token that ties a `setParameters` call to the `getParameters` call it edits
/// @param encodings        the encodings, one per simulcast layer
/// @param headerExtensions the negotiated header extensions, read-only
/// @param rtcp             the RTCP parameters, read-only
/// @param codecs           the negotiated codecs in preference order, read-only
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public record RtpSendParameters(String transactionId, List<Encoding> encodings,
                                List<RtpHeaderExtensionParameters> headerExtensions, RtcpParameters rtcp,
                                List<RtpCodecParameters> codecs) {
    /// Creates the parameters, copying the lists.
    ///
    /// @param transactionId    the transaction id
    /// @param encodings        the encodings
    /// @param headerExtensions the header extensions
    /// @param rtcp             the RTCP parameters
    /// @param codecs           the codecs
    public RtpSendParameters {
        Objects.requireNonNull(transactionId, "transactionId cannot be null");
        encodings = List.copyOf(encodings);
        headerExtensions = List.copyOf(headerExtensions);
        Objects.requireNonNull(rtcp, "rtcp cannot be null");
        codecs = List.copyOf(codecs);
    }

    /// {@return a copy with other encodings}
    ///
    /// @param newEncodings the encodings
    public RtpSendParameters withEncodings(List<Encoding> newEncodings) {
        return new RtpSendParameters(transactionId, newEncodings, headerExtensions, rtcp, codecs);
    }
}
