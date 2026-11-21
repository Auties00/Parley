package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.RtpCodecParameters;

import java.util.List;
import java.util.Objects;

/// The parameters of a receiver, the W3C `RTCRtpReceiveParameters`.
///
/// @param headerExtensions the negotiated header extensions
/// @param rtcp             the RTCP parameters
/// @param codecs           the codecs the receiver accepts
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public record RtpReceiveParameters(List<RtpHeaderExtensionParameters> headerExtensions, RtcpParameters rtcp,
                                   List<RtpCodecParameters> codecs) {
    /// Creates the parameters, copying the lists.
    ///
    /// @param headerExtensions the header extensions
    /// @param rtcp             the RTCP parameters
    /// @param codecs           the codecs
    public RtpReceiveParameters {
        headerExtensions = List.copyOf(headerExtensions);
        Objects.requireNonNull(rtcp, "rtcp cannot be null");
        codecs = List.copyOf(codecs);
    }
}
