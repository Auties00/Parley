package com.github.auties00.parley.peer;

import java.util.Objects;

/// The RTCP parameters of a sender or receiver, the W3C `RTCRtcpParameters`.
///
/// @param cname       the canonical name the connection's RTCP `SDES` packets carry
/// @param reducedSize whether reduced-size RTCP was negotiated
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
public record RtcpParameters(String cname, boolean reducedSize) {
    /// Creates the parameters.
    ///
    /// @param cname       the canonical name
    /// @param reducedSize whether reduced-size RTCP was negotiated
    public RtcpParameters {
        Objects.requireNonNull(cname, "cname cannot be null");
    }
}
