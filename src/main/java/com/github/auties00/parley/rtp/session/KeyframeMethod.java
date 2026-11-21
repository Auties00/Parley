package com.github.auties00.parley.rtp.session;

/// The RTCP message a keyframe request travels in.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
public enum KeyframeMethod {
    /// A picture loss indication, the usual request after loss.
    PLI,
    /// A full intra request, the request for a decoder refresh point when a receiver joins or switches streams.
    FIR
}
