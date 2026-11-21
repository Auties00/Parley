package com.github.auties00.parley.rtp.session;

/// An RTCP feedback mechanism negotiated for a stream (`a=rtcp-fb`), which decides what the stream sends and serves.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
public enum FeedbackMechanism {
    /// Generic NACK (`nack`): the receiver asks for retransmissions, the sender serves them from its history.
    NACK,
    /// Picture loss indication (`nack pli`).
    PLI,
    /// Full intra request (`ccm fir`).
    FIR,
    /// Receiver estimated maximum bitrate (`goog-remb`).
    REMB,
    /// Transport-wide congestion control feedback (`transport-cc`).
    TRANSPORT_CC
}
