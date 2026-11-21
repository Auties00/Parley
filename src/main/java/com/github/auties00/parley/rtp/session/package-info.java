/// Provides RTP sessions: [RtpSession], the send and receive streams of one BUNDLE group over one SRTP transport, with
/// their RTCP, feedback and repair machinery.
///
/// - [RtpSendStream] turns payloads into packets, keeps the retransmission history that serves NACKs (as RTX or
///   plain resends), adds RED or FEC, and reports PLI and FIR requests.
/// - [RtpReceiveStream] unwraps RTX, decodes RED and FEC, orders packets, keeps the RFC 3550 reception statistics,
///   NACKs gaps and falls back to keyframe requests.
/// - [RtpDemuxer] routes incoming packets by MID, RID, SSRC and payload type as RFC 8843 prescribes; streams nobody
///   claims are reported as [UnsignaledStream]s.
/// - [OutgoingPacketScheduler] and [TransportFeedbackObserver] are the hooks a congestion controller plugs into: the
///   pacer, and the observer of sent packets and feedback.
/// - [RtpStreamRewriter] keeps one output stream continuous across the simulcast switches of an SFU.
///
/// Statistics are immutable snapshots ([SendStreamStatistics], [ReceiveStreamStatistics]).
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
package com.github.auties00.parley.rtp.session;
