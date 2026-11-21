package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.rtcp.CongestionControlFeedback;
import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;

import java.util.List;

/// Observes what a sender-side congestion controller needs: every packet that actually left, and every piece of
/// congestion feedback the peer returned: transport-wide feedback, RFC 8888 congestion control feedback, REMB and
/// reception reports.
///
/// # Threading
///
/// [#onPacketSent] is called on whatever thread sent the packet (the scheduler's); the feedback callbacks on the
/// transport's RTCP reader thread. Implementations synchronize themselves and must not block.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
/// @spec https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03 RTCP message for Receiver Estimated Maximum Bitrate
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public interface TransportFeedbackObserver {
    /// Called after a packet was written to the transport.
    ///
    /// @param packet the packet
    void onPacketSent(SentPacket packet);

    /// Called for every transport-wide feedback packet received.
    ///
    /// @param feedback     the feedback
    /// @param arrivalNanos when it arrived, in nanoseconds of the session's clock
    void onTransportFeedback(TransportFeedback feedback, long arrivalNanos);

    /// Called for every REMB received.
    ///
    /// @param remb         the estimate
    /// @param arrivalNanos when it arrived, in nanoseconds of the session's clock
    void onRemb(Remb remb, long arrivalNanos);

    /// Called for the reception reports about local send streams that one sender or receiver report carried.
    ///
    /// @param reports      the report blocks about local SSRCs, never empty
    /// @param rttNanos     the round-trip time measured from these reports, or `-1` when none carried a usable
    ///                     `LSR`
    /// @param arrivalNanos when the report arrived, in nanoseconds of the session's clock
    void onReceptionReports(List<ReceptionReport> reports, long rttNanos, long arrivalNanos);

    /// Called for every RFC 8888 congestion control feedback received, which names packets by SSRC and RTP sequence
    /// number instead of a transport-wide sequence number.
    ///
    /// @implSpec The default implementation ignores the feedback.
    ///
    /// @param feedback     the feedback
    /// @param arrivalNanos when it arrived, in nanoseconds of the session's clock
    /// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
    default void onCongestionControlFeedback(CongestionControlFeedback feedback, long arrivalNanos) {
    }
}
