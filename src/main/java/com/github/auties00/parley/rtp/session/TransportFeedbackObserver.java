package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.rtcp.ReceptionReport;
import com.github.auties00.parley.rtp.rtcp.Remb;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;

import java.util.List;

/// Observes what a sender-side congestion controller needs: every packet that actually left, and every piece of
/// congestion feedback the peer returned.
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
    /// @param transportSequence the transport-wide sequence number stamped on it, `0..65535`, or `-1` when the
    ///                          session did not negotiate the transport-wide sequence extension
    /// @param sizeBytes         the packet's size before SRTP protection, header and padding included
    /// @param sendNanos         when it was sent, in nanoseconds of the session's clock
    /// @param priority          its priority class
    /// @param probe             whether it belonged to a probe cluster
    void onPacketSent(int transportSequence, int sizeBytes, long sendNanos, OutgoingPacketScheduler.Priority priority,
                      boolean probe);

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
}
