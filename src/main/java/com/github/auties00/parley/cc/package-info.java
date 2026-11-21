/// Provides send-side congestion control and pacing for RTP: [CongestionController], whose
/// [CongestionController#gcc(CongestionConfig)] runs Google Congestion Control with a congestion window, the
/// [Pacer] that releases packets at the estimated rate, [BitrateAllocator] that splits a target across senders and
/// simulcast encodings within their ceilings, and the receive-side feedback generators
/// [TransportFeedbackGenerator] (transport-wide congestion control), [CongestionControlFeedbackGenerator] (RFC 8888)
/// and [RembGenerator] (receiver estimated maximum bitrate).
///
/// # Time
///
/// Every type here reads time from the [com.github.auties00.parley.net.MonotonicClock] it is given and expresses
/// instants as `long` nanoseconds of that clock, so the estimators can be driven deterministically by a simulated
/// clock. Rates are `long` bits per second.
///
/// # Threading
///
/// The controller and the generators are safe for use from any thread; they serialize their state behind private
/// locks and never call back while holding one. The pacer and the periodic generators start their threads through
/// the [java.util.concurrent.ThreadFactory] they are given, the only threads the package starts. The controller's
/// listeners are part of its [CongestionConfig], so none can miss a target.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
/// @spec https://datatracker.ietf.org/doc/html/draft-alvestrand-rmcat-remb-03 RTCP message for Receiver Estimated Maximum Bitrate
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
package com.github.auties00.parley.cc;
