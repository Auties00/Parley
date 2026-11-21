/// Provides the statistics of a peer connection as typed records: [RtcStats], a sealed hierarchy with one record per
/// W3C statistics type, and [StatsReport], the immutable snapshot `PeerConnection.getStats()` returns.
///
/// The records follow the W3C dictionaries member for member where Parley can measure the value; Parley neither
/// encodes nor decodes media, so codec-internal members (decoded frames, QP, audio samples) are absent, and the frame
/// counters count encoded frames the application wrote or Parley assembled. Times are [java.time.Instant]s, durations
/// in seconds as `double`, counts as `long`, and a member that is not always known is an `Optional`.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
package com.github.auties00.parley.stats;
