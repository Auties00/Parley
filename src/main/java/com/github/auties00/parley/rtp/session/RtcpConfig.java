package com.github.auties00.parley.rtp.session;

import java.time.Duration;
import java.util.Objects;

/// How a session schedules and shapes its RTCP.
///
/// The regular report interval follows RFC 3550 section 6.3 (5% of the session bandwidth shared by the members, a
/// quarter of it reserved for senders, randomized by a factor between 0.5 and 1.5 and compensated by `e - 3/2`),
/// never shorter than `minimumInterval` (half of it before the first report). Under AVPF, feedback that cannot wait
/// is sent early (RFC 4585 section 3.5): immediately as a reduced-size packet when `reducedSize` is negotiated,
/// otherwise as an early compound packet at most once per regular interval.
///
/// @param avpf              whether the profile is AVPF (`RTP/AVPF`, `UDP/TLS/RTP/SAVPF`), which allows early
///                          feedback
/// @param reducedSize       whether `a=rtcp-rsize` was negotiated
/// @param extendedReports   whether a receive-only session sends receiver reference time blocks (RFC 3611) so it
///                          can measure round-trip time
/// @param minimumInterval   the shortest regular report interval
/// @param trrInterval       the AVPF `trr-int`: the shortest time between two regular reports, zero for none
/// @param sessionBandwidthBps the session bandwidth in bits per second, of which RTCP takes 5%
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
public record RtcpConfig(boolean avpf, boolean reducedSize, boolean extendedReports, Duration minimumInterval,
                         Duration trrInterval, long sessionBandwidthBps) {
    /// Validates the fields.
    ///
    /// @throws IllegalArgumentException if an interval is negative, `minimumInterval` is zero, or the bandwidth is
    ///                                  not positive
    public RtcpConfig {
        Objects.requireNonNull(minimumInterval, "minimumInterval cannot be null");
        Objects.requireNonNull(trrInterval, "trrInterval cannot be null");
        if (minimumInterval.isNegative() || minimumInterval.isZero() || trrInterval.isNegative()) {
            throw new IllegalArgumentException("minimumInterval must be positive and trrInterval non-negative");
        }
        if (sessionBandwidthBps <= 0) {
            throw new IllegalArgumentException("sessionBandwidthBps must be positive: " + sessionBandwidthBps);
        }
    }

    /// {@return the configuration of a WebRTC session: AVPF, reduced size, extended reports, one second minimum
    /// interval as browsers use for video, no `trr-int`, 2 Mb/s of session bandwidth}
    public static RtcpConfig webrtc() {
        return new RtcpConfig(true, true, true, Duration.ofSeconds(1), Duration.ZERO, 2_000_000);
    }

    /// {@return the configuration of a plain RFC 3550 session: no early feedback, compound packets only, the five
    /// second minimum interval}
    ///
    /// @param sessionBandwidthBps the session bandwidth in bits per second
    public static RtcpConfig rfc3550(long sessionBandwidthBps) {
        return new RtcpConfig(false, false, false, Duration.ofSeconds(5), Duration.ZERO, sessionBandwidthBps);
    }
}
