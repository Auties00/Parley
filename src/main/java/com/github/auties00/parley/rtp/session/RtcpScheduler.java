package com.github.auties00.parley.rtp.session;

import java.util.random.RandomGenerator;

/// The RTCP transmission timing of RFC 3550 section 6.3 and appendix A.7, with the AVPF early feedback rules of
/// RFC 4585 section 3.5.
///
/// Not thread-safe: the session serializes access.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
final class RtcpScheduler {
    /// The fraction of the session bandwidth RTCP uses.
    static final double RTCP_FRACTION = 0.05;
    /// The share of the RTCP bandwidth reserved for senders.
    static final double SENDER_FRACTION = 0.25;
    /// The compensation for the timer reconsideration algorithm converging below the intended average.
    static final double COMPENSATION = Math.E - 1.5;
    /// The UDP and IPv4 header bytes counted in the average RTCP size.
    static final int LOWER_LAYER_OVERHEAD = 28;

    private final RtcpConfig config;
    private final RandomGenerator random;
    private double averageSize;
    private boolean initial = true;
    private long lastRegularNanos = Long.MIN_VALUE;
    private long nextRegularNanos;
    private boolean allowEarly = true;

    RtcpScheduler(RtcpConfig config, RandomGenerator random, long nowNanos, int initialAverageSize) {
        this.config = config;
        this.random = random;
        this.averageSize = initialAverageSize + LOWER_LAYER_OVERHEAD;
        this.nextRegularNanos = nowNanos + interval(2, 0, false);
    }

    /// Computes the deterministic interval `Td` of RFC 3550 A.7, in seconds.
    static double deterministicInterval(int members, int senders, double rtcpBandwidthBytes, boolean weSent,
                                        double averageSize, double minimumSeconds) {
        double n = members;
        var c = averageSize / rtcpBandwidthBytes;
        if (senders > 0 && senders <= members * SENDER_FRACTION) {
            if (weSent) {
                c = averageSize / (SENDER_FRACTION * rtcpBandwidthBytes);
                n = senders;
            } else {
                c = averageSize / ((1 - SENDER_FRACTION) * rtcpBandwidthBytes);
                n = members - senders;
            }
        }
        return Math.max(minimumSeconds, n * c);
    }

    /// {@return the randomized interval in nanoseconds for the current membership}
    long interval(int members, int senders, boolean weSent) {
        var minimum = config.minimumInterval().toNanos() / 1e9;
        if (initial) {
            minimum /= 2;
        }
        var rtcpBandwidth = config.sessionBandwidthBps() * RTCP_FRACTION / 8;
        var td = deterministicInterval(Math.max(members, 1), senders, rtcpBandwidth, weSent, averageSize, minimum);
        var t = td * (random.nextDouble() + 0.5) / COMPENSATION;
        return (long) (t * 1e9);
    }

    /// {@return the randomized interval in nanoseconds before a BYE may leave, under the BYE reconsideration of RFC
    /// 3550 section 6.3.7: computed as for a first report with `byeMembers` members (the leaving participant plus
    /// the BYEs received since it decided to leave), none of them senders, and the BYE's own size as the average}
    ///
    /// @param byeMembers the members to count, at least one
    /// @param byeSize    the size of the compound BYE packet, in bytes
    long byeInterval(int byeMembers, int byeSize) {
        var minimum = config.minimumInterval().toNanos() / 1e9 / 2;
        var rtcpBandwidth = config.sessionBandwidthBps() * RTCP_FRACTION / 8;
        var td = deterministicInterval(Math.max(byeMembers, 1), 0, rtcpBandwidth, false,
                byeSize + LOWER_LAYER_OVERHEAD, minimum);
        var t = td * (random.nextDouble() + 0.5) / COMPENSATION;
        return (long) (t * 1e9);
    }

    /// {@return whether a regular report is due}
    boolean regularDue(long nowNanos) {
        return nowNanos >= nextRegularNanos;
    }

    long nextRegularNanos() {
        return nextRegularNanos;
    }

    /// {@return whether the `trr-int` allows a regular report now; a suppressed report is rescheduled the same way}
    boolean trrAllows(long nowNanos) {
        var trr = config.trrInterval().toNanos();
        return trr == 0 || lastRegularNanos == Long.MIN_VALUE || nowNanos - lastRegularNanos >= trr;
    }

    /// Records a regular report sent (or suppressed by `trr-int`) and schedules the next one.
    void onRegular(long nowNanos, int sizeBytes, boolean sent, int members, int senders, boolean weSent) {
        if (sent) {
            updateAverage(sizeBytes);
            lastRegularNanos = nowNanos;
        }
        initial = false;
        allowEarly = true;
        nextRegularNanos = nowNanos + interval(members, senders, weSent);
    }

    /// Decides whether feedback may go out now as an early compound packet (RFC 4585 section 3.5.2).
    ///
    /// @return `true` when an early packet may be sent now; the next regular report is then pushed back so the
    ///         average rate is kept; `false` when the feedback must wait for the next regular report
    boolean tryEarly(long nowNanos, int members, int senders, boolean weSent) {
        if (!config.avpf() || !allowEarly) {
            return false;
        }
        allowEarly = false;
        if (lastRegularNanos != Long.MIN_VALUE) {
            var t = interval(members, senders, weSent);
            nextRegularNanos = Math.max(nextRegularNanos, lastRegularNanos + 2 * t);
        }
        return true;
    }

    /// Records an early or reduced-size packet's size in the average.
    void onFeedbackSent(int sizeBytes) {
        updateAverage(sizeBytes);
    }

    private void updateAverage(int sizeBytes) {
        averageSize = (sizeBytes + LOWER_LAYER_OVERHEAD) / 16.0 + averageSize * 15.0 / 16.0;
    }

    double averageSize() {
        return averageSize;
    }
}
