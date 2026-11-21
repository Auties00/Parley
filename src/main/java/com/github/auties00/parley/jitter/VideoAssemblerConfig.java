package com.github.auties00.parley.jitter;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.payload.DepacketizerConfig;

import java.time.Duration;
import java.util.Objects;

/// The settings of a [VideoFrameAssembler].
///
/// @param clock                     the clock that times waits and arrivals; arrivals passed to the assembler must
///                                  come from it
/// @param retransmissions           whether to ask for lost packets with NACKs (the stream negotiated `nack`)
/// @param initialRtt                the round-trip time assumed until [VideoFrameAssembler#updateRtt(Duration)] tells
///                                  the measured one, positive
/// @param minimumWait               the shortest time a frame waits for missing packets before the assembler gives
///                                  them up, at least zero
/// @param maximumWait               the longest such wait, at least `minimumWait`; the wait is three round-trip times
///                                  within these bounds
/// @param keyframeRequestInterval   the shortest time between two keyframe requests, positive
/// @param maxRetransmissionRequests the most NACKs sent for one packet, positive
/// @param maxPackets                the most packets held at once; beyond it the oldest are dropped and a keyframe is
///                                  requested; positive
/// @param depacketizer              the header extensions the assembler's depacketizer reads
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
public record VideoAssemblerConfig(MonotonicClock clock, boolean retransmissions, Duration initialRtt,
                                   Duration minimumWait, Duration maximumWait, Duration keyframeRequestInterval,
                                   int maxRetransmissionRequests, int maxPackets, DepacketizerConfig depacketizer) {
    /// Creates settings.
    ///
    /// @param clock                     the clock
    /// @param retransmissions           whether to send NACKs
    /// @param initialRtt                the assumed round-trip time
    /// @param minimumWait               the shortest wait for missing packets
    /// @param maximumWait               the longest wait for missing packets
    /// @param keyframeRequestInterval   the spacing of keyframe requests
    /// @param maxRetransmissionRequests the NACK limit per packet
    /// @param maxPackets                the packet limit
    /// @param depacketizer              the depacketizer settings
    /// @throws IllegalArgumentException if a value is outside its range
    public VideoAssemblerConfig {
        Objects.requireNonNull(clock, "clock cannot be null");
        Objects.requireNonNull(initialRtt, "initialRtt cannot be null");
        Objects.requireNonNull(minimumWait, "minimumWait cannot be null");
        Objects.requireNonNull(maximumWait, "maximumWait cannot be null");
        Objects.requireNonNull(keyframeRequestInterval, "keyframeRequestInterval cannot be null");
        Objects.requireNonNull(depacketizer, "depacketizer cannot be null");
        if (!initialRtt.isPositive() || minimumWait.isNegative() || maximumWait.compareTo(minimumWait) < 0
                || !keyframeRequestInterval.isPositive() || maxRetransmissionRequests <= 0 || maxPackets <= 0) {
            throw new IllegalArgumentException("invalid video assembler settings");
        }
    }

    /// {@return the settings of a typical call: the system clock, NACKs on, a 100 ms initial round trip, waits of
    /// 20..500 ms, keyframe requests at most every 500 ms, ten NACKs per packet, at most 2048 packets}
    public static VideoAssemblerConfig defaults() {
        return new VideoAssemblerConfig(MonotonicClock.system(), true, Duration.ofMillis(100), Duration.ofMillis(20),
                Duration.ofMillis(500), Duration.ofMillis(500), 10, 2048, DepacketizerConfig.none());
    }

    /// {@return a copy with another clock}
    ///
    /// @param newClock the clock
    public VideoAssemblerConfig withClock(MonotonicClock newClock) {
        return new VideoAssemblerConfig(newClock, retransmissions, initialRtt, minimumWait, maximumWait,
                keyframeRequestInterval, maxRetransmissionRequests, maxPackets, depacketizer);
    }

    /// {@return a copy with NACKs turned on or off}
    ///
    /// @param enabled whether to send NACKs
    public VideoAssemblerConfig withRetransmissions(boolean enabled) {
        return new VideoAssemblerConfig(clock, enabled, initialRtt, minimumWait, maximumWait,
                keyframeRequestInterval, maxRetransmissionRequests, maxPackets, depacketizer);
    }

    /// {@return a copy with another wait range for missing packets}
    ///
    /// @param minimum the shortest wait
    /// @param maximum the longest wait
    /// @throws IllegalArgumentException if the range is invalid
    public VideoAssemblerConfig withWaitRange(Duration minimum, Duration maximum) {
        return new VideoAssemblerConfig(clock, retransmissions, initialRtt, minimum, maximum,
                keyframeRequestInterval, maxRetransmissionRequests, maxPackets, depacketizer);
    }

    /// {@return a copy with other depacketizer settings}
    ///
    /// @param config the depacketizer settings
    public VideoAssemblerConfig withDepacketizer(DepacketizerConfig config) {
        return new VideoAssemblerConfig(clock, retransmissions, initialRtt, minimumWait, maximumWait,
                keyframeRequestInterval, maxRetransmissionRequests, maxPackets, config);
    }
}
