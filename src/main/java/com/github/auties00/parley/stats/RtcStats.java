package com.github.auties00.parley.stats;

import java.time.Instant;

/// One statistics object of a [StatsReport], shaped after a W3C `RTCStats` dictionary.
///
/// Each permitted record carries the members of its W3C dictionary that a transport stack can measure; a member the
/// stack cannot know (decoder output, rendered frames, audio samples) is left out, and one that is known only some
/// of the time is an `Optional`. Objects reference one another by [#id()], as the W3C dictionaries do through their
/// `*Id` members.
///
/// {@snippet lang = java :
/// StatsReport report = peerConnection.getStats();
/// report.stream(InboundRtpStreamStats.class)
///         .forEach(inbound -> System.out.println(inbound.ssrc() + " lost " + inbound.packetsLost()));
/// }
///
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public sealed interface RtcStats permits CodecStats, InboundRtpStreamStats, OutboundRtpStreamStats,
        RemoteInboundRtpStreamStats, RemoteOutboundRtpStreamStats, MediaSourceStats, AudioPlayoutStats,
        PeerConnectionStats, DataChannelStats, TransportStats, IceCandidatePairStats, IceCandidateStats,
        CertificateStats {
    /// {@return the identifier of this object, unique within its report and stable across reports of the same peer
    /// connection}
    String id();

    /// {@return when the object was measured}
    Instant timestamp();

    /// {@return the type of this object}
    RtcStatsType type();
}
