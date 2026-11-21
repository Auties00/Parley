package com.github.auties00.parley.transport;

import com.github.auties00.srtp.SrtpCryptoSuite;

import java.util.Objects;
import java.util.Optional;

/// A snapshot of the counters of an [RtpTransport].
///
/// Byte counts are of the protected packets on the wire. A packet dropped on receipt is counted in exactly one of the
/// failure counters and in none of the received ones.
///
/// @param suite                  the SRTP crypto suite once keyed, absent before
/// @param rtpPacketsSent         the RTP packets sent
/// @param rtpBytesSent           the bytes of RTP packets sent
/// @param rtcpPacketsSent        the compound RTCP packets sent
/// @param rtcpBytesSent          the bytes of RTCP packets sent
/// @param rtpPacketsReceived     the RTP packets received and authenticated
/// @param rtpBytesReceived       the bytes of RTP packets received and authenticated
/// @param rtcpPacketsReceived    the RTCP packets received and authenticated
/// @param rtcpBytesReceived      the bytes of RTCP packets received and authenticated
/// @param authenticationFailures the packets that failed SRTP or SRTCP authentication
/// @param replayedPackets        the packets rejected as replays or as older than the replay window
/// @param malformedPackets       the packets too short or malformed to process
/// @param unkeyedPackets         the packets received before the transport was keyed
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record RtpTransportStatistics(Optional<SrtpCryptoSuite> suite, long rtpPacketsSent, long rtpBytesSent,
                                     long rtcpPacketsSent, long rtcpBytesSent, long rtpPacketsReceived,
                                     long rtpBytesReceived, long rtcpPacketsReceived, long rtcpBytesReceived,
                                     long authenticationFailures, long replayedPackets, long malformedPackets,
                                     long unkeyedPackets) {
    /// Creates a snapshot.
    ///
    /// @param suite                  the suite
    /// @param rtpPacketsSent         the RTP packets sent
    /// @param rtpBytesSent           the RTP bytes sent
    /// @param rtcpPacketsSent        the RTCP packets sent
    /// @param rtcpBytesSent          the RTCP bytes sent
    /// @param rtpPacketsReceived     the RTP packets received
    /// @param rtpBytesReceived       the RTP bytes received
    /// @param rtcpPacketsReceived    the RTCP packets received
    /// @param rtcpBytesReceived      the RTCP bytes received
    /// @param authenticationFailures the authentication failures
    /// @param replayedPackets        the replays
    /// @param malformedPackets       the malformed packets
    /// @param unkeyedPackets         the packets received before keying
    public RtpTransportStatistics {
        Objects.requireNonNull(suite, "suite cannot be null");
    }
}
