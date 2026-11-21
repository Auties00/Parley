package com.github.auties00.parley.rtp.session;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// A snapshot of the counters of one receive stream, and of what the remote sender reported: the data of the
/// `inbound-rtp` and `remote-outbound-rtp` statistics.
///
/// @param ssrc                         the media SSRC, once known
/// @param rtxSsrc                      the RTX SSRC, once known
/// @param mid                          the MID, if any
/// @param rid                          the RID, if any
/// @param packetsReceived              the media packets received from the network, duplicates included
/// @param bytesReceived                the payload bytes of those packets
/// @param headerBytesReceived          the header and padding bytes of those packets
/// @param packetsLost                  the cumulative packets lost (expected minus received, RFC 3550 A.3)
/// @param fractionLost                 the fraction lost in the last reported interval, in units of `1/256`
/// @param jitter                       the interarrival jitter (RFC 3550 A.8)
/// @param packetsDuplicated            the packets received more than once and dropped
/// @param packetsDiscarded             the packets dropped as too old to place
/// @param retransmittedPacketsReceived the packets that arrived as retransmissions (RTX or plain)
/// @param retransmittedBytesReceived   the payload bytes of those packets
/// @param fecPacketsReceived           the FEC packets received
/// @param packetsRecovered             the media packets rebuilt from FEC or RED redundancy
/// @param nackCount                    the NACK messages sent
/// @param pliCount                     the PLI messages sent
/// @param firCount                     the FIR messages sent
/// @param lastPacketReceivedNanos      when the last packet arrived, in nanoseconds of the session's clock
/// @param remoteSender                 what the remote sender last reported, once it sent a sender report
/// @param roundTripTime                the round-trip time measured as a receiver (RFC 3611 `DLRR`), if any
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record ReceiveStreamStatistics(OptionalLong ssrc, OptionalLong rtxSsrc, Optional<String> mid,
                                      Optional<String> rid, long packetsReceived, long bytesReceived,
                                      long headerBytesReceived, long packetsLost, int fractionLost, Duration jitter,
                                      long packetsDuplicated, long packetsDiscarded,
                                      long retransmittedPacketsReceived, long retransmittedBytesReceived,
                                      long fecPacketsReceived, long packetsRecovered, long nackCount, long pliCount,
                                      long firCount, OptionalLong lastPacketReceivedNanos,
                                      Optional<RemoteSender> remoteSender, Optional<Duration> roundTripTime) {
    /// Checks the fields are not `null`.
    public ReceiveStreamStatistics {
        Objects.requireNonNull(ssrc, "ssrc cannot be null");
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        Objects.requireNonNull(mid, "mid cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        Objects.requireNonNull(jitter, "jitter cannot be null");
        Objects.requireNonNull(lastPacketReceivedNanos, "lastPacketReceivedNanos cannot be null");
        Objects.requireNonNull(remoteSender, "remoteSender cannot be null");
        Objects.requireNonNull(roundTripTime, "roundTripTime cannot be null");
    }

    /// The remote sender's last sender report.
    ///
    /// @param packetsSent     the packets it reported sending, modulo `2^32`
    /// @param bytesSent       the payload bytes it reported sending, modulo `2^32`
    /// @param remoteTimestamp its wall clock at the report
    /// @param reportsReceived the sender reports received
    public record RemoteSender(long packetsSent, long bytesSent, Instant remoteTimestamp, long reportsReceived) {
        /// Checks `remoteTimestamp` is not `null`.
        public RemoteSender {
            Objects.requireNonNull(remoteTimestamp, "remoteTimestamp cannot be null");
        }
    }
}
