package com.github.auties00.parley.rtp.session;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// A snapshot of the counters of one send stream, and of what the remote receiver reported about it: the data of the
/// `outbound-rtp` and `remote-inbound-rtp` statistics.
///
/// @param ssrc                     the media SSRC
/// @param rtxSsrc                  the RTX SSRC, if any
/// @param rid                      the RID, if any
/// @param packetsSent              the media packets sent, retransmissions and FEC excluded
/// @param bytesSent                the payload bytes of those packets
/// @param headerBytesSent          the header and padding bytes of those packets
/// @param retransmittedPacketsSent the packets resent in answer to NACKs, as RTX or plain
/// @param retransmittedBytesSent   the payload bytes of those packets
/// @param fecPacketsSent           the FEC packets sent
/// @param paddingPacketsSent       the padding packets sent for probing
/// @param nackCount                the NACK messages received
/// @param pliCount                 the PLI messages received
/// @param firCount                 the new FIR requests received
/// @param remote                   what the remote receiver last reported, once it reported
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record SendStreamStatistics(long ssrc, OptionalLong rtxSsrc, Optional<String> rid, long packetsSent,
                                   long bytesSent, long headerBytesSent, long retransmittedPacketsSent,
                                   long retransmittedBytesSent, long fecPacketsSent, long paddingPacketsSent,
                                   long nackCount, long pliCount, long firCount,
                                   Optional<RemoteReception> remote) {
    /// Checks the optional fields are not `null`.
    public SendStreamStatistics {
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        Objects.requireNonNull(remote, "remote cannot be null");
    }

    /// The remote receiver's last reception report about the stream, and the round-trip times measured from its
    /// reports.
    ///
    /// @param fractionLost               the fraction lost in the last report interval, in units of `1/256`
    /// @param packetsLost                the cumulative packets lost
    /// @param extendedHighestSequence    the extended highest sequence number received
    /// @param jitter                     the interarrival jitter
    /// @param roundTripTime              the last round-trip time measured, if a report carried a usable `LSR`
    /// @param totalRoundTripTime         the sum of every round-trip time measured
    /// @param roundTripTimeMeasurements  the number of round-trip times measured
    /// @param reportsReceived            the reception report blocks received about the stream
    public record RemoteReception(int fractionLost, long packetsLost, long extendedHighestSequence, Duration jitter,
                                  Optional<Duration> roundTripTime, Duration totalRoundTripTime,
                                  long roundTripTimeMeasurements, long reportsReceived) {
        /// Checks the fields are not `null`.
        public RemoteReception {
            Objects.requireNonNull(jitter, "jitter cannot be null");
            Objects.requireNonNull(roundTripTime, "roundTripTime cannot be null");
            Objects.requireNonNull(totalRoundTripTime, "totalRoundTripTime cannot be null");
        }
    }
}
