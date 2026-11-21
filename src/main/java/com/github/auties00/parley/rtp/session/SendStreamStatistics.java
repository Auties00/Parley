package com.github.auties00.parley.rtp.session;

import java.util.OptionalInt;
import java.util.OptionalDouble;
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
/// @param framesSent               the frames sent: one per `RtpSendStream.send` call, one per forwarded marker bit
/// @param keyFramesSent            those of them that were key frames
/// @param frameWidth               the width of the last frame whose size was given, in pixels
/// @param frameHeight              the height of the last frame whose size was given, in pixels
/// @param framesPerSecond          the frames sent in the last second, once the stream has sent for a second
/// @param totalPacketSendDelay     the sum of the time each media packet waited in the scheduler (the pacer queue)
///                                 between being scheduled and leaving
/// @param droppedPackets           the packets dropped unsent: after the stream was removed, or forwarded from a
///                                 source not switched to yet
/// @param remote                   what the remote receiver last reported, once it reported
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record SendStreamStatistics(long ssrc, OptionalLong rtxSsrc, Optional<String> rid, long packetsSent,
                                   long bytesSent, long headerBytesSent, long retransmittedPacketsSent,
                                   long retransmittedBytesSent, long fecPacketsSent, long paddingPacketsSent,
                                   long nackCount, long pliCount, long firCount, long framesSent,
                                   long keyFramesSent, OptionalInt frameWidth, OptionalInt frameHeight,
                                   OptionalDouble framesPerSecond, Duration totalPacketSendDelay,
                                   long droppedPackets, Optional<RemoteReception> remote) {
    /// Checks the optional fields are not `null`.
    public SendStreamStatistics {
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        Objects.requireNonNull(remote, "remote cannot be null");
        Objects.requireNonNull(frameWidth, "frameWidth cannot be null");
        Objects.requireNonNull(frameHeight, "frameHeight cannot be null");
        Objects.requireNonNull(framesPerSecond, "framesPerSecond cannot be null");
        Objects.requireNonNull(totalPacketSendDelay, "totalPacketSendDelay cannot be null");
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
