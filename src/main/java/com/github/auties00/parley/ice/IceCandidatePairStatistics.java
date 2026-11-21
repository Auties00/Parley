package com.github.auties00.parley.ice;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// A snapshot of the counters of one candidate pair, the inputs of the webrtc-stats `candidate-pair` dictionary.
///
/// Packet and byte counts cover application data only (what [IceAgent#send(java.nio.ByteBuffer)] sent and what
/// reached the receiver), not STUN traffic. Times are [com.github.auties00.parley.net.MonotonicClock] readings.
///
/// @param pair                   the pair
/// @param state                  the checklist state
/// @param nominated              whether the pair is nominated
/// @param selected               whether the transport sends on the pair
/// @param packetsSent            the application packets sent on the pair
/// @param packetsReceived        the application packets received on the pair
/// @param bytesSent              the application bytes sent on the pair
/// @param bytesReceived          the application bytes received on the pair
/// @param currentRoundTripTime   the round-trip time of the last answered check, or an empty optional before one
/// @param totalRoundTripTime     the sum of the round-trip times of every answered check
/// @param requestsSent           the connectivity checks sent, retransmissions included, consent checks excluded
/// @param requestsReceived       the connectivity checks received
/// @param responsesSent          the responses sent to checks
/// @param responsesReceived      the responses received to checks, consent checks included
/// @param consentRequestsSent    the consent freshness checks sent
/// @param lastPacketSentNanos    when the last application packet was sent, or an empty optional before one
/// @param lastPacketReceivedNanos when the last application packet was received, or an empty optional before one
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record IceCandidatePairStatistics(IceCandidatePair pair, IceCandidatePairState state, boolean nominated,
                                         boolean selected, long packetsSent, long packetsReceived, long bytesSent,
                                         long bytesReceived, Optional<Duration> currentRoundTripTime,
                                         Duration totalRoundTripTime, long requestsSent, long requestsReceived,
                                         long responsesSent, long responsesReceived, long consentRequestsSent,
                                         OptionalLong lastPacketSentNanos, OptionalLong lastPacketReceivedNanos) {
    /// Creates a snapshot.
    ///
    /// @param pair                    the pair
    /// @param state                   the checklist state
    /// @param nominated               whether the pair is nominated
    /// @param selected                whether the transport sends on the pair
    /// @param packetsSent             the application packets sent
    /// @param packetsReceived         the application packets received
    /// @param bytesSent               the application bytes sent
    /// @param bytesReceived           the application bytes received
    /// @param currentRoundTripTime    the last round-trip time
    /// @param totalRoundTripTime      the sum of the round-trip times
    /// @param requestsSent            the checks sent
    /// @param requestsReceived        the checks received
    /// @param responsesSent           the responses sent
    /// @param responsesReceived       the responses received
    /// @param consentRequestsSent     the consent checks sent
    /// @param lastPacketSentNanos     when the last packet was sent
    /// @param lastPacketReceivedNanos when the last packet was received
    public IceCandidatePairStatistics {
        Objects.requireNonNull(pair, "pair cannot be null");
        Objects.requireNonNull(state, "state cannot be null");
        Objects.requireNonNull(currentRoundTripTime, "currentRoundTripTime cannot be null");
        Objects.requireNonNull(totalRoundTripTime, "totalRoundTripTime cannot be null");
        Objects.requireNonNull(lastPacketSentNanos, "lastPacketSentNanos cannot be null");
        Objects.requireNonNull(lastPacketReceivedNanos, "lastPacketReceivedNanos cannot be null");
    }
}
