package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;

/// An ICE candidate pair, `candidate-pair`.
///
/// @param id                          the identifier of this object
/// @param timestamp                   when the object was measured
/// @param transportId                 the id of the [TransportStats] the pair belongs to
/// @param localCandidateId            the id of the local [IceCandidateStats]
/// @param remoteCandidateId           the id of the remote [IceCandidateStats]
/// @param state                       the check state of the pair
/// @param nominated                   whether the pair is nominated
/// @param packetsSent                 the packets sent on the pair
/// @param packetsReceived             the packets received on the pair
/// @param bytesSent                   the payload bytes sent on the pair
/// @param bytesReceived               the payload bytes received on the pair
/// @param lastPacketSentTimestamp     when the last packet was sent, or an empty optional
/// @param lastPacketReceivedTimestamp when the last packet arrived, or an empty optional
/// @param totalRoundTripTime          the sum of the STUN round-trip times measured, in seconds
/// @param currentRoundTripTime        the last STUN round-trip time, in seconds, or an empty optional
/// @param availableOutgoingBitrate    the bandwidth estimate for sending, in bits per second, or an empty optional when the pair is not selected
/// @param requestsSent                the connectivity check requests sent
/// @param requestsReceived            the connectivity check requests received
/// @param responsesSent               the connectivity check responses sent
/// @param responsesReceived           the connectivity check responses received
/// @param consentRequestsSent         the consent freshness requests sent
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record IceCandidatePairStats(String id, Instant timestamp, String transportId, String localCandidateId,
                                    String remoteCandidateId, State state, boolean nominated, long packetsSent,
                                    long packetsReceived, long bytesSent, long bytesReceived,
                                    Optional<Instant> lastPacketSentTimestamp,
                                    Optional<Instant> lastPacketReceivedTimestamp, double totalRoundTripTime,
                                    OptionalDouble currentRoundTripTime, OptionalDouble availableOutgoingBitrate,
                                    long requestsSent, long requestsReceived, long responsesSent,
                                    long responsesReceived, long consentRequestsSent) implements RtcStats {
    /// The check state of a candidate pair, the W3C `RTCStatsIceCandidatePairState`.
    public enum State {
        /// `frozen`: Waiting for another pair of the same foundation.
        FROZEN("frozen"),
        /// `waiting`: Ready to be checked.
        WAITING("waiting"),
        /// `in-progress`: Being checked.
        IN_PROGRESS("in-progress"),
        /// `failed`: The check failed.
        FAILED("failed"),
        /// `succeeded`: The check succeeded.
        SUCCEEDED("succeeded");

        /// The W3C enumeration value.
        private final String value;

        State(String value) {
            this.value = value;
        }

        /// {@return the W3C enumeration value}
        public String value() {
            return value;
        }
    }

    /// Creates the statistics object.
    public IceCandidatePairStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(localCandidateId, "localCandidateId cannot be null");
        Objects.requireNonNull(remoteCandidateId, "remoteCandidateId cannot be null");
        Objects.requireNonNull(state, "state cannot be null");
        Objects.requireNonNull(lastPacketSentTimestamp, "lastPacketSentTimestamp cannot be null");
        Objects.requireNonNull(lastPacketReceivedTimestamp, "lastPacketReceivedTimestamp cannot be null");
        Objects.requireNonNull(currentRoundTripTime, "currentRoundTripTime cannot be null");
        Objects.requireNonNull(availableOutgoingBitrate, "availableOutgoingBitrate cannot be null");
    }

    /// {@return `CANDIDATE_PAIR`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.CANDIDATE_PAIR;
    }
}
