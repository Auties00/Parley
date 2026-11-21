package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/// A local or remote ICE candidate, `local-candidate` or `remote-candidate`.
///
/// @param id               the identifier of this object
/// @param timestamp        when the object was measured
/// @param remote           whether this is a remote candidate (`remote-candidate`) rather than a local one
/// @param transportId      the id of the [TransportStats] the candidate belongs to
/// @param address          the address, possibly an mDNS `.local` name, or an empty optional when it is withheld
/// @param port             the port
/// @param protocol         the transport protocol, `udp` or `tcp`
/// @param candidateType    the candidate type
/// @param priority         the candidate priority
/// @param url              the STUN or TURN server URL a local server-reflexive or relayed candidate came from, or an empty optional
/// @param relayProtocol    the protocol to the TURN server of a local relayed candidate, `udp`, `tcp` or `tls`, or an empty optional
/// @param foundation       the foundation
/// @param relatedAddress   the related address, or an empty optional
/// @param relatedPort      the related port, or an empty optional
/// @param usernameFragment the ICE username fragment the candidate belongs to, or an empty optional
/// @param tcpType          the TCP candidate type, `active`, `passive` or `so`, or an empty optional for UDP
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record IceCandidateStats(String id, Instant timestamp, boolean remote, String transportId,
                                Optional<String> address, int port, String protocol, CandidateType candidateType,
                                long priority, Optional<String> url, Optional<String> relayProtocol, String foundation,
                                Optional<String> relatedAddress, OptionalInt relatedPort,
                                Optional<String> usernameFragment, Optional<String> tcpType) implements RtcStats {
    /// The type of an ICE candidate, the W3C `RTCIceCandidateType`.
    public enum CandidateType {
        /// `host`: A host candidate.
        HOST("host"),
        /// `srflx`: A server-reflexive candidate.
        SRFLX("srflx"),
        /// `prflx`: A peer-reflexive candidate.
        PRFLX("prflx"),
        /// `relay`: A relayed candidate.
        RELAY("relay");

        /// The W3C enumeration value.
        private final String value;

        CandidateType(String value) {
            this.value = value;
        }

        /// {@return the W3C enumeration value}
        public String value() {
            return value;
        }
    }

    /// Creates the statistics object.
    public IceCandidateStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(address, "address cannot be null");
        Objects.requireNonNull(protocol, "protocol cannot be null");
        Objects.requireNonNull(candidateType, "candidateType cannot be null");
        Objects.requireNonNull(url, "url cannot be null");
        Objects.requireNonNull(relayProtocol, "relayProtocol cannot be null");
        Objects.requireNonNull(foundation, "foundation cannot be null");
        Objects.requireNonNull(relatedAddress, "relatedAddress cannot be null");
        Objects.requireNonNull(relatedPort, "relatedPort cannot be null");
        Objects.requireNonNull(usernameFragment, "usernameFragment cannot be null");
        Objects.requireNonNull(tcpType, "tcpType cannot be null");
    }

    /// {@return `REMOTE_CANDIDATE` for a remote candidate, `LOCAL_CANDIDATE` for a local one}
    @Override
    public RtcStatsType type() {
        return remote ? RtcStatsType.REMOTE_CANDIDATE : RtcStatsType.LOCAL_CANDIDATE;
    }
}
