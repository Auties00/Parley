package com.github.auties00.parley.ice;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// A snapshot of an ICE transport, the inputs of the webrtc-stats `transport`, `candidate-pair`, `local-candidate`
/// and `remote-candidate` dictionaries.
///
/// @param role                        the current role
/// @param state                       the transport state
/// @param gatheringState              the gathering state
/// @param selectedPair                the pair the transport sends on, or an empty optional before one is selected
/// @param selectedCandidatePairChanges how many times the selected pair changed
/// @param packetsSent                 the application packets sent on every pair
/// @param packetsReceived             the application packets received on every pair
/// @param bytesSent                   the application bytes sent on every pair
/// @param bytesReceived               the application bytes received on every pair
/// @param localCandidates             the local candidates, as signalled
/// @param remoteCandidates            the remote candidates, signalled and peer-reflexive
/// @param pairs                       the statistics of every pair in the checklist
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record IceTransportStatistics(IceRole role, IceTransportState state, IceGatheringState gatheringState,
                                     Optional<IceCandidatePair> selectedPair, long selectedCandidatePairChanges,
                                     long packetsSent, long packetsReceived, long bytesSent, long bytesReceived,
                                     List<IceCandidate> localCandidates, List<IceCandidate> remoteCandidates,
                                     List<IceCandidatePairStatistics> pairs) {
    /// Creates a snapshot.
    ///
    /// @param role                         the role
    /// @param state                        the transport state
    /// @param gatheringState               the gathering state
    /// @param selectedPair                 the selected pair
    /// @param selectedCandidatePairChanges the selected pair changes
    /// @param packetsSent                  the packets sent
    /// @param packetsReceived              the packets received
    /// @param bytesSent                    the bytes sent
    /// @param bytesReceived                the bytes received
    /// @param localCandidates              the local candidates, copied
    /// @param remoteCandidates             the remote candidates, copied
    /// @param pairs                        the pair statistics, copied
    public IceTransportStatistics {
        Objects.requireNonNull(role, "role cannot be null");
        Objects.requireNonNull(state, "state cannot be null");
        Objects.requireNonNull(gatheringState, "gatheringState cannot be null");
        Objects.requireNonNull(selectedPair, "selectedPair cannot be null");
        localCandidates = List.copyOf(localCandidates);
        remoteCandidates = List.copyOf(remoteCandidates);
        pairs = List.copyOf(pairs);
    }
}
