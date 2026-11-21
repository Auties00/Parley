package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;

/// The peer connection itself, `peer-connection`.
///
/// @param id                 the identifier of this object
/// @param timestamp          when the object was measured
/// @param dataChannelsOpened the data channels that reached the open state
/// @param dataChannelsClosed the data channels that left the open state
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record PeerConnectionStats(String id, Instant timestamp, long dataChannelsOpened,
                                  long dataChannelsClosed) implements RtcStats {
    /// Creates the statistics object.
    public PeerConnectionStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
    }

    /// {@return `PEER_CONNECTION`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.PEER_CONNECTION;
    }
}
