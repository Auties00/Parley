package com.github.auties00.parley.datachannel;

import java.util.Objects;
import java.util.OptionalInt;

/// A snapshot of a [DataChannel]'s counters, the members of the webrtc-stats `data-channel` dictionary.
///
/// @param label            the channel's label
/// @param protocol         the channel's sub-protocol
/// @param id               the channel's stream id, empty while it has none
/// @param state            the channel's ready state when the snapshot was taken
/// @param messagesSent     the messages handed to the association
/// @param bytesSent        the payload bytes of those messages
/// @param messagesReceived the messages delivered to the channel
/// @param bytesReceived    the payload bytes of those messages
///
/// @spec https://www.w3.org/TR/webrtc-stats/#dcstats-dict* Identifiers for WebRTC's Statistics API, RTCDataChannelStats
public record DataChannelStatistics(String label, String protocol, OptionalInt id, DataChannelState state,
                                    long messagesSent, long bytesSent, long messagesReceived, long bytesReceived) {
    /// Validates the snapshot.
    ///
    /// @throws IllegalArgumentException if a counter is negative
    public DataChannelStatistics {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(state, "state");
        if (messagesSent < 0 || bytesSent < 0 || messagesReceived < 0 || bytesReceived < 0) {
            throw new IllegalArgumentException("counters must not be negative");
        }
    }
}
