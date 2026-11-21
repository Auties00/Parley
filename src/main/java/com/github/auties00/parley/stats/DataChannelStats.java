package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.OptionalInt;

/// A data channel, `data-channel`.
///
/// @param id                    the identifier of this object
/// @param timestamp             when the object was measured
/// @param label                 the channel label
/// @param protocol              the subprotocol, empty when none
/// @param dataChannelIdentifier the SCTP stream id, or an empty optional before one is assigned
/// @param state                 the channel state
/// @param messagesSent          the messages sent
/// @param bytesSent             the payload bytes sent
/// @param messagesReceived      the messages received
/// @param bytesReceived         the payload bytes received
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record DataChannelStats(String id, Instant timestamp, String label, String protocol,
                               OptionalInt dataChannelIdentifier, State state, long messagesSent, long bytesSent,
                               long messagesReceived, long bytesReceived) implements RtcStats {
    /// The state of a data channel, the W3C `RTCDataChannelState`.
    public enum State {
        /// `connecting`: Opening.
        CONNECTING("connecting"),
        /// `open`: Open.
        OPEN("open"),
        /// `closing`: Closing.
        CLOSING("closing"),
        /// `closed`: Closed.
        CLOSED("closed");

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
    public DataChannelStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(label, "label cannot be null");
        Objects.requireNonNull(protocol, "protocol cannot be null");
        Objects.requireNonNull(dataChannelIdentifier, "dataChannelIdentifier cannot be null");
        Objects.requireNonNull(state, "state cannot be null");
    }

    /// {@return `DATA_CHANNEL`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.DATA_CHANNEL;
    }
}
