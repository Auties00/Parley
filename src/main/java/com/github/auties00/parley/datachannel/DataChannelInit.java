package com.github.auties00.parley.datachannel;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/// The options of a new [DataChannel], as the W3C `RTCDataChannelInit`.
///
/// {@snippet lang = java :
/// var game = DataChannelInit.reliable()
///         .withOrdered(false)
///         .withMaxRetransmits(0)
///         .withPriority(DataChannelPriority.HIGH);
/// var control = DataChannelInit.reliable().withNegotiatedId(0);
/// }
///
/// @param ordered           whether messages are delivered in the order they were sent
/// @param maxRetransmits    how many times a message is retransmitted before it is abandoned (partial reliability);
///                          empty for unlimited
/// @param maxPacketLifeTime how long a message is retransmitted before it is abandoned (partial reliability); empty
///                          for unlimited
/// @param protocol          the sub-protocol name announced to the peer, possibly empty; at most 65,535 UTF-8 bytes
/// @param negotiated        whether the application negotiated the channel out of band, so no
///                          `DATA_CHANNEL_OPEN` is sent and the peer creates the same channel with the same id
/// @param id                the SCTP stream id of a negotiated channel, `0` to `65534`; present exactly when
///                          `negotiated` is
/// @param priority          the channel's priority
///
/// @spec https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit WebRTC: Real-Time Communication in Browsers, RTCDataChannelInit
/// @spec https://www.rfc-editor.org/rfc/rfc3758.html RFC 3758: Stream Control Transmission Protocol (SCTP) Partial Reliability Extension
public record DataChannelInit(boolean ordered, OptionalInt maxRetransmits, Optional<Duration> maxPacketLifeTime,
                              String protocol, boolean negotiated, OptionalInt id, DataChannelPriority priority) {
    /// The largest stream id a channel may use; 65535 is reserved.
    public static final int MAX_ID = 65534;

    /// The largest retransmission count and lifetime in milliseconds, the 16-bit range the W3C API clamps to.
    public static final int MAX_RELIABILITY_VALUE = 65535;

    /// Validates the options and clamps `maxPacketLifeTime` to 65,535 ms.
    ///
    /// @throws IllegalArgumentException if both `maxRetransmits` and `maxPacketLifeTime` are present, either is
    ///                                  negative, `protocol` is longer than 65,535 UTF-8 bytes, `negotiated` is set
    ///                                  without an `id` (or the reverse) or `id` is outside `0` to [#MAX_ID]
    public DataChannelInit {
        Objects.requireNonNull(maxRetransmits, "maxRetransmits");
        Objects.requireNonNull(maxPacketLifeTime, "maxPacketLifeTime");
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(priority, "priority");
        if (maxRetransmits.isPresent() && maxPacketLifeTime.isPresent()) {
            throw new IllegalArgumentException("maxRetransmits and maxPacketLifeTime are mutually exclusive");
        }
        if (maxRetransmits.isPresent()) {
            if (maxRetransmits.getAsInt() < 0) {
                throw new IllegalArgumentException("maxRetransmits must not be negative: " + maxRetransmits.getAsInt());
            }
            maxRetransmits = OptionalInt.of(Math.min(maxRetransmits.getAsInt(), MAX_RELIABILITY_VALUE));
        }
        if (maxPacketLifeTime.isPresent()) {
            var lifetime = maxPacketLifeTime.get();
            if (lifetime.isNegative()) {
                throw new IllegalArgumentException("maxPacketLifeTime must not be negative: " + lifetime);
            }
            if (lifetime.toMillis() > MAX_RELIABILITY_VALUE) {
                maxPacketLifeTime = Optional.of(Duration.ofMillis(MAX_RELIABILITY_VALUE));
            }
        }
        if (protocol.getBytes(StandardCharsets.UTF_8).length > 0xFFFF) {
            throw new IllegalArgumentException("protocol must be at most 65535 UTF-8 bytes");
        }
        if (negotiated != id.isPresent()) {
            throw new IllegalArgumentException("id must be present exactly when the channel is negotiated");
        }
        if (id.isPresent() && (id.getAsInt() < 0 || id.getAsInt() > MAX_ID)) {
            throw new IllegalArgumentException("id must be in 0.." + MAX_ID + ": " + id.getAsInt());
        }
    }

    /// {@return the options of an ordered, reliable, in-band negotiated channel with no protocol and [DataChannelPriority#LOW]
    /// priority}, the W3C defaults
    public static DataChannelInit reliable() {
        return new DataChannelInit(true, OptionalInt.empty(), Optional.empty(), "", false, OptionalInt.empty(),
                DataChannelPriority.LOW);
    }

    /// {@return a copy with the given ordering}
    ///
    /// @param ordered whether messages are delivered in order
    public DataChannelInit withOrdered(boolean ordered) {
        return new DataChannelInit(ordered, maxRetransmits, maxPacketLifeTime, protocol, negotiated, id, priority);
    }

    /// {@return a copy abandoning messages after `maxRetransmits` retransmissions, with no lifetime limit}
    ///
    /// @param maxRetransmits the retransmission limit, not negative
    /// @throws IllegalArgumentException if `maxRetransmits` is negative
    public DataChannelInit withMaxRetransmits(int maxRetransmits) {
        return new DataChannelInit(ordered, OptionalInt.of(maxRetransmits), Optional.empty(), protocol, negotiated, id,
                priority);
    }

    /// {@return a copy abandoning messages not delivered within `maxPacketLifeTime`, with no retransmission limit}
    ///
    /// @param maxPacketLifeTime the lifetime, not negative
    /// @throws IllegalArgumentException if `maxPacketLifeTime` is negative
    public DataChannelInit withMaxPacketLifeTime(Duration maxPacketLifeTime) {
        Objects.requireNonNull(maxPacketLifeTime, "maxPacketLifeTime");
        return new DataChannelInit(ordered, OptionalInt.empty(), Optional.of(maxPacketLifeTime), protocol, negotiated,
                id, priority);
    }

    /// {@return a copy announcing `protocol`}
    ///
    /// @param protocol the sub-protocol name
    /// @throws IllegalArgumentException if `protocol` is longer than 65,535 UTF-8 bytes
    public DataChannelInit withProtocol(String protocol) {
        return new DataChannelInit(ordered, maxRetransmits, maxPacketLifeTime, protocol, negotiated, id, priority);
    }

    /// {@return a copy negotiated out of band on stream `id`}
    ///
    /// @param id the stream id, `0` to [#MAX_ID]
    /// @throws IllegalArgumentException if `id` is out of range
    public DataChannelInit withNegotiatedId(int id) {
        return new DataChannelInit(ordered, maxRetransmits, maxPacketLifeTime, protocol, true, OptionalInt.of(id),
                priority);
    }

    /// {@return a copy with the given priority}
    ///
    /// @param priority the priority
    public DataChannelInit withPriority(DataChannelPriority priority) {
        return new DataChannelInit(ordered, maxRetransmits, maxPacketLifeTime, protocol, negotiated, id, priority);
    }

    /// {@return whether the channel is reliable: neither a retransmission nor a lifetime limit is set}
    public boolean reliableDelivery() {
        return maxRetransmits.isEmpty() && maxPacketLifeTime.isEmpty();
    }
}
