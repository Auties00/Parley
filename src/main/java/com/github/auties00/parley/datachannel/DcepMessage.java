package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.media.Priority;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/// A Data Channel Establishment Protocol message, carried with payload protocol identifier 50 on the stream of the
/// channel it opens.
///
/// ```text
/// DATA_CHANNEL_OPEN
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Message Type |  Channel Type |            Priority           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Reliability Parameter                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Label Length          |       Protocol Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Label (UTF-8) ...  Protocol (UTF-8) ...   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// DATA_CHANNEL_ACK: one byte, the message type 0x02
/// ```
///
/// @spec https://www.rfc-editor.org/rfc/rfc8832.html#section-5 RFC 8832: WebRTC Data Channel Establishment Protocol, Message Formats
sealed interface DcepMessage {
    /// The `DATA_CHANNEL_OPEN` message type.
    int OPEN_TYPE = 0x03;

    /// The `DATA_CHANNEL_ACK` message type.
    int ACK_TYPE = 0x02;

    /// The bit of the channel type that makes delivery unordered.
    int UNORDERED_BIT = 0x80;

    /// The channel type of a reliable channel.
    int RELIABLE = 0x00;

    /// The channel type of a channel limited by a retransmission count.
    int PARTIAL_RELIABLE_REXMIT = 0x01;

    /// The channel type of a channel limited by a lifetime in milliseconds.
    int PARTIAL_RELIABLE_TIMED = 0x02;

    /// The size of the fixed part of an open message.
    int OPEN_HEADER_SIZE = 12;

    /// {@return the encoded message, positioned at its first byte}
    ByteBuffer encode();

    /// A `DATA_CHANNEL_OPEN` message.
    ///
    /// @param channelType          the channel type, one of the three reliability types optionally with
    ///                             [#UNORDERED_BIT]
    /// @param priority             the 16-bit priority
    /// @param reliabilityParameter the retransmission count or lifetime in milliseconds; `0` for a reliable channel
    /// @param label                the channel label
    /// @param protocol             the sub-protocol
    record Open(int channelType, int priority, long reliabilityParameter, String label, String protocol)
            implements DcepMessage {
        /// Validates the message.
        public Open {
            Objects.requireNonNull(label, "label");
            Objects.requireNonNull(protocol, "protocol");
            if (!validChannelType(channelType)) {
                throw new IllegalArgumentException("unknown channel type: " + channelType);
            }
            if (priority < 0 || priority > 0xFFFF) {
                throw new IllegalArgumentException("priority must be an unsigned 16-bit value: " + priority);
            }
            if (reliabilityParameter < 0 || reliabilityParameter > 0xFFFF_FFFFL) {
                throw new IllegalArgumentException("reliabilityParameter must be an unsigned 32-bit value");
            }
            if (label.getBytes(StandardCharsets.UTF_8).length > 0xFFFF
                    || protocol.getBytes(StandardCharsets.UTF_8).length > 0xFFFF) {
                throw new IllegalArgumentException("label and protocol must be at most 65535 UTF-8 bytes");
            }
        }

        /// {@return the open message announcing a channel created with `init`}
        ///
        /// @param label the channel label
        /// @param init  the channel options
        static Open of(String label, DataChannelInit init) {
            var type = init.maxRetransmits().isPresent() ? PARTIAL_RELIABLE_REXMIT
                    : init.maxPacketLifeTime().isPresent() ? PARTIAL_RELIABLE_TIMED : RELIABLE;
            if (!init.ordered()) {
                type |= UNORDERED_BIT;
            }
            long parameter = init.maxRetransmits().isPresent() ? init.maxRetransmits().getAsInt()
                    : init.maxPacketLifeTime().map(Duration::toMillis).orElse(0L);
            return new Open(type, init.priority().wireValue(), parameter, label, init.protocol());
        }

        /// {@return the options of the channel this message opens, as the receiving side creates it}
        DataChannelInit toInit() {
            var ordered = (channelType & UNORDERED_BIT) == 0;
            var reliability = channelType & ~UNORDERED_BIT;
            var maxRetransmits = reliability == PARTIAL_RELIABLE_REXMIT
                    ? OptionalInt.of((int) Math.min(reliabilityParameter, DataChannelInit.MAX_RELIABILITY_VALUE))
                    : OptionalInt.empty();
            var lifetime = reliability == PARTIAL_RELIABLE_TIMED
                    ? Optional.of(Duration.ofMillis(Math.min(reliabilityParameter, DataChannelInit.MAX_RELIABILITY_VALUE)))
                    : Optional.<Duration>empty();
            return new DataChannelInit(ordered, maxRetransmits, lifetime, protocol, false, OptionalInt.empty(),
                    Priority.ofWireValue(priority));
        }

        @Override
        public ByteBuffer encode() {
            var labelBytes = label.getBytes(StandardCharsets.UTF_8);
            var protocolBytes = protocol.getBytes(StandardCharsets.UTF_8);
            var buffer = ByteBuffer.allocate(OPEN_HEADER_SIZE + labelBytes.length + protocolBytes.length);
            buffer.put((byte) OPEN_TYPE)
                    .put((byte) channelType)
                    .putShort((short) priority)
                    .putInt((int) reliabilityParameter)
                    .putShort((short) labelBytes.length)
                    .putShort((short) protocolBytes.length)
                    .put(labelBytes)
                    .put(protocolBytes);
            return buffer.flip();
        }
    }

    /// A `DATA_CHANNEL_ACK` message.
    record Ack() implements DcepMessage {
        @Override
        public ByteBuffer encode() {
            return ByteBuffer.wrap(new byte[]{(byte) ACK_TYPE});
        }
    }

    /// Parses a message received with payload protocol identifier 50.
    ///
    /// @param payload the message, between position and limit; not modified
    /// @return the message, or empty when it is malformed, of an unknown type, or announces an unknown channel
    ///         type or invalid UTF-8
    static Optional<DcepMessage> parse(ByteBuffer payload) {
        var buffer = payload.duplicate();
        if (!buffer.hasRemaining()) {
            return Optional.empty();
        }
        var type = buffer.get() & 0xFF;
        if (type == ACK_TYPE) {
            return Optional.of(new Ack());
        }
        if (type != OPEN_TYPE || buffer.remaining() < OPEN_HEADER_SIZE - 1) {
            return Optional.empty();
        }
        var channelType = buffer.get() & 0xFF;
        var priority = buffer.getShort() & 0xFFFF;
        var reliability = buffer.getInt() & 0xFFFF_FFFFL;
        var labelLength = buffer.getShort() & 0xFFFF;
        var protocolLength = buffer.getShort() & 0xFFFF;
        if (!validChannelType(channelType) || buffer.remaining() < labelLength + protocolLength) {
            return Optional.empty();
        }
        try {
            var label = decode(buffer, labelLength);
            var protocol = decode(buffer, protocolLength);
            if ((channelType & ~UNORDERED_BIT) == RELIABLE) {
                reliability = 0;
            }
            return Optional.of(new Open(channelType, priority, reliability, label, protocol));
        } catch (CharacterCodingException exception) {
            return Optional.empty();
        }
    }

    private static String decode(ByteBuffer buffer, int length) throws CharacterCodingException {
        var slice = buffer.slice(buffer.position(), length);
        buffer.position(buffer.position() + length);
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(slice)
                .toString();
    }

    private static boolean validChannelType(int channelType) {
        var reliability = channelType & ~UNORDERED_BIT;
        return channelType >= 0 && channelType <= 0xFF
                && (reliability == RELIABLE || reliability == PARTIAL_RELIABLE_REXMIT
                || reliability == PARTIAL_RELIABLE_TIMED);
    }
}
