package com.github.auties00.parley.turn;

import java.nio.ByteBuffer;

/// The ChannelData message, the four-byte framing of data sent over a bound TURN channel.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Channel Number        |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                       Application Data                        /
/// ```
///
/// Over TCP and TLS the message is padded to a multiple of four bytes, which the length does not count.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
final class ChannelData {
    /// The first channel number a client may bind.
    static final int MIN_CHANNEL = 0x4000;

    /// The last channel number a client may bind.
    static final int MAX_CHANNEL = 0x4FFF;

    /// The length of the header.
    static final int HEADER_LENGTH = 4;

    /// Not instantiated.
    private ChannelData() {
    }

    /// {@return whether the remaining bytes start with a whole ChannelData message of a valid channel}
    static boolean isChannelData(ByteBuffer packet) {
        if (packet.remaining() < HEADER_LENGTH) {
            return false;
        }
        var channel = packet.getShort(packet.position()) & 0xFFFF;
        var length = packet.getShort(packet.position() + 2) & 0xFFFF;
        return channel >= MIN_CHANNEL && channel <= MAX_CHANNEL && HEADER_LENGTH + length <= packet.remaining();
    }

    /// {@return the channel number of the message at the buffer's position}
    static int channel(ByteBuffer packet) {
        return packet.getShort(packet.position()) & 0xFFFF;
    }

    /// {@return a view of the application data of the message at the buffer's position}
    static ByteBuffer payload(ByteBuffer packet) {
        var length = packet.getShort(packet.position() + 2) & 0xFFFF;
        return packet.slice(packet.position() + HEADER_LENGTH, length);
    }

    /// {@return the bytes a stream reader consumes for the message whose header starts at the buffer's position,
    /// padding included, or `-1` when fewer than four bytes remain}
    static int streamFrameLength(ByteBuffer packet) {
        if (packet.remaining() < HEADER_LENGTH) {
            return -1;
        }
        var length = packet.getShort(packet.position() + 2) & 0xFFFF;
        return HEADER_LENGTH + ((length + 3) & ~3);
    }

    /// {@return a new buffer holding a ChannelData message carrying `data`'s remaining bytes, which are consumed}
    ///
    /// @param padded whether to pad to four bytes, as a stream transport requires
    static ByteBuffer encode(int channel, ByteBuffer data, boolean padded) {
        var length = data.remaining();
        var total = HEADER_LENGTH + (padded ? (length + 3) & ~3 : length);
        var buffer = ByteBuffer.allocate(total);
        buffer.putShort((short) channel).putShort((short) length).put(data);
        return buffer.position(total).flip();
    }
}
