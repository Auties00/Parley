package com.github.auties00.parley.stun;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HexFormat;

/// The 96-bit transaction id of a STUN message, as two big-endian halves.
///
/// Ids of requests a client sends come from [#random()], a cryptographically random source, so an off-path attacker
/// cannot forge a matching response.
///
/// @param high the first 64 bits, big-endian
/// @param low  the last 32 bits, big-endian
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public record StunTransactionId(long high, int low) {
    /// The length of an id in bytes.
    public static final int LENGTH = 12;

    /// The source of random ids.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// {@return a new id drawn from a [SecureRandom]}
    public static StunTransactionId random() {
        return new StunTransactionId(RANDOM.nextLong(), RANDOM.nextInt());
    }

    /// {@return the id stored at `offset` in `buffer`, which is not moved}
    ///
    /// @param buffer the buffer
    /// @param offset the absolute offset of the first of the 12 bytes
    /// @throws IndexOutOfBoundsException if the 12 bytes do not fit in the buffer's limit
    public static StunTransactionId read(ByteBuffer buffer, int offset) {
        return new StunTransactionId(buffer.getLong(offset), buffer.getInt(offset + 8));
    }

    /// {@return the id held by a 12-byte array}
    ///
    /// @param bytes the id, big-endian
    /// @throws IllegalArgumentException if `bytes` is not 12 bytes long
    public static StunTransactionId of(byte[] bytes) {
        if (bytes.length != LENGTH) {
            throw new IllegalArgumentException("a transaction id has 12 bytes, not " + bytes.length);
        }
        var buffer = ByteBuffer.wrap(bytes);
        return new StunTransactionId(buffer.getLong(), buffer.getInt());
    }

    /// Writes the 12 bytes of the id at the buffer's position, which advances past them.
    ///
    /// @param buffer the destination
    /// @throws java.nio.BufferOverflowException if fewer than 12 bytes remain
    public void write(ByteBuffer buffer) {
        buffer.putLong(high).putInt(low);
    }

    /// {@return a new 12-byte array holding the id, big-endian}
    public byte[] toBytes() {
        return ByteBuffer.allocate(LENGTH).putLong(high).putInt(low).array();
    }

    /// {@return the id as 24 hexadecimal digits}
    @Override
    public String toString() {
        return HexFormat.of().formatHex(toBytes());
    }
}
