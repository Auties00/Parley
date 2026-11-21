package com.github.auties00.parley.dtls;

import java.util.Arrays;

/// Reads the TLS presentation-language encoding of a message: big-endian integers and length-prefixed vectors.
///
/// Every read past the end, and every vector whose length exceeds what remains, fails with a [DtlsException] carrying
/// [DtlsAlert#DECODE_ERROR], so a parser never reads garbage from a truncated or hostile message.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html#section-3 RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
final class TlsReader {
    /// The source array.
    private final byte[] source;

    /// The index of the next byte to read.
    private int position;

    /// The index after the last readable byte.
    private final int limit;

    /// Creates a reader over a whole array.
    ///
    /// @param source the array, not copied
    TlsReader(byte[] source) {
        this(source, 0, source.length);
    }

    /// Creates a reader over a range of an array.
    ///
    /// @param source the array, not copied
    /// @param offset the first byte
    /// @param length the number of bytes
    TlsReader(byte[] source, int offset, int length) {
        this.source = source;
        this.position = offset;
        this.limit = offset + length;
    }

    /// {@return an unsigned 8-bit value}
    ///
    /// @throws DtlsException if no byte remains
    int u8() throws DtlsException {
        require(1);
        return source[position++] & 0xFF;
    }

    /// {@return an unsigned 16-bit value}
    ///
    /// @throws DtlsException if fewer than two bytes remain
    int u16() throws DtlsException {
        require(2);
        var value = (source[position] & 0xFF) << 8 | (source[position + 1] & 0xFF);
        position += 2;
        return value;
    }

    /// {@return an unsigned 24-bit value}
    ///
    /// @throws DtlsException if fewer than three bytes remain
    int u24() throws DtlsException {
        require(3);
        var value = (source[position] & 0xFF) << 16 | (source[position + 1] & 0xFF) << 8 | (source[position + 2] & 0xFF);
        position += 3;
        return value;
    }

    /// {@return an unsigned 48-bit value}
    ///
    /// @throws DtlsException if fewer than six bytes remain
    long u48() throws DtlsException {
        return uN(6);
    }

    /// {@return a 64-bit value}
    ///
    /// @throws DtlsException if fewer than eight bytes remain
    long u64() throws DtlsException {
        return uN(8);
    }

    /// {@return a copy of the next `count` bytes}
    ///
    /// @param count the number of bytes
    /// @throws DtlsException if fewer bytes remain
    byte[] bytes(int count) throws DtlsException {
        require(count);
        var bytes = Arrays.copyOfRange(source, position, position + count);
        position += count;
        return bytes;
    }

    /// {@return the contents of a vector with an 8-bit length}
    ///
    /// @throws DtlsException if the vector is truncated
    byte[] vector8() throws DtlsException {
        return bytes(u8());
    }

    /// {@return the contents of a vector with a 16-bit length}
    ///
    /// @throws DtlsException if the vector is truncated
    byte[] vector16() throws DtlsException {
        return bytes(u16());
    }

    /// {@return the contents of a vector with a 24-bit length}
    ///
    /// @throws DtlsException if the vector is truncated
    byte[] vector24() throws DtlsException {
        return bytes(u24());
    }

    /// {@return a reader over the contents of a vector with an 8-bit length, skipping it in this reader}
    ///
    /// @throws DtlsException if the vector is truncated
    TlsReader sub8() throws DtlsException {
        return sub(u8());
    }

    /// {@return a reader over the contents of a vector with a 16-bit length, skipping it in this reader}
    ///
    /// @throws DtlsException if the vector is truncated
    TlsReader sub16() throws DtlsException {
        return sub(u16());
    }

    /// {@return a reader over the contents of a vector with a 24-bit length, skipping it in this reader}
    ///
    /// @throws DtlsException if the vector is truncated
    TlsReader sub24() throws DtlsException {
        return sub(u24());
    }

    /// Skips bytes.
    ///
    /// @param count the number of bytes
    /// @throws DtlsException if fewer bytes remain
    void skip(int count) throws DtlsException {
        require(count);
        position += count;
    }

    /// {@return the number of unread bytes}
    int remaining() {
        return limit - position;
    }

    /// {@return whether unread bytes remain}
    boolean hasRemaining() {
        return position < limit;
    }

    /// {@return the index of the next byte in the source array}
    int position() {
        return position;
    }

    /// Fails when bytes remain, for messages that must be consumed exactly.
    ///
    /// @throws DtlsException if bytes remain
    void expectEnd() throws DtlsException {
        if (position != limit) {
            throw new DtlsException(DtlsAlert.DECODE_ERROR, "trailing bytes in a message");
        }
    }

    /// {@return a reader over the next `count` bytes, skipping them in this reader}
    private TlsReader sub(int count) throws DtlsException {
        require(count);
        var reader = new TlsReader(source, position, count);
        position += count;
        return reader;
    }

    /// Reads an unsigned big-endian value of `count` bytes.
    private long uN(int count) throws DtlsException {
        require(count);
        var value = 0L;
        for (var index = 0; index < count; index++) {
            value = value << 8 | (source[position++] & 0xFF);
        }
        return value;
    }

    /// Fails when fewer than `count` bytes remain.
    private void require(int count) throws DtlsException {
        if (count < 0 || count > limit - position) {
            throw new DtlsException(DtlsAlert.DECODE_ERROR, "truncated message");
        }
    }
}
