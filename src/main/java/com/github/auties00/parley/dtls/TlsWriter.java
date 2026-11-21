package com.github.auties00.parley.dtls;

import java.util.Arrays;

/// Builds the TLS presentation-language encoding of a handshake message or record: big-endian integers and
/// length-prefixed vectors, growing its array as needed.
///
/// A vector is written by reserving its length field with one of the `open` methods, writing the contents, and
/// filling the length in with [#close(int)].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html#section-3 RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
final class TlsWriter {
    /// The bytes written so far, followed by spare capacity.
    private byte[] buffer;

    /// The number of bytes written.
    private int length;

    /// Creates an empty writer.
    TlsWriter() {
        this(128);
    }

    /// Creates an empty writer with an initial capacity.
    ///
    /// @param capacity the initial capacity in bytes
    TlsWriter(int capacity) {
        this.buffer = new byte[Math.max(16, capacity)];
    }

    /// Writes the low 8 bits of a value.
    ///
    /// @param value the value
    /// @return this writer
    TlsWriter u8(int value) {
        ensure(1);
        buffer[length++] = (byte) value;
        return this;
    }

    /// Writes the low 16 bits of a value.
    ///
    /// @param value the value
    /// @return this writer
    TlsWriter u16(int value) {
        ensure(2);
        buffer[length++] = (byte) (value >>> 8);
        buffer[length++] = (byte) value;
        return this;
    }

    /// Writes the low 24 bits of a value.
    ///
    /// @param value the value
    /// @return this writer
    TlsWriter u24(int value) {
        ensure(3);
        buffer[length++] = (byte) (value >>> 16);
        buffer[length++] = (byte) (value >>> 8);
        buffer[length++] = (byte) value;
        return this;
    }

    /// Writes the low 48 bits of a value.
    ///
    /// @param value the value
    /// @return this writer
    TlsWriter u48(long value) {
        ensure(6);
        for (var shift = 40; shift >= 0; shift -= 8) {
            buffer[length++] = (byte) (value >>> shift);
        }
        return this;
    }

    /// Writes a 64-bit value.
    ///
    /// @param value the value
    /// @return this writer
    TlsWriter u64(long value) {
        ensure(8);
        for (var shift = 56; shift >= 0; shift -= 8) {
            buffer[length++] = (byte) (value >>> shift);
        }
        return this;
    }

    /// Writes bytes as they are.
    ///
    /// @param bytes the bytes
    /// @return this writer
    TlsWriter bytes(byte[] bytes) {
        return bytes(bytes, 0, bytes.length);
    }

    /// Writes a range of bytes as they are.
    ///
    /// @param bytes  the source
    /// @param offset the first byte
    /// @param count  the number of bytes
    /// @return this writer
    TlsWriter bytes(byte[] bytes, int offset, int count) {
        ensure(count);
        System.arraycopy(bytes, offset, buffer, length, count);
        length += count;
        return this;
    }

    /// Writes a vector with an 8-bit length.
    ///
    /// @param bytes the contents, at most 255 bytes
    /// @return this writer
    TlsWriter vector8(byte[] bytes) {
        return u8(checkLength(bytes.length, 0xFF)).bytes(bytes);
    }

    /// Writes a vector with a 16-bit length.
    ///
    /// @param bytes the contents, at most 65535 bytes
    /// @return this writer
    TlsWriter vector16(byte[] bytes) {
        return u16(checkLength(bytes.length, 0xFFFF)).bytes(bytes);
    }

    /// Writes a vector with a 24-bit length.
    ///
    /// @param bytes the contents
    /// @return this writer
    TlsWriter vector24(byte[] bytes) {
        return u24(checkLength(bytes.length, 0xFFFFFF)).bytes(bytes);
    }

    /// Reserves an 8-bit length field.
    ///
    /// @return the mark to pass to [#close(int)]
    int open8() {
        return open(1);
    }

    /// Reserves a 16-bit length field.
    ///
    /// @return the mark to pass to [#close(int)]
    int open16() {
        return open(2);
    }

    /// Reserves a 24-bit length field.
    ///
    /// @return the mark to pass to [#close(int)]
    int open24() {
        return open(3);
    }

    /// Fills in a reserved length field with the number of bytes written after it.
    ///
    /// @param mark the value an `open` method returned
    /// @throws IllegalStateException if the contents exceed the field
    void close(int mark) {
        var size = mark >>> 28;
        var position = mark & 0x0FFFFFFF;
        var contents = length - position - size;
        if (contents >= 1 << (8 * size)) {
            throw new IllegalStateException("vector of " + contents + " bytes exceeds its " + size + "-byte length");
        }
        for (var index = 0; index < size; index++) {
            buffer[position + index] = (byte) (contents >>> (8 * (size - 1 - index)));
        }
    }

    /// {@return the number of bytes written}
    int length() {
        return length;
    }

    /// {@return a copy of the bytes written}
    byte[] toByteArray() {
        return Arrays.copyOf(buffer, length);
    }

    /// Reserves `size` length bytes and encodes the size and position into a mark.
    private int open(int size) {
        ensure(size);
        var position = length;
        length += size;
        return size << 28 | position;
    }

    /// Fails when a vector exceeds its length field.
    private static int checkLength(int length, int maximum) {
        if (length > maximum) {
            throw new IllegalArgumentException("vector of " + length + " bytes exceeds " + maximum);
        }
        return length;
    }

    /// Grows the array to fit `extra` more bytes.
    private void ensure(int extra) {
        if (length + extra > buffer.length) {
            buffer = Arrays.copyOf(buffer, Math.max(buffer.length * 2, length + extra));
        }
    }
}
