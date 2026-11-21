package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/// Shared checks of the header extension codecs.
final class ExtensionCodec {
    private ExtensionCodec() {
        throw new AssertionError("ExtensionCodec cannot be instantiated");
    }

    /// Fails with an [RtpFormatException] when `value` has fewer than `length` remaining bytes.
    static void require(ByteBuffer value, int length, String name) throws RtpFormatException {
        if (value.remaining() < length) {
            throw new RtpFormatException(name + " value shorter than " + length + " bytes: " + value.remaining());
        }
    }

    /// Fails with a [BufferOverflowException] when `destination` cannot take `length` more bytes.
    static void checkRoom(ByteBuffer destination, int length) {
        if (destination.remaining() < length) {
            throw new BufferOverflowException();
        }
    }

    /// Reads an SDES-style identifier: the remaining bytes as UTF-8 with trailing zero bytes removed.
    static String readIdentifier(ByteBuffer value, String name) throws RtpFormatException {
        var bytes = new byte[value.remaining()];
        value.get(bytes);
        var length = bytes.length;
        while (length > 0 && bytes[length - 1] == 0) {
            length--;
        }
        if (length == 0) {
            throw new RtpFormatException(name + " is empty");
        }
        return new String(bytes, 0, length, StandardCharsets.UTF_8);
    }

    /// Validates an SDES-style identifier: 1..255 UTF-8 bytes.
    static byte[] identifierBytes(String value, String name) {
        var bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0 || bytes.length > 255) {
            throw new IllegalArgumentException(name + " must be 1..255 UTF-8 bytes: " + bytes.length);
        }
        return bytes;
    }
}
