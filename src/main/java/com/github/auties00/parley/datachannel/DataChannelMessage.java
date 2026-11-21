package com.github.auties00.parley.datachannel;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/// A message received on, or sent over, a [DataChannel]: text or binary, as the payload protocol identifier of the
/// SCTP message says.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html#section-6.6 RFC 8831: WebRTC Data Channels, Transferring User Data on a Data Channel
public sealed interface DataChannelMessage {
    /// {@return the size of the message payload in bytes: the UTF-8 length of a text message}
    int sizeBytes();

    /// A text message.
    ///
    /// @param value the text, possibly empty
    record Text(String value) implements DataChannelMessage {
        /// Validates the message.
        public Text {
            Objects.requireNonNull(value, "value");
        }

        @Override
        public int sizeBytes() {
            return value.getBytes(StandardCharsets.UTF_8).length;
        }
    }

    /// A binary message. The bytes are copied in and the accessor returns a read-only view, so the message is
    /// immutable.
    ///
    /// @param value the bytes between position and limit, possibly none
    record Binary(ByteBuffer value) implements DataChannelMessage {
        /// Copies the remaining bytes of `value`.
        public Binary {
            Objects.requireNonNull(value, "value");
            var copy = ByteBuffer.allocate(value.remaining());
            copy.put(value.duplicate()).flip();
            value = copy.asReadOnlyBuffer();
        }

        /// {@return a read-only view of the bytes, positioned at the first one}
        @Override
        public ByteBuffer value() {
            return value.duplicate();
        }

        /// {@return a copy of the bytes}
        public byte[] toByteArray() {
            var bytes = new byte[value.remaining()];
            value.duplicate().get(bytes);
            return bytes;
        }

        @Override
        public int sizeBytes() {
            return value.remaining();
        }
    }
}
