package com.github.auties00.parley.payload;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/// One RTP payload a [Packetizer] produced, with the marker bit and header extension values its packet must carry.
///
/// A payload is a `header` the packetizer wrote (a payload descriptor, a fragmentation header; empty when the format
/// has none) followed by a `body` that is a slice of the frame's bytes, so splitting a frame copies none of its
/// bytes: the sender writes the header and then the body into the packet, the one copy a packet needs.
///
/// # Ownership
///
/// The body is a read-only view of the frame's data, not a copy, so a payload is valid only while the buffer the
/// frame was built from keeps those bytes: send it, or copy it with [#payload()], before reusing that buffer.
///
/// @param header     the bytes the packetizer wrote before the body, read-only, from position to limit; empty when
///                   the payload is the body alone
/// @param body       the bytes taken from the frame, read-only, from position to limit; a slice of the frame's
///                   buffer when the format lets the payload be one, otherwise a freshly written buffer
/// @param marker     the RTP marker bit of the packet
/// @param extensions the header extension values the packet must carry, by extension URI, each read-only;
///                   unmodifiable, usually empty
public record PacketizedPayload(ByteBuffer header, ByteBuffer body, boolean marker,
                                Map<URI, ByteBuffer> extensions) {
    /// The empty header of a payload that is its body alone.
    private static final ByteBuffer NO_HEADER = ByteBuffer.allocate(0).asReadOnlyBuffer();

    /// Creates a payload.
    ///
    /// @param header     the header; the record keeps a read-only view without copying
    /// @param body       the body; the record keeps a read-only view without copying
    /// @param marker     the marker bit
    /// @param extensions the header extension values, copied as read-only views
    public PacketizedPayload {
        header = view(Objects.requireNonNull(header, "header cannot be null"));
        body = view(Objects.requireNonNull(body, "body cannot be null"));
        Objects.requireNonNull(extensions, "extensions cannot be null");
        if (extensions.isEmpty()) {
            extensions = Map.of();
        } else {
            var copy = new HashMap<URI, ByteBuffer>();
            for (var entry : extensions.entrySet()) {
                copy.put(Objects.requireNonNull(entry.getKey(), "extension uri cannot be null"),
                        view(Objects.requireNonNull(entry.getValue(), "extension value cannot be null")));
            }
            extensions = Map.copyOf(copy);
        }
    }

    /// Creates a payload without a header.
    ///
    /// @param payload    the payload, the body; the record keeps a read-only view without copying
    /// @param marker     the marker bit
    /// @param extensions the header extension values, copied as read-only views
    public PacketizedPayload(ByteBuffer payload, boolean marker, Map<URI, ByteBuffer> extensions) {
        this(NO_HEADER, payload, marker, extensions);
    }

    /// {@return a payload without header extensions or a header}
    ///
    /// @param payload the payload, kept without copying
    /// @param marker  the marker bit
    public static PacketizedPayload of(ByteBuffer payload, boolean marker) {
        return new PacketizedPayload(NO_HEADER, payload, marker, Map.of());
    }

    /// {@return a payload of a header and a body, without header extensions}
    ///
    /// @param header the header, kept without copying
    /// @param body   the body, kept without copying
    /// @param marker the marker bit
    public static PacketizedPayload of(ByteBuffer header, ByteBuffer body, boolean marker) {
        return new PacketizedPayload(header, body, marker, Map.of());
    }

    /// {@return a read-only view of `buffer` from its position to its limit, positioned at zero}
    private static ByteBuffer view(ByteBuffer buffer) {
        var slice = buffer.slice();
        return slice.isReadOnly() ? slice : slice.asReadOnlyBuffer();
    }

    /// {@return a new read-only view of the header, positioned at zero}
    @Override
    public ByteBuffer header() {
        return header.duplicate();
    }

    /// {@return a new read-only view of the body, positioned at zero}
    @Override
    public ByteBuffer body() {
        return body.duplicate();
    }

    /// {@return the whole payload, the header followed by the body, read-only and positioned at zero}
    ///
    /// A payload without a header returns a view of the body; one with a header returns a new buffer holding a copy
    /// of both, which a sender avoids by writing [#header()] and [#body()] itself.
    public ByteBuffer payload() {
        if (!header.hasRemaining()) {
            return body.duplicate();
        }
        var joined = ByteBuffer.allocate(header.remaining() + body.remaining());
        joined.put(header.duplicate()).put(body.duplicate());
        return joined.flip().asReadOnlyBuffer();
    }

    /// {@return the payload length: the header's and the body's}
    public int length() {
        return header.remaining() + body.remaining();
    }

    /// {@return a description of the payload with its size instead of its bytes}
    @Override
    public String toString() {
        return "PacketizedPayload[size=" + length() + ", marker=" + marker + ", extensions=" + extensions.keySet()
                + "]";
    }
}
