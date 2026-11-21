package com.github.auties00.parley.payload;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/// One RTP payload a [Packetizer] produced, with the marker bit and header extension values its packet must carry.
///
/// @param payload    the payload, read-only, from position to limit; a slice of the frame's bytes when the format
///                   lets the payload be one, otherwise a freshly written buffer
/// @param marker     the RTP marker bit of the packet
/// @param extensions the header extension values the packet must carry, by extension URI, each read-only;
///                   unmodifiable, usually empty
public record PacketizedPayload(ByteBuffer payload, boolean marker, Map<URI, ByteBuffer> extensions) {
    /// Creates a payload.
    ///
    /// @param payload    the payload; the record keeps a read-only view without copying
    /// @param marker     the marker bit
    /// @param extensions the header extension values, copied as read-only views
    public PacketizedPayload {
        Objects.requireNonNull(payload, "payload cannot be null");
        payload = payload.slice().asReadOnlyBuffer();
        var copy = new HashMap<URI, ByteBuffer>();
        for (var entry : extensions.entrySet()) {
            copy.put(Objects.requireNonNull(entry.getKey(), "extension uri cannot be null"),
                    Objects.requireNonNull(entry.getValue(), "extension value cannot be null").slice().asReadOnlyBuffer());
        }
        extensions = Map.copyOf(copy);
    }

    /// {@return a payload without header extensions}
    ///
    /// @param payload the payload, kept without copying
    /// @param marker  the marker bit
    public static PacketizedPayload of(ByteBuffer payload, boolean marker) {
        return new PacketizedPayload(payload, marker, Map.of());
    }

    /// {@return a new read-only view of the payload, positioned at zero}
    @Override
    public ByteBuffer payload() {
        return payload.duplicate();
    }

    /// {@return a description of the payload with its size instead of its bytes}
    @Override
    public String toString() {
        return "PacketizedPayload[size=" + payload.remaining() + ", marker=" + marker + ", extensions="
                + extensions.keySet() + "]";
    }
}
