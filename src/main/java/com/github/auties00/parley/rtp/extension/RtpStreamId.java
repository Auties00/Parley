package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The RTP stream identifier (`rid`) of a packet, which tells simulcast layers apart before their SSRCs are known.
///
/// The value is the identifier's UTF-8 bytes, without terminator; trailing zero bytes some senders pad it with are
/// removed when parsing.
///
/// @param value the identifier, 1 to 255 UTF-8 bytes (at most 16 in the one-byte element form)
/// @spec https://www.rfc-editor.org/rfc/rfc8852.html RFC 8852: RTP Stream Identifier Source Description (SDES)
public record RtpStreamId(String value) implements HeaderExtension {
    /// Validates the length.
    ///
    /// @throws IllegalArgumentException if the identifier is empty or longer than 255 UTF-8 bytes
    public RtpStreamId {
        ExtensionCodec.identifierBytes(java.util.Objects.requireNonNull(value, "value cannot be null"), "rid");
    }

    /// Parses an element value.
    ///
    /// @param value the element value between position and limit; the position is advanced to the limit
    /// @return the identifier
    /// @throws RtpFormatException if the value is empty or only zero bytes
    public static RtpStreamId parse(ByteBuffer value) throws RtpFormatException {
        return new RtpStreamId(ExtensionCodec.readIdentifier(value, "rid"));
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.RTP_STREAM_ID;
    }

    @Override
    public int encodedLength() {
        return ExtensionCodec.identifierBytes(value, "rid").length;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        var bytes = ExtensionCodec.identifierBytes(value, "rid");
        ExtensionCodec.checkRoom(destination, bytes.length);
        destination.put(bytes);
    }
}
