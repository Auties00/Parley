package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The RTP stream identifier of the stream a repair packet (RTX or FEC) repairs.
///
/// The value is the identifier's UTF-8 bytes, without terminator; trailing zero bytes some senders pad it with are
/// removed when parsing.
///
/// @param value the identifier, 1 to 255 UTF-8 bytes (at most 16 in the one-byte element form)
/// @spec https://www.rfc-editor.org/rfc/rfc8852.html RFC 8852: RTP Stream Identifier Source Description (SDES)
public record RepairedRtpStreamId(String value) implements HeaderExtension {
    /// Validates the length.
    ///
    /// @throws IllegalArgumentException if the identifier is empty or longer than 255 UTF-8 bytes
    public RepairedRtpStreamId {
        ExtensionCodec.identifierBytes(java.util.Objects.requireNonNull(value, "value cannot be null"), "repaired rid");
    }

    /// Parses an element value.
    ///
    /// @param value the element value between position and limit; the position is advanced to the limit
    /// @return the identifier
    /// @throws RtpFormatException if the value is empty or only zero bytes
    public static RepairedRtpStreamId parse(ByteBuffer value) throws RtpFormatException {
        return new RepairedRtpStreamId(ExtensionCodec.readIdentifier(value, "repaired rid"));
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.REPAIRED_RTP_STREAM_ID;
    }

    @Override
    public int encodedLength() {
        return ExtensionCodec.identifierBytes(value, "repaired rid").length;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        var bytes = ExtensionCodec.identifierBytes(value, "repaired rid");
        ExtensionCodec.checkRoom(destination, bytes.length);
        destination.put(bytes);
    }
}
