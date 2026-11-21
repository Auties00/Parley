package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The media identification (`a=mid`) of the m-section a packet belongs to, which routes it to its receiver in a BUNDLE group.
///
/// The value is the identifier's UTF-8 bytes, without terminator; trailing zero bytes some senders pad it with are
/// removed when parsing.
///
/// @param value the identifier, 1 to 255 UTF-8 bytes (at most 16 in the one-byte element form)
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
public record Mid(String value) implements HeaderExtension {
    /// Validates the length.
    ///
    /// @throws IllegalArgumentException if the identifier is empty or longer than 255 UTF-8 bytes
    public Mid {
        ExtensionCodec.identifierBytes(java.util.Objects.requireNonNull(value, "value cannot be null"), "mid");
    }

    /// Parses an element value.
    ///
    /// @param value the element value between position and limit; the position is advanced to the limit
    /// @return the identifier
    /// @throws RtpFormatException if the value is empty or only zero bytes
    public static Mid parse(ByteBuffer value) throws RtpFormatException {
        return new Mid(ExtensionCodec.readIdentifier(value, "mid"));
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.MID;
    }

    @Override
    public int encodedLength() {
        return ExtensionCodec.identifierBytes(value, "mid").length;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        var bytes = ExtensionCodec.identifierBytes(value, "mid");
        ExtensionCodec.checkRoom(destination, bytes.length);
        destination.put(bytes);
    }
}
