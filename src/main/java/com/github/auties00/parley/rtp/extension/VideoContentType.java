package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The kind of video content, which lets a receiver tune its jitter buffer and statistics for screen sharing.
///
/// @param value the content type byte: [#UNSPECIFIED], [#SCREENSHARE], or another value kept as received
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/video-content-type/README.md WebRTC: Video Content Type
public record VideoContentType(int value) implements HeaderExtension {
    /// The content type of camera or unknown video.
    public static final int UNSPECIFIED = 0;
    /// The content type of screen sharing.
    public static final int SCREENSHARE = 1;

    /// Validates the range.
    ///
    /// @throws IllegalArgumentException if `value` is not a byte value
    public VideoContentType {
        if (value < 0 || value > 255) {
            throw new IllegalArgumentException("value must be in 0..255: " + value);
        }
    }

    /// {@return whether the content is a screen share}
    public boolean isScreenshare() {
        return value == SCREENSHARE;
    }

    /// Parses an element value.
    ///
    /// @param value the element value; the position is advanced past the byte read
    /// @return the content type
    /// @throws RtpFormatException if the value is empty
    public static VideoContentType parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, 1, "video-content-type");
        return new VideoContentType(value.get() & 0xFF);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.VIDEO_CONTENT_TYPE;
    }

    @Override
    public int encodedLength() {
        return 1;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, 1);
        destination.put((byte) value);
    }
}
