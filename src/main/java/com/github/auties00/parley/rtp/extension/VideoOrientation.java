package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The coordination of video orientation (CVO): how the receiver must rotate and flip the decoded picture.
///
/// ```text
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |0 0 0 0 C F R R|
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// @param backCamera      whether the picture comes from a back-facing camera (`C`)
/// @param horizontalFlip  whether the picture must be flipped horizontally before rotation (`F`)
/// @param rotationDegrees the clockwise rotation to apply, `0`, `90`, `180` or `270`
/// @spec https://www.3gpp.org/ftp/Specs/archive/26_series/26.114/ 3GPP TS 26.114: IP Multimedia Subsystem (IMS); Multimedia telephony; Media handling and interaction
public record VideoOrientation(boolean backCamera, boolean horizontalFlip, int rotationDegrees)
        implements HeaderExtension {
    /// Validates the rotation.
    ///
    /// @throws IllegalArgumentException if `rotationDegrees` is not a multiple of 90 in `0..270`
    public VideoOrientation {
        if (rotationDegrees < 0 || rotationDegrees > 270 || rotationDegrees % 90 != 0) {
            throw new IllegalArgumentException("rotationDegrees must be 0, 90, 180 or 270: " + rotationDegrees);
        }
    }

    /// Parses an element value.
    ///
    /// @param value the element value; the position is advanced past the byte read
    /// @return the orientation
    /// @throws RtpFormatException if the value is empty
    public static VideoOrientation parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, 1, "video-orientation");
        var b = value.get() & 0xFF;
        return new VideoOrientation((b & 0x08) != 0, (b & 0x04) != 0, (b & 0x03) * 90);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.VIDEO_ORIENTATION;
    }

    @Override
    public int encodedLength() {
        return 1;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, 1);
        destination.put((byte) ((backCamera ? 0x08 : 0) | (horizontalFlip ? 0x04 : 0) | rotationDegrees / 90));
    }
}
