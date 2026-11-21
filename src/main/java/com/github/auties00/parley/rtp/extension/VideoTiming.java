package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The timing of a video frame's way through the sender, each a delta in milliseconds from the frame's capture
/// time, which a receiver uses to break end-to-end delay down by stage.
///
/// ```text
/// | flags | encode start | encode finish | packetization finish | pacer exit | network ts | network2 ts |
/// |  1 B  |     2 B      |      2 B      |          2 B         |    2 B     |    2 B     |     2 B     |
/// ```
///
/// A 12-byte value without the flags byte, the older form, is also accepted.
///
/// @param flags                      the flags: bit 0 set when the frame was timed because of a timer, bit 1 when
///                                   because it was outsized
/// @param encodeStartDelta           the encode start, `0..65535` ms after capture
/// @param encodeFinishDelta          the encode finish, `0..65535` ms after capture
/// @param packetizationFinishDelta   the packetization finish, `0..65535` ms after capture
/// @param pacerExitDelta             the pacer exit of the last packet, `0..65535` ms after capture
/// @param networkTimestampDelta      a value reserved for a network element, `0..65535`
/// @param network2TimestampDelta     a second value reserved for a network element, `0..65535`
/// @spec https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/video-timing/README.md WebRTC: Video Timing
public record VideoTiming(int flags, int encodeStartDelta, int encodeFinishDelta, int packetizationFinishDelta,
                          int pacerExitDelta, int networkTimestampDelta, int network2TimestampDelta)
        implements HeaderExtension {
    /// The encoded length.
    public static final int LENGTH = 13;

    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if a field is out of range
    public VideoTiming {
        if (flags < 0 || flags > 255) {
            throw new IllegalArgumentException("flags must be in 0..255: " + flags);
        }
        for (var delta : new int[]{encodeStartDelta, encodeFinishDelta, packetizationFinishDelta, pacerExitDelta,
                networkTimestampDelta, network2TimestampDelta}) {
            if (delta < 0 || delta > 0xFFFF) {
                throw new IllegalArgumentException("deltas must be in 0..65535: " + delta);
            }
        }
    }

    /// Parses an element value of 13 bytes, or 12 in the older form without flags.
    ///
    /// @param value the element value; the position is advanced past the bytes read
    /// @return the timing
    /// @throws RtpFormatException if the value is shorter than 12 bytes
    public static VideoTiming parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, 12, "video-timing");
        var flags = value.remaining() >= LENGTH ? value.get() & 0xFF : 0;
        return new VideoTiming(flags, value.getShort() & 0xFFFF, value.getShort() & 0xFFFF,
                value.getShort() & 0xFFFF, value.getShort() & 0xFFFF, value.getShort() & 0xFFFF,
                value.getShort() & 0xFFFF);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.VIDEO_TIMING;
    }

    @Override
    public int encodedLength() {
        return LENGTH;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, LENGTH);
        destination.put((byte) flags);
        destination.putShort((short) encodeStartDelta);
        destination.putShort((short) encodeFinishDelta);
        destination.putShort((short) packetizationFinishDelta);
        destination.putShort((short) pacerExitDelta);
        destination.putShort((short) networkTimestampDelta);
        destination.putShort((short) network2TimestampDelta);
    }
}
