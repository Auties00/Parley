package com.github.auties00.parley.payload;

/// What one RTP packet says about the frame it belongs to, read by [Depacketizer#inspect(com.github.auties00.parley.rtp.RtpPacket)]
/// without assembling the frame: whether it starts or ends a frame, whether that frame is a keyframe, and its layers.
///
/// A jitter buffer groups packets into frames with it, and an SFU decides with it which packets to forward.
///
/// @param valid             whether the packet follows its payload format; every other component is meaningless
///                          when `false`
/// @param frameStart        whether the packet starts a frame, as far as the payload tells
/// @param frameEnd          whether the packet ends a frame: an end bit of the payload descriptor or the dependency
///                          descriptor, else the RTP marker bit
/// @param explicitStart     whether `frameStart` comes from a start bit the format defines (VP8, VP9, a dependency
///                          descriptor); when `false` it is a guess from the payload (the first slice of an H.264
///                          picture), and the receiver also needs the end of the previous frame to place the start
/// @param keyframe          whether the packet belongs to a keyframe, as far as this one packet tells (always `true`
///                          for audio)
/// @param spatialId         the spatial layer of the frame, `0` when the format or stream has none
/// @param temporalId        the temporal layer of the frame, `0` when the format or stream has none
public record PacketBoundaries(boolean valid, boolean frameStart, boolean frameEnd, boolean explicitStart,
                               boolean keyframe, int spatialId, int temporalId) {
    /// The boundaries of a packet that does not follow its format.
    private static final PacketBoundaries INVALID = new PacketBoundaries(false, false, false, false, false, 0, 0);

    /// Creates boundaries.
    ///
    /// @param valid         the validity
    /// @param frameStart    the start flag
    /// @param frameEnd      the end flag
    /// @param explicitStart whether the start flag is explicit
    /// @param keyframe      the keyframe flag
    /// @param spatialId     the spatial layer
    /// @param temporalId    the temporal layer
    /// @throws IllegalArgumentException if a layer is negative
    public PacketBoundaries {
        if (spatialId < 0 || temporalId < 0) {
            throw new IllegalArgumentException("negative layer id");
        }
    }

    /// {@return the boundaries of a packet that does not follow its payload format}
    public static PacketBoundaries invalid() {
        return INVALID;
    }

    /// {@return the boundaries of a packet that is a frame on its own, as every audio packet is}
    ///
    /// @param keyframe whether the frame is a keyframe
    public static PacketBoundaries singlePacket(boolean keyframe) {
        return new PacketBoundaries(true, true, true, true, keyframe, 0, 0);
    }
}
