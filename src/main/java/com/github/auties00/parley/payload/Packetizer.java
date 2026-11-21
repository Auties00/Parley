package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;

import java.util.List;

/// Splits encoded frames into RTP payloads, writing the payload format's descriptors.
///
/// A packetizer belongs to one outgoing RTP stream: formats that number pictures (VP8, VP9) or remember parameter
/// sets (H.264, H.265) keep that state across frames, so frames must be passed in send order. A packetizer is not
/// safe for concurrent use.
public interface Packetizer {
    /// Splits a frame into RTP payloads.
    ///
    /// Every payload fits the configured maximum size. The last payload carries the marker bit when the format puts it
    /// at the end of a frame (for VP9, only at the end of a picture; for audio, on the first packet of a talkspurt
    /// instead). Payloads are read-only slices of the frame's bytes where the format allows, so the frame must stay
    /// unchanged until the payloads are sent.
    ///
    /// @param frame the frame, of the kind of the packetizer's format
    /// @return the payloads in send order, at least one
    /// @throws IllegalArgumentException if the frame is of another kind, or its bytes or metadata violate the format
    ///                                  (an H.264 NAL unit too large for packetization mode 0, an audio frame larger
    ///                                  than one payload, an AV1 OBU that does not parse)
    List<PacketizedPayload> packetize(EncodedFrame frame);
}
