package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.rtp.RtpPacket;

import java.util.List;

/// Reads RTP payloads back into encoded frames.
///
/// A depacketizer belongs to one incoming RTP stream: some formats remember state across frames (the parameter sets
/// of H.264, the template structure of a dependency descriptor). It is not safe for concurrent use. It keeps no
/// reference to the packets passed to it, and the frames it assembles own their bytes.
public interface Depacketizer {
    /// Reads what one packet says about its frame, without assembling it.
    ///
    /// @param packet the packet
    /// @return the frame boundaries, keyframe flag and layers the packet carries; [PacketBoundaries#invalid()] when
    ///         the payload does not follow the format
    PacketBoundaries inspect(RtpPacket packet);

    /// Assembles one frame from all of its packets.
    ///
    /// The packets must be the complete frame in sequence number order: from the packet that starts it to the one
    /// that ends it, without gaps. The frame's RTP timestamp is the packets' timestamp.
    ///
    /// @param packetsOfOneFrame the packets, in sequence number order
    /// @return the frame, owning a copy of the media bytes, with the metadata the payloads carry
    /// @throws PayloadFormatException  if a payload does not follow the format, or the packets do not form one
    ///                                 complete frame (a fragment without its start, mixed timestamps)
    /// @throws IllegalArgumentException if `packetsOfOneFrame` is empty
    EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException;
}
