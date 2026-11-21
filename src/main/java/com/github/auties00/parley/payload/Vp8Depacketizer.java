package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.rtp.RtpPacket;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/// The VP8 depacketizer of RFC 7741.
///
/// A frame starts at a packet with the `S` bit in partition `0` and ends at the marker bit. A keyframe is recognised
/// from the inverse key frame flag of the VP8 frame tag, and its size read from the key frame header.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html RFC 7741: RTP Payload Format for VP8 Video
/// @spec https://www.rfc-editor.org/rfc/rfc6386.html RFC 6386: VP8 Data Format and Decoding Guide
final class Vp8Depacketizer implements Depacketizer {
    @Override
    public PacketBoundaries inspect(RtpPacket packet) {
        var payload = packet.payload();
        Vp8Descriptor descriptor;
        try {
            descriptor = Vp8Descriptor.parse(payload);
        } catch (PayloadFormatException exception) {
            return PacketBoundaries.invalid();
        }
        var start = descriptor.startOfPartition() && descriptor.partitionIndex() == 0;
        var keyframe = start && (payload.get(payload.position() + descriptor.size()) & 0x01) == 0;
        return new PacketBoundaries(true, start, packet.marker(), true, keyframe, 0,
                descriptor.temporalId().orElse(0));
    }

    @Override
    public EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException {
        Payloads.checkRun(packetsOfOneFrame);
        var out = new ByteArrayOutputStream();
        Vp8Descriptor first = null;
        for (var packet : packetsOfOneFrame) {
            var payload = packet.payload();
            var descriptor = Vp8Descriptor.parse(payload);
            if (first == null) {
                if (!descriptor.startOfPartition() || descriptor.partitionIndex() != 0) {
                    throw new PayloadFormatException("VP8 frame does not start at partition 0");
                }
                first = descriptor;
            }
            var bytes = new byte[payload.remaining() - descriptor.size()];
            payload.get(payload.position() + descriptor.size(), bytes);
            out.writeBytes(bytes);
        }
        var data = out.toByteArray();
        var keyframe = (data[0] & 0x01) == 0;
        var resolution = keyframe ? keyframeResolution(data) : Optional.<Resolution>empty();
        var metadata = new Vp8FrameMetadata(first.pictureId(), first.tl0PicIndex(), first.temporalId(),
                first.layerSync(), first.keyIndex(), first.nonReference(), resolution, OptionalLong.empty(), List.of());
        return new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), packetsOfOneFrame.getFirst().timestamp(),
                keyframe, Optional.empty(), metadata);
    }

    /// {@return the size in a VP8 key frame header, after the three-byte frame tag and the `9d 01 2a` start code}
    static Optional<Resolution> keyframeResolution(byte[] data) {
        if (data.length < 10 || (data[3] & 0xFF) != 0x9D || (data[4] & 0xFF) != 0x01 || (data[5] & 0xFF) != 0x2A) {
            return Optional.empty();
        }
        var width = ((data[7] & 0xFF) << 8 | (data[6] & 0xFF)) & 0x3FFF;
        var height = ((data[9] & 0xFF) << 8 | (data[8] & 0xFF)) & 0x3FFF;
        return NalUnits.resolution(width, height);
    }
}
