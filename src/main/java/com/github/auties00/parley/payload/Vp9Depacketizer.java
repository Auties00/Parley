package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.media.Vp9FrameMetadata;
import com.github.auties00.parley.media.Vp9ScalabilityStructure;
import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// The VP9 depacketizer of RFC 9628.
///
/// A frame is one layer frame, from the packet with the `B` bit to the one with the `E` bit. It is a keyframe when it
/// is neither inter-picture nor inter-layer predicted. Its resolution comes from the scalability structure (the
/// latest one the stream carried, for the frame's spatial layer) or, for a keyframe, from the VP9 uncompressed
/// header.
///
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
/// @spec https://storage.googleapis.com/downloads.webmproject.org/docs/vp9/vp9-bitstream-specification-v0.6-20160331-draft.pdf VP9 Bitstream and Decoding Process Specification
final class Vp9Depacketizer implements Depacketizer {
    /// The latest scalability structure of the stream.
    private Optional<Vp9ScalabilityStructure> structure = Optional.empty();

    @Override
    public PacketBoundaries inspect(RtpPacket packet) {
        Vp9Descriptor descriptor;
        try {
            descriptor = Vp9Descriptor.parse(packet.payload());
        } catch (PayloadFormatException exception) {
            return PacketBoundaries.invalid();
        }
        var keyframe = descriptor.begin() && !descriptor.interPicturePredicted() && !descriptor.interLayerPredicted();
        return new PacketBoundaries(true, descriptor.begin(), descriptor.end(), true, keyframe,
                descriptor.spatialId(), descriptor.temporalId());
    }

    @Override
    public EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException {
        Payloads.checkRun(packetsOfOneFrame);
        // One pass finds the descriptors and the frame size, the second copies each payload once into the frame
        var count = packetsOfOneFrame.size();
        var payloads = new ByteBuffer[count];
        var skips = new int[count];
        var total = 0;
        Vp9Descriptor first = null;
        Vp9Descriptor last = null;
        for (var index = 0; index < count; index++) {
            var payload = packetsOfOneFrame.get(index).payload();
            var descriptor = Vp9Descriptor.parse(payload);
            if (first == null) {
                if (!descriptor.begin()) {
                    throw new PayloadFormatException("VP9 layer frame without its beginning");
                }
                first = descriptor;
            }
            last = descriptor;
            payloads[index] = payload;
            skips[index] = descriptor.size();
            total += payload.remaining() - descriptor.size();
        }
        if (!last.end()) {
            throw new PayloadFormatException("VP9 layer frame without its end");
        }
        if (first.structure().isPresent()) {
            structure = first.structure();
        }
        var data = Payloads.join(payloads, skips, total);
        var keyframe = !first.interPicturePredicted() && !first.interLayerPredicted();
        var spatialId = first.spatialId();
        var resolution = structure
                .filter(value -> value.resolutions().size() > spatialId)
                .map(value -> value.resolutions().get(spatialId));
        if (resolution.isEmpty() && !first.interPicturePredicted()) {
            resolution = keyframeResolution(data);
        }
        var layered = first.layered();
        var metadata = new Vp9FrameMetadata(first.pictureId(), first.tl0PicIndex(),
                layered ? OptionalInt.of(first.spatialId()) : OptionalInt.empty(),
                layered ? OptionalInt.of(first.temporalId()) : OptionalInt.empty(), first.switchingUpPoint(),
                first.interLayerPredicted(), first.interPicturePredicted(), first.notUpperReference(),
                first.flexible(), first.flexible() ? first.referenceDiffs() : List.of(), first.structure(),
                packetsOfOneFrame.getLast().marker(), resolution, OptionalLong.empty(), List.of());
        return new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), packetsOfOneFrame.getFirst().timestamp(),
                keyframe, Optional.empty(), metadata);
    }

    /// {@return the frame size of a VP9 key frame's uncompressed header, or empty for any other frame}
    static Optional<Resolution> keyframeResolution(byte[] data) {
        try {
            var reader = new BitReader(data, 0, data.length);
            if (reader.bits(2) != 2) {
                return Optional.empty();
            }
            var low = reader.bit();
            var profile = reader.bit() << 1 | low;
            if (profile == 3) {
                reader.skip(1);
            }
            if (reader.flag() || reader.flag()) {
                return Optional.empty();
            }
            reader.skip(2);
            if (reader.bits(24) != 0x498342) {
                return Optional.empty();
            }
            if (profile >= 2) {
                reader.skip(1);
            }
            var colorSpace = reader.bits(3);
            if (colorSpace != 7) {
                reader.skip(1);
                if (profile == 1 || profile == 3) {
                    reader.skip(3);
                }
            } else if (profile == 1 || profile == 3) {
                reader.skip(1);
            }
            var width = reader.bits(16) + 1;
            var height = reader.bits(16) + 1;
            return NalUnits.resolution(width, height);
        } catch (IndexOutOfBoundsException exception) {
            return Optional.empty();
        }
    }
}
