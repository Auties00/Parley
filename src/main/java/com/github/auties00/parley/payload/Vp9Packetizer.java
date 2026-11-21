package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Vp9FrameMetadata;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.concurrent.ThreadLocalRandom;

/// The VP9 packetizer of RFC 9628.
///
/// Each frame is one layer frame. The descriptor comes from the frame's
/// [Vp9FrameMetadata][com.github.auties00.parley.media.Vp9FrameMetadata]: a 15-bit picture id (the frame's own, or
/// one the packetizer numbers per picture from a random start), the layer indices when the metadata has them, the
/// `TL0PICIDX` of a layered non-flexible stream (generated when absent), the reference differences in flexible mode,
/// and the scalability structure on the first packet. A frame without VP9 metadata is sent as a single-layer
/// flexible frame that references the previous picture unless it is a keyframe. The marker bit closes a picture: it
/// is set on the last packet of a frame whose metadata has `endOfPicture`.
///
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
final class Vp9Packetizer implements Packetizer {
    /// The largest payload.
    private final int maxPayloadSize;

    /// The picture id of the next picture without one.
    private int nextPictureId;

    /// The picture id of the picture in progress.
    private int currentPictureId;

    /// Whether the previous frame closed its picture.
    private boolean pictureClosed = true;

    /// The last generated `TL0PICIDX`.
    private int tl0PicIndex;

    /// Creates a packetizer.
    Vp9Packetizer(PacketizerConfig config) {
        this.maxPayloadSize = config.maxPayloadSize();
        this.nextPictureId = ThreadLocalRandom.current().nextInt(0x8000);
        this.tl0PicIndex = ThreadLocalRandom.current().nextInt(0x100);
    }

    @Override
    public List<PacketizedPayload> packetize(EncodedFrame frame) {
        Payloads.checkKind(frame, MediaKind.VIDEO);
        var data = frame.data();
        if (!data.hasRemaining()) {
            throw new IllegalArgumentException("empty VP9 frame");
        }
        var metadata = frame.metadata() instanceof Vp9FrameMetadata vp9 ? vp9 : defaultMetadata(frame.keyframe());
        if (metadata.flexibleMode() && metadata.interPicturePredicted() && metadata.referenceDiffs().isEmpty()) {
            throw new IllegalArgumentException("a predicted flexible-mode VP9 frame needs reference differences");
        }
        var newPicture = pictureClosed;
        if (metadata.pictureId().isPresent()) {
            currentPictureId = metadata.pictureId().getAsInt();
            nextPictureId = (currentPictureId + 1) & 0x7FFF;
        } else if (newPicture) {
            currentPictureId = nextPictureId;
            nextPictureId = (nextPictureId + 1) & 0x7FFF;
        }
        pictureClosed = metadata.endOfPicture();
        var layered = metadata.spatialId().isPresent() || metadata.temporalId().isPresent();
        var tl0 = OptionalInt.empty();
        if (layered && !metadata.flexibleMode()) {
            if (metadata.tl0PicIndex().isPresent()) {
                tl0PicIndex = metadata.tl0PicIndex().getAsInt();
            } else if (newPicture && metadata.temporalId().orElse(0) == 0) {
                tl0PicIndex = (tl0PicIndex + 1) & 0xFF;
            }
            tl0 = OptionalInt.of(tl0PicIndex);
        }
        var baseSize = 1 + 2 + (layered ? 1 : 0) + (tl0.isPresent() ? 1 : 0)
                + (metadata.flexibleMode() && metadata.interPicturePredicted() ? metadata.referenceDiffs().size() : 0);
        var structureSize = metadata.scalabilityStructure().map(Vp9Descriptor::sizeOf).orElse(0);
        var firstCapacity = maxPayloadSize - baseSize - structureSize;
        if (firstCapacity <= 0) {
            throw new IllegalArgumentException("VP9 scalability structure does not fit the payload size");
        }
        var fragments = new ArrayList<ByteBuffer>();
        var first = data.slice(data.position(), Math.min(firstCapacity, data.remaining()));
        fragments.add(first);
        var rest = data.slice(data.position() + first.remaining(), data.remaining() - first.remaining());
        if (rest.hasRemaining()) {
            fragments.addAll(Payloads.split(rest, maxPayloadSize - baseSize));
        }
        var result = new ArrayList<PacketizedPayload>(fragments.size());
        for (var k = 0; k < fragments.size(); k++) {
            var fragment = fragments.get(k);
            var begin = k == 0;
            var end = k == fragments.size() - 1;
            var out = ByteBuffer.allocate(baseSize + (begin ? structureSize : 0) + fragment.remaining());
            writeDescriptor(out, metadata, begin, end, layered, tl0, begin && structureSize > 0);
            out.put(fragment);
            result.add(PacketizedPayload.of(out.flip(), end && metadata.endOfPicture()));
        }
        return List.copyOf(result);
    }

    /// Writes the descriptor of one packet.
    private void writeDescriptor(ByteBuffer out, Vp9FrameMetadata metadata, boolean begin, boolean end,
                                 boolean layered, OptionalInt tl0, boolean structure) {
        var predicted = metadata.interPicturePredicted();
        out.put((byte) (0x80 | (predicted ? 0x40 : 0) | (layered ? 0x20 : 0) | (metadata.flexibleMode() ? 0x10 : 0)
                | (begin ? 0x08 : 0) | (end ? 0x04 : 0) | (structure ? 0x02 : 0)
                | (metadata.notUpperLayerReference() ? 0x01 : 0)));
        out.putShort((short) (0x8000 | currentPictureId));
        if (layered) {
            out.put((byte) (metadata.temporalId().orElse(0) << 5 | (metadata.switchingUpPoint() ? 0x10 : 0)
                    | metadata.spatialId().orElse(0) << 1 | (metadata.interLayerPredicted() ? 0x01 : 0)));
            if (tl0.isPresent()) {
                out.put((byte) tl0.getAsInt());
            }
        }
        if (metadata.flexibleMode() && predicted) {
            var diffs = metadata.referenceDiffs();
            for (var i = 0; i < diffs.size(); i++) {
                out.put((byte) (diffs.get(i) << 1 | (i < diffs.size() - 1 ? 1 : 0)));
            }
        }
        if (structure) {
            Vp9Descriptor.writeStructure(out, metadata.scalabilityStructure().orElseThrow());
        }
    }

    /// {@return the metadata of a frame that has none: one flexible-mode layer referencing the previous picture}
    private static Vp9FrameMetadata defaultMetadata(boolean keyframe) {
        return new Vp9FrameMetadata(OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(),
                OptionalInt.empty(), false, false, !keyframe, false, true, keyframe ? List.of() : List.of(1),
                Optional.empty(), true, Optional.empty(), OptionalLong.empty(), List.of());
    }
}
