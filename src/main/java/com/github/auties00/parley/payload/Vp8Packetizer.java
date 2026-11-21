package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Vp8FrameMetadata;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.ThreadLocalRandom;

/// The VP8 packetizer of RFC 7741.
///
/// Every packet carries a 15-bit picture id, the frame's own or one the packetizer numbers from a random start; a
/// temporally layered frame also carries its `TID`, `Y` and `TL0PICIDX`, the latter generated (incremented on each
/// base layer frame) when the metadata has none. The frame is split into fragments of nearly equal size, the first
/// with the `S` bit, all in partition `0`.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html RFC 7741: RTP Payload Format for VP8 Video
final class Vp8Packetizer implements Packetizer {
    /// The largest payload.
    private final int maxPayloadSize;

    /// The picture id of the next frame without one.
    private int nextPictureId;

    /// The last generated `TL0PICIDX`.
    private int tl0PicIndex;

    /// Creates a packetizer.
    Vp8Packetizer(PacketizerConfig config) {
        this.maxPayloadSize = config.maxPayloadSize();
        this.nextPictureId = ThreadLocalRandom.current().nextInt(0x8000);
        this.tl0PicIndex = ThreadLocalRandom.current().nextInt(0x100);
    }

    @Override
    public List<PacketizedPayload> packetize(EncodedFrame frame) {
        Payloads.checkKind(frame, MediaKind.VIDEO);
        var data = frame.data();
        if (!data.hasRemaining()) {
            throw new IllegalArgumentException("empty VP8 frame");
        }
        var metadata = frame.metadata() instanceof Vp8FrameMetadata vp8 ? vp8 : Vp8FrameMetadata.none();
        var pictureId = metadata.pictureId().orElse(nextPictureId);
        var shortPictureId = metadata.pictureId().isPresent() && metadata.pictureIdBits() == 7;
        nextPictureId = (pictureId + 1) & 0x7FFF;
        var tl0 = metadata.tl0PicIndex();
        if (tl0.isEmpty() && metadata.temporalId().isPresent()) {
            if (metadata.temporalId().getAsInt() == 0) {
                tl0PicIndex = (tl0PicIndex + 1) & 0xFF;
            }
            tl0 = OptionalInt.of(tl0PicIndex);
        } else if (tl0.isPresent()) {
            tl0PicIndex = tl0.getAsInt();
        }
        var descriptorSize = Vp8Descriptor.sizeOf(true, shortPictureId, tl0.isPresent(),
                metadata.temporalId().isPresent() || metadata.keyIndex().isPresent());
        var fragments = Payloads.split(data, maxPayloadSize - descriptorSize);
        var result = new ArrayList<PacketizedPayload>(fragments.size());
        for (var k = 0; k < fragments.size(); k++) {
            var fragment = fragments.get(k);
            var out = ByteBuffer.allocate(descriptorSize + fragment.remaining());
            Vp8Descriptor.write(out, metadata.nonReference(), k == 0, OptionalInt.of(pictureId), shortPictureId, tl0,
                    metadata.temporalId(), metadata.layerSync(), metadata.keyIndex());
            out.put(fragment);
            result.add(PacketizedPayload.of(out.flip(), k == fragments.size() - 1));
        }
        return List.copyOf(result);
    }
}
