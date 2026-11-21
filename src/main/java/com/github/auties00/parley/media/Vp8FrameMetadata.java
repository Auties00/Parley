package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// The metadata of a VP8 frame: the fields of the RFC 7741 payload descriptor, plus the resolution of a keyframe and
/// the references the receiver resolved.
///
/// @param pictureId    the picture id, `0..32767` (a 7-bit id is `0..127`), or an empty optional when absent; a
///                     packetizer generates one when empty
/// @param pictureIdBits the width of the picture id field, `7` or `15`: the `M` bit of the descriptor on the receive
///                     side, the width the packetizer writes on the send side (`15` for a generated id); a
///                     receiver unwraps the id modulo `2^pictureIdBits`
/// @param tl0PicIndex  the `TL0PICIDX`, the running index of the base temporal layer frames, `0..255`, or an empty
///                     optional when absent
/// @param temporalId   the temporal layer, `0..3`, or an empty optional when the stream is not layered
/// @param layerSync    the `Y` bit: the frame depends only on base layer frames, so a receiver may switch up to its
///                     temporal layer here
/// @param keyIndex     the `KEYIDX`, `0..31`, or an empty optional when absent
/// @param nonReference the `N` bit: no other frame references this one, so it may be dropped
/// @param resolution   the picture size, known for a keyframe
/// @param frameId      the frame id the receiver assigned, or an empty optional on the send side
/// @param dependencies the frame ids this frame references, unmodifiable
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html RFC 7741: RTP Payload Format for VP8 Video
public record Vp8FrameMetadata(OptionalInt pictureId, int pictureIdBits, OptionalInt tl0PicIndex,
                               OptionalInt temporalId,
                               boolean layerSync, OptionalInt keyIndex, boolean nonReference,
                               Optional<Resolution> resolution, OptionalLong frameId, List<Long> dependencies)
        implements FrameMetadata {
    /// Metadata with every field absent.
    private static final Vp8FrameMetadata NONE = new Vp8FrameMetadata(OptionalInt.empty(), 15, OptionalInt.empty(),
            OptionalInt.empty(), false, OptionalInt.empty(), false, Optional.empty(), OptionalLong.empty(), List.of());

    /// Creates VP8 metadata.
    ///
    /// @param pictureId    the picture id
    /// @param pictureIdBits the picture id width
    /// @param tl0PicIndex  the base layer index
    /// @param temporalId   the temporal layer
    /// @param layerSync    the layer sync bit
    /// @param keyIndex     the key index
    /// @param nonReference the non-reference bit
    /// @param resolution   the resolution
    /// @param frameId      the frame id
    /// @param dependencies the dependencies, copied
    /// @throws IllegalArgumentException if a field is out of its range, `pictureIdBits` is neither `7` nor `15`, a
    ///                                  7-bit picture id is above `127`, or a dependency is negative or not below
    ///                                  `frameId`
    public Vp8FrameMetadata {
        if (pictureIdBits != 7 && pictureIdBits != 15) {
            throw new IllegalArgumentException("pictureIdBits must be 7 or 15: " + pictureIdBits);
        }
        MetadataChecks.checkRange(pictureId, (1 << pictureIdBits) - 1, "pictureId");
        MetadataChecks.checkRange(tl0PicIndex, 0xFF, "tl0PicIndex");
        MetadataChecks.checkRange(temporalId, 3, "temporalId");
        MetadataChecks.checkRange(keyIndex, 31, "keyIndex");
        Objects.requireNonNull(resolution, "resolution cannot be null");
        dependencies = MetadataChecks.checkDependencies(frameId, dependencies);
    }

    /// {@return metadata with every field absent, which lets the packetizer generate the picture id}
    public static Vp8FrameMetadata none() {
        return NONE;
    }

    /// {@return metadata of a temporally layered frame}
    ///
    /// @param temporalId the temporal layer, `0..3`
    /// @param layerSync  whether the frame references only base layer frames
    /// @throws IllegalArgumentException if `temporalId` is outside `0..3`
    public static Vp8FrameMetadata ofTemporalLayer(int temporalId, boolean layerSync) {
        return new Vp8FrameMetadata(OptionalInt.empty(), 15, OptionalInt.empty(), OptionalInt.of(temporalId),
                layerSync, OptionalInt.empty(), false, Optional.empty(), OptionalLong.empty(), List.of());
    }

    @Override
    public Vp8FrameMetadata withDependencies(long frameId, List<Long> dependencies) {
        return new Vp8FrameMetadata(pictureId, pictureIdBits, tl0PicIndex, temporalId, layerSync, keyIndex,
                nonReference, resolution, OptionalLong.of(frameId), dependencies);
    }

    /// {@return a copy with a 15-bit picture id and a base layer index}
    ///
    /// @param pictureId   the picture id, `0..32767`
    /// @param tl0PicIndex the base layer index, `0..255`, or an empty optional for none
    /// @throws IllegalArgumentException if a value is out of range
    public Vp8FrameMetadata withPictureId(int pictureId, OptionalInt tl0PicIndex) {
        return new Vp8FrameMetadata(OptionalInt.of(pictureId), 15, tl0PicIndex, temporalId, layerSync, keyIndex,
                nonReference, resolution, frameId, dependencies);
    }

    /// {@return a copy with a 7-bit picture id, which the packetizer writes in the one-byte field}
    ///
    /// @param pictureId the picture id, `0..127`
    /// @throws IllegalArgumentException if `pictureId` is outside `0..127`
    public Vp8FrameMetadata withShortPictureId(int pictureId) {
        return new Vp8FrameMetadata(OptionalInt.of(pictureId), 7, tl0PicIndex, temporalId, layerSync, keyIndex,
                nonReference, resolution, frameId, dependencies);
    }

    /// {@return [MediaKind#VIDEO]}
    @Override
    public MediaKind kind() {
        return MediaKind.VIDEO;
    }
}
