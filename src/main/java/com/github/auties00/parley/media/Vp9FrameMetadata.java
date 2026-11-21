package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// The metadata of one VP9 layer frame (the frame of one spatial layer of a picture): the fields of the RFC 9628
/// payload descriptor, plus the resolution of a keyframe and the references the receiver resolved.
///
/// @param pictureId              the picture id, `0..32767`, or an empty optional when absent; a packetizer generates
///                               one when empty
/// @param tl0PicIndex            the `TL0PICIDX` of a non-flexible stream, `0..255`, or an empty optional when absent
/// @param spatialId              the spatial layer, `0..7`, or an empty optional when the descriptor carries no layer
///                               indices
/// @param temporalId             the temporal layer, `0..7`, or an empty optional when the descriptor carries no layer
///                               indices
/// @param switchingUpPoint       the `U` bit: a receiver may switch up to this temporal layer here
/// @param interLayerPredicted    the `D` bit: the frame references the frame of the spatial layer below it in the same
///                               picture
/// @param interPicturePredicted  the `P` bit: the frame references earlier pictures; a frame without it, in the base
///                               spatial layer, starts a keyframe picture
/// @param notUpperLayerReference the `Z` bit: frames of higher spatial layers of the picture do not reference this one
/// @param flexibleMode           the `F` bit: references are explicit `referenceDiffs` instead of following the
///                               picture group of the scalability structure
/// @param referenceDiffs         in flexible mode, the differences between the picture id and those of the pictures
///                               this frame references, each `1..127`, at most three; unmodifiable
/// @param scalabilityStructure   the scalability structure the frame carries
/// @param endOfPicture           whether this is the last layer frame of its picture, which the marker bit of its last
///                               packet signals
/// @param resolution             the picture size, known for a keyframe or from a scalability structure
/// @param frameId                the frame id the receiver assigned, or an empty optional on the send side
/// @param dependencies           the frame ids this frame references, unmodifiable
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
public record Vp9FrameMetadata(OptionalInt pictureId, OptionalInt tl0PicIndex, OptionalInt spatialId,
                               OptionalInt temporalId, boolean switchingUpPoint, boolean interLayerPredicted,
                               boolean interPicturePredicted, boolean notUpperLayerReference, boolean flexibleMode,
                               List<Integer> referenceDiffs, Optional<Vp9ScalabilityStructure> scalabilityStructure,
                               boolean endOfPicture, Optional<Resolution> resolution, OptionalLong frameId,
                               List<Long> dependencies) implements FrameMetadata {
    /// Creates VP9 metadata.
    ///
    /// @param pictureId              the picture id
    /// @param tl0PicIndex            the base layer index
    /// @param spatialId              the spatial layer
    /// @param temporalId             the temporal layer
    /// @param switchingUpPoint       the `U` bit
    /// @param interLayerPredicted    the `D` bit
    /// @param interPicturePredicted  the `P` bit
    /// @param notUpperLayerReference the `Z` bit
    /// @param flexibleMode           the `F` bit
    /// @param referenceDiffs         the reference differences, copied
    /// @param scalabilityStructure   the scalability structure
    /// @param endOfPicture           whether the frame ends its picture
    /// @param resolution             the resolution
    /// @param frameId                the frame id
    /// @param dependencies           the dependencies, copied
    /// @throws IllegalArgumentException if a field is out of its range, reference differences are given outside
    ///                                  flexible mode or for a frame that is not inter-picture predicted, or a
    ///                                  dependency is negative or not below `frameId`
    public Vp9FrameMetadata {
        MetadataChecks.checkRange(pictureId, 0x7FFF, "pictureId");
        MetadataChecks.checkRange(tl0PicIndex, 0xFF, "tl0PicIndex");
        MetadataChecks.checkRange(spatialId, 7, "spatialId");
        MetadataChecks.checkRange(temporalId, 7, "temporalId");
        Objects.requireNonNull(scalabilityStructure, "scalabilityStructure cannot be null");
        Objects.requireNonNull(resolution, "resolution cannot be null");
        referenceDiffs = List.copyOf(referenceDiffs);
        if (referenceDiffs.size() > 3) {
            throw new IllegalArgumentException("at most 3 reference differences");
        }
        if (!referenceDiffs.isEmpty() && (!flexibleMode || !interPicturePredicted)) {
            throw new IllegalArgumentException("reference differences need flexible mode and inter-picture prediction");
        }
        for (var diff : referenceDiffs) {
            if (diff < 1 || diff > 127) {
                throw new IllegalArgumentException("reference difference out of range: " + diff);
            }
        }
        dependencies = MetadataChecks.checkDependencies(frameId, dependencies);
    }

    /// {@return metadata of a single-layer frame in flexible mode, the mode WebRTC endpoints send}
    ///
    /// @param interPicturePredicted whether the frame references earlier pictures; `false` for a keyframe
    /// @param referenceDiffs        the picture id differences of the referenced pictures, each `1..127`, at most
    ///                              three; empty when `interPicturePredicted` is `false`
    /// @throws IllegalArgumentException if the differences are out of range or given for a keyframe
    public static Vp9FrameMetadata ofFlexible(boolean interPicturePredicted, List<Integer> referenceDiffs) {
        return new Vp9FrameMetadata(OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(),
                OptionalInt.empty(), false, false, interPicturePredicted, false, true, referenceDiffs,
                Optional.empty(), true, Optional.empty(), OptionalLong.empty(), List.of());
    }

    /// {@return a copy with a frame id and the frame ids it references}
    ///
    /// @param frameId      the frame id, non-negative
    /// @param dependencies the referenced frame ids, each below `frameId`
    /// @throws IllegalArgumentException if a dependency is negative or not below `frameId`
    @Override
    public Vp9FrameMetadata withDependencies(long frameId, List<Long> dependencies) {
        return new Vp9FrameMetadata(pictureId, tl0PicIndex, spatialId, temporalId, switchingUpPoint,
                interLayerPredicted, interPicturePredicted, notUpperLayerReference, flexibleMode, referenceDiffs,
                scalabilityStructure, endOfPicture, resolution, OptionalLong.of(frameId), dependencies);
    }

    /// {@return a copy with a picture id and a base layer index}
    ///
    /// @param pictureId   the picture id, `0..32767`
    /// @param tl0PicIndex the base layer index, `0..255`, or an empty optional for none
    /// @throws IllegalArgumentException if a value is out of range
    public Vp9FrameMetadata withPictureId(int pictureId, OptionalInt tl0PicIndex) {
        return new Vp9FrameMetadata(OptionalInt.of(pictureId), tl0PicIndex, spatialId, temporalId, switchingUpPoint,
                interLayerPredicted, interPicturePredicted, notUpperLayerReference, flexibleMode, referenceDiffs,
                scalabilityStructure, endOfPicture, resolution, frameId, dependencies);
    }

    /// {@return [MediaKind#VIDEO]}
    @Override
    public MediaKind kind() {
        return MediaKind.VIDEO;
    }
}
