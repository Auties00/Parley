package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// The metadata of an H.265 access unit: the NAL unit types it carries, whether it is an intra random access point,
/// its temporal sub-layer, the resolution its sequence parameter set declares, and the references the receiver
/// resolved.
///
/// @param irap         whether the access unit contains an IRAP picture (NAL unit types `16..23`)
/// @param temporalId   the temporal sub-layer of the access unit, `TemporalId` of its NAL unit headers, `0..6`
/// @param nalUnitTypes the type of each NAL unit in order, each `0..63`; unmodifiable
/// @param resolution   the picture size from a sequence parameter set in the access unit or an earlier one
/// @param frameId      the frame id the receiver assigned, or an empty optional on the send side
/// @param dependencies the frame ids this frame references, unmodifiable
/// @spec https://www.rfc-editor.org/rfc/rfc7798.html RFC 7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
/// @spec https://www.itu.int/rec/T-REC-H.265 ITU-T H.265: High efficiency video coding
public record H265FrameMetadata(boolean irap, int temporalId, List<Integer> nalUnitTypes,
                                Optional<Resolution> resolution, OptionalLong frameId, List<Long> dependencies)
        implements FrameMetadata {
    /// Metadata that knows nothing about the access unit.
    private static final H265FrameMetadata NONE = new H265FrameMetadata(false, 0, List.of(), Optional.empty(),
            OptionalLong.empty(), List.of());

    /// Creates H.265 metadata.
    ///
    /// @param irap         the IRAP flag
    /// @param temporalId   the temporal sub-layer
    /// @param nalUnitTypes the NAL unit types, copied
    /// @param resolution   the resolution
    /// @param frameId      the frame id
    /// @param dependencies the dependencies, copied
    /// @throws IllegalArgumentException if a field is out of its range, or a dependency is negative or not below
    ///                                  `frameId`
    public H265FrameMetadata {
        MetadataChecks.checkRange(temporalId, 6, "temporalId");
        nalUnitTypes = List.copyOf(nalUnitTypes);
        for (var type : nalUnitTypes) {
            MetadataChecks.checkRange(type, 63, "nal unit type");
        }
        Objects.requireNonNull(resolution, "resolution cannot be null");
        dependencies = MetadataChecks.checkDependencies(frameId, dependencies);
    }

    /// {@return metadata that knows nothing about the access unit; a packetizer reads what it needs from the bytes}
    public static H265FrameMetadata none() {
        return NONE;
    }

    /// {@return a copy with a frame id and the frame ids it references}
    ///
    /// @param frameId      the frame id, non-negative
    /// @param dependencies the referenced frame ids, each below `frameId`
    /// @throws IllegalArgumentException if a dependency is negative or not below `frameId`
    @Override
    public H265FrameMetadata withDependencies(long frameId, List<Long> dependencies) {
        return new H265FrameMetadata(irap, temporalId, nalUnitTypes, resolution, OptionalLong.of(frameId),
                dependencies);
    }

    /// {@return [MediaKind#VIDEO]}
    @Override
    public MediaKind kind() {
        return MediaKind.VIDEO;
    }
}
