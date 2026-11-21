package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// The metadata of an H.264 access unit: the NAL unit types it carries, whether it is an IDR picture, the resolution
/// its sequence parameter set declares, and the references the receiver resolved.
///
/// @param idr          whether the access unit contains an IDR slice (NAL unit type 5)
/// @param nalUnitTypes the type of each NAL unit in order, each `0..31`; unmodifiable
/// @param resolution   the picture size from a sequence parameter set in the access unit or an earlier one
/// @param frameId      the frame id the receiver assigned, or an empty optional on the send side
/// @param dependencies the frame ids this frame references, unmodifiable
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
/// @spec https://www.itu.int/rec/T-REC-H.264 ITU-T H.264: Advanced video coding for generic audiovisual services
public record H264FrameMetadata(boolean idr, List<Integer> nalUnitTypes, Optional<Resolution> resolution,
                                OptionalLong frameId, List<Long> dependencies) implements FrameMetadata {
    /// Metadata that knows nothing about the access unit.
    private static final H264FrameMetadata NONE = new H264FrameMetadata(false, List.of(), Optional.empty(),
            OptionalLong.empty(), List.of());

    /// Creates H.264 metadata.
    ///
    /// @param idr          the IDR flag
    /// @param nalUnitTypes the NAL unit types, copied
    /// @param resolution   the resolution
    /// @param frameId      the frame id
    /// @param dependencies the dependencies, copied
    /// @throws IllegalArgumentException if a NAL unit type is outside `0..31`, or a dependency is negative or not
    ///                                  below `frameId`
    public H264FrameMetadata {
        nalUnitTypes = List.copyOf(nalUnitTypes);
        for (var type : nalUnitTypes) {
            MetadataChecks.checkRange(type, 31, "nal unit type");
        }
        Objects.requireNonNull(resolution, "resolution cannot be null");
        dependencies = MetadataChecks.checkDependencies(frameId, dependencies);
    }

    /// {@return metadata that knows nothing about the access unit; a packetizer reads what it needs from the bytes}
    public static H264FrameMetadata none() {
        return NONE;
    }

    /// {@return a copy with a frame id and the frame ids it references}
    ///
    /// @param frameId      the frame id, non-negative
    /// @param dependencies the referenced frame ids, each below `frameId`
    /// @throws IllegalArgumentException if a dependency is negative or not below `frameId`
    @Override
    public H264FrameMetadata withDependencies(long frameId, List<Long> dependencies) {
        return new H264FrameMetadata(idr, nalUnitTypes, resolution, OptionalLong.of(frameId), dependencies);
    }

    /// {@return [MediaKind#VIDEO]}
    @Override
    public MediaKind kind() {
        return MediaKind.VIDEO;
    }
}
