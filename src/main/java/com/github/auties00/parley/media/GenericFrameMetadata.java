package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// The metadata of a frame of a payload format Parley does not interpret, or of any kind of media whose layering
/// a dependency descriptor alone describes.
///
/// @param kind         the kind of media
/// @param spatialId    the spatial layer, `0` when unknown
/// @param temporalId   the temporal layer, `0` when unknown
/// @param resolution   the picture size, when known
/// @param frameId      the frame id the receiver assigned, or an empty optional on the send side
/// @param dependencies the frame ids this frame references, unmodifiable
public record GenericFrameMetadata(MediaKind kind, int spatialId, int temporalId, Optional<Resolution> resolution,
                                   OptionalLong frameId, List<Long> dependencies) implements FrameMetadata {
    /// Creates generic metadata.
    ///
    /// @param kind         the kind
    /// @param spatialId    the spatial layer
    /// @param temporalId   the temporal layer
    /// @param resolution   the resolution
    /// @param frameId      the frame id
    /// @param dependencies the dependencies, copied
    /// @throws IllegalArgumentException if a layer is negative, or a dependency is negative or not below `frameId`
    public GenericFrameMetadata {
        Objects.requireNonNull(kind, "kind cannot be null");
        MetadataChecks.checkRange(spatialId, Integer.MAX_VALUE, "spatialId");
        MetadataChecks.checkRange(temporalId, Integer.MAX_VALUE, "temporalId");
        Objects.requireNonNull(resolution, "resolution cannot be null");
        dependencies = MetadataChecks.checkDependencies(frameId, dependencies);
    }

    /// {@return metadata of a kind that knows nothing else about the frame}
    ///
    /// @param kind the kind
    public static GenericFrameMetadata none(MediaKind kind) {
        return new GenericFrameMetadata(kind, 0, 0, Optional.empty(), OptionalLong.empty(), List.of());
    }

    @Override
    public GenericFrameMetadata withDependencies(long frameId, List<Long> dependencies) {
        return new GenericFrameMetadata(kind, spatialId, temporalId, resolution, OptionalLong.of(frameId),
                dependencies);
    }
}
