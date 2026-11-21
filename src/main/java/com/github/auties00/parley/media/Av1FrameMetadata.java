package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// The metadata of an AV1 frame: its layers from the OBU extension headers, whether it carries a sequence header,
/// the resolution the sequence header declares, and its references, from the dependency descriptor when the stream
/// carries one.
///
/// Without a dependency descriptor a frame is a whole temporal unit; with one it is the frame of one layer.
///
/// @param spatialId              the spatial layer, `0..3`, `0` for a stream without OBU extension headers
/// @param temporalId             the temporal layer, `0..7`, `0` for a stream without OBU extension headers
/// @param sequenceHeader         whether the frame contains a sequence header OBU
/// @param newCodedVideoSequence  the `N` bit of the aggregation header: the frame starts a new coded video sequence
/// @param resolution             the maximum picture size from a sequence header in the frame or an earlier one
/// @param frameId                the frame id the receiver assigned, or an empty optional on the send side
/// @param dependencies           the frame ids this frame references, unmodifiable
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
/// @spec https://aomediacodec.github.io/av1-spec/ AV1 Bitstream and Decoding Process Specification
public record Av1FrameMetadata(int spatialId, int temporalId, boolean sequenceHeader, boolean newCodedVideoSequence,
                               Optional<Resolution> resolution, OptionalLong frameId, List<Long> dependencies)
        implements FrameMetadata {
    /// Metadata that knows nothing about the frame.
    private static final Av1FrameMetadata NONE = new Av1FrameMetadata(0, 0, false, false, Optional.empty(),
            OptionalLong.empty(), List.of());

    /// Creates AV1 metadata.
    ///
    /// @param spatialId             the spatial layer
    /// @param temporalId            the temporal layer
    /// @param sequenceHeader        the sequence header flag
    /// @param newCodedVideoSequence the `N` bit
    /// @param resolution            the resolution
    /// @param frameId               the frame id
    /// @param dependencies          the dependencies, copied
    /// @throws IllegalArgumentException if a layer is out of range, or a dependency is negative or not below
    ///                                  `frameId`
    public Av1FrameMetadata {
        MetadataChecks.checkRange(spatialId, 3, "spatialId");
        MetadataChecks.checkRange(temporalId, 7, "temporalId");
        Objects.requireNonNull(resolution, "resolution cannot be null");
        dependencies = MetadataChecks.checkDependencies(frameId, dependencies);
    }

    /// {@return metadata that knows nothing about the frame; a packetizer reads what it needs from the OBUs}
    public static Av1FrameMetadata none() {
        return NONE;
    }

    @Override
    public Av1FrameMetadata withDependencies(long frameId, List<Long> dependencies) {
        return new Av1FrameMetadata(spatialId, temporalId, sequenceHeader, newCodedVideoSequence, resolution,
                OptionalLong.of(frameId), dependencies);
    }

    /// {@return [MediaKind#VIDEO]}
    @Override
    public MediaKind kind() {
        return MediaKind.VIDEO;
    }
}
