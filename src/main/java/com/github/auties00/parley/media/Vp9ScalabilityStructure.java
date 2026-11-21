package com.github.auties00.parley.media;

import java.util.List;

/// The scalability structure (SS) of a VP9 stream: its spatial layers, their resolutions, and the picture group that
/// fixes the temporal layering and references of a non-flexible stream.
///
/// A sender attaches it to the first layer frame of a keyframe picture, and whenever the structure changes.
///
/// @param spatialLayers the number of spatial layers, `1..8`
/// @param resolutions   the resolution of each spatial layer, lowest first, or empty when the structure omits them;
///                      unmodifiable
/// @param pictureGroup  the pictures of one group of pictures in order, empty when the structure omits the
///                      description; unmodifiable, at most 255 entries
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html#section-4.2.1 RFC 9628 section 4.2.1: Scalability Structure (SS)
public record Vp9ScalabilityStructure(int spatialLayers, List<Resolution> resolutions,
                                      List<PictureGroupEntry> pictureGroup) {
    /// Creates a structure.
    ///
    /// @param spatialLayers the number of spatial layers
    /// @param resolutions   the resolutions, copied
    /// @param pictureGroup  the picture group, copied
    /// @throws IllegalArgumentException if `spatialLayers` is outside `1..8`, the resolutions are neither empty nor
    ///                                  one per layer, a resolution exceeds 65535 in either dimension, or the group
    ///                                  has more than 255 entries
    public Vp9ScalabilityStructure {
        MetadataChecks.checkRange(spatialLayers - 1, 7, "spatialLayers - 1");
        resolutions = List.copyOf(resolutions);
        pictureGroup = List.copyOf(pictureGroup);
        if (!resolutions.isEmpty() && resolutions.size() != spatialLayers) {
            throw new IllegalArgumentException("expected " + spatialLayers + " resolutions, got " + resolutions.size());
        }
        for (var resolution : resolutions) {
            if (resolution.width() > 0xFFFF || resolution.height() > 0xFFFF) {
                throw new IllegalArgumentException("resolution too large: " + resolution);
            }
        }
        if (pictureGroup.size() > 255) {
            throw new IllegalArgumentException("picture group too large: " + pictureGroup.size());
        }
    }

    /// One picture of a group of pictures.
    ///
    /// @param temporalId       the temporal layer of the picture, `0..7`
    /// @param switchingUpPoint whether a receiver may switch up to the picture's temporal layer at it
    /// @param referenceDiffs   the differences between the picture's id and the ids of the pictures it references,
    ///                         each `1..255`, at most three; unmodifiable
    public record PictureGroupEntry(int temporalId, boolean switchingUpPoint, List<Integer> referenceDiffs) {
        /// Creates an entry.
        ///
        /// @param temporalId       the temporal layer
        /// @param switchingUpPoint the switching up point flag
        /// @param referenceDiffs   the reference differences, copied
        /// @throws IllegalArgumentException if a value is out of its range
        public PictureGroupEntry {
            MetadataChecks.checkRange(temporalId, 7, "temporalId");
            referenceDiffs = List.copyOf(referenceDiffs);
            if (referenceDiffs.size() > 3) {
                throw new IllegalArgumentException("at most 3 reference differences");
            }
            for (var diff : referenceDiffs) {
                if (diff < 1 || diff > 255) {
                    throw new IllegalArgumentException("reference difference out of range: " + diff);
                }
            }
        }
    }
}
