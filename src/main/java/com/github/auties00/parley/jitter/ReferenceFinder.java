package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.Vp8FrameMetadata;
import com.github.auties00.parley.media.Vp9FrameMetadata;
import com.github.auties00.parley.media.Vp9ScalabilityStructure;
import com.github.auties00.parley.payload.GenericFormat;
import com.github.auties00.parley.payload.PayloadFormat;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/// Assigns each assembled video frame a frame id and finds the frames it references, per payload format.
///
/// | Frames | Id | References |
/// |---|---|---|
/// | with a frame id from the dependency descriptor | the descriptor's frame number | the descriptor's |
/// | VP8 with a picture id | the picture id unwrapped modulo `2^7` or `2^15`, as its field width says | the previous picture; with temporal layers, the base layer frame of the previous (layer 0) or same (higher layers) `TL0PICIDX` group, the latest lower-layer frame of the group and, without `Y`, the previous frame of the same layer |
/// | VP9 with a picture id | unwrapped picture id times 8 plus the spatial layer | the `P_DIFF` pictures in flexible mode; in non-flexible mode the reference differences of the picture's entry in the group of pictures of the latest scalability structure, else the temporal layering rule of VP8; the lower spatial layer of the picture with `D` |
/// | the passthrough format | the unwrapped last sequence number | none: frames are independent |
/// | everything else (H.264, H.265, AV1 without descriptor, VP8 without picture id) | the unwrapped last sequence number | the frame that ends right before it, so frames decode strictly in sequence |
///
/// A keyframe references nothing. References that cannot be named yet (a base layer frame never seen) leave the
/// frame unresolved until they can or the frame times out.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html RFC 7741: RTP Payload Format for VP8 Video
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
final class ReferenceFinder {
    /// The number of spatial layers a VP9 frame id leaves room for.
    private static final int SPATIAL_SLOTS = 8;

    /// Whether frames are independent (passthrough format).
    private final boolean independent;

    /// The unwrapper of 15-bit picture ids.
    private final Unwrapper longPictureIds = new Unwrapper(15);

    /// The unwrapper of 7-bit VP8 picture ids.
    private final Unwrapper shortPictureIds = new Unwrapper(7);

    /// The picture group of the latest VP9 scalability structure that described one, or `null`.
    private List<Vp9ScalabilityStructure.PictureGroupEntry> pictureGroup;

    /// The unwrapped picture id of the picture that carried [#pictureGroup], its first entry.
    private long pictureGroupStart;

    /// The unwrapper of `TL0PICIDX`.
    private final Unwrapper tl0Indices = new Unwrapper(8);

    /// The base layer frame id of each `TL0PICIDX` group, by unwrapped index and spatial layer (`tl0 * 8 + sid`).
    private final Map<Long, Long> baseFrames = new HashMap<>();

    /// The frames seen per temporal layer and spatial layer key (`tid * 8 + sid`), by frame id, valued by group.
    private final Map<Integer, TreeMap<Long, Long>> layerFrames = new HashMap<>();

    /// Creates a finder for a format.
    ReferenceFinder(PayloadFormat format) {
        this.independent = format instanceof GenericFormat;
    }

    /// The identity and reference rule of one frame.
    ///
    /// @param id        the frame id
    /// @param keyframe  whether it is a keyframe
    /// @param rule      how its references are found
    record Identity(long id, boolean keyframe, Rule rule) {
    }

    /// How the references of a frame are found.
    sealed interface Rule {
        /// References known at assembly.
        ///
        /// @param references the frame ids
        record Fixed(List<Long> references) implements Rule {
        }

        /// The temporal layering rule, resolved against the frames seen.
        ///
        /// @param group      the unwrapped `TL0PICIDX`
        /// @param temporalId the temporal layer
        /// @param spatialId  the spatial layer
        /// @param layerSync  whether the frame references only the base layer
        /// @param extra      references known at assembly (the lower spatial layer)
        record Layered(long group, int temporalId, int spatialId, boolean layerSync, List<Long> extra)
                implements Rule {
        }
    }

    /// {@return the identity of an assembled frame}
    ///
    /// @param frame         the frame
    /// @param firstSequence the unwrapped sequence number of its first packet
    /// @param lastSequence  the unwrapped sequence number of its last packet
    Identity identify(EncodedFrame frame, long firstSequence, long lastSequence) {
        var metadata = frame.metadata();
        var keyframe = frame.keyframe();
        if (metadata.frameId().isPresent()) {
            return new Identity(metadata.frameId().getAsLong(), keyframe, new Rule.Fixed(metadata.dependencies()));
        }
        if (metadata instanceof Vp8FrameMetadata vp8 && vp8.pictureId().isPresent()) {
            var id = (vp8.pictureIdBits() == 7 ? shortPictureIds : longPictureIds).unwrap(vp8.pictureId().getAsInt());
            if (keyframe) {
                remember(vp8.tl0PicIndex().isPresent() ? tl0Indices.unwrap(vp8.tl0PicIndex().getAsInt()) : -1, 0, 0, id);
                return new Identity(id, true, new Rule.Fixed(List.of()));
            }
            if (vp8.tl0PicIndex().isEmpty() || vp8.temporalId().isEmpty()) {
                return new Identity(id, false, new Rule.Fixed(List.of(id - 1)));
            }
            var group = tl0Indices.unwrap(vp8.tl0PicIndex().getAsInt());
            var temporal = vp8.temporalId().getAsInt();
            remember(group, temporal, 0, id);
            return new Identity(id, false, new Rule.Layered(group, temporal, 0, vp8.layerSync(), List.of()));
        }
        if (metadata instanceof Vp9FrameMetadata vp9 && vp9.pictureId().isPresent()) {
            var picture = longPictureIds.unwrap(vp9.pictureId().getAsInt());
            var spatial = vp9.spatialId().orElse(0);
            var id = picture * SPATIAL_SLOTS + spatial;
            var extra = new ArrayList<Long>();
            if (vp9.interLayerPredicted() && spatial > 0) {
                extra.add(id - 1);
            }
            var group = vp9.tl0PicIndex().isPresent() ? tl0Indices.unwrap(vp9.tl0PicIndex().getAsInt()) : -1;
            var temporal = vp9.temporalId().orElse(0);
            if (group >= 0) {
                remember(group, temporal, spatial, id);
            }
            var structure = vp9.scalabilityStructure();
            if (structure.isPresent() && !structure.get().pictureGroup().isEmpty()) {
                pictureGroup = structure.get().pictureGroup();
                pictureGroupStart = picture;
            }
            if (!vp9.interPicturePredicted()) {
                return new Identity(id, extra.isEmpty(), new Rule.Fixed(extra));
            }
            if (vp9.flexibleMode()) {
                for (var diff : vp9.referenceDiffs()) {
                    extra.add((picture - diff) * SPATIAL_SLOTS + spatial);
                }
                return new Identity(id, false, new Rule.Fixed(extra));
            }
            var entry = pictureGroupEntry(picture, temporal);
            if (entry.isPresent() && !entry.get().referenceDiffs().isEmpty()) {
                for (var diff : entry.get().referenceDiffs()) {
                    extra.add((picture - diff) * SPATIAL_SLOTS + spatial);
                }
                return new Identity(id, false, new Rule.Fixed(extra));
            }
            if (group < 0) {
                extra.add((picture - 1) * SPATIAL_SLOTS + spatial);
                return new Identity(id, false, new Rule.Fixed(extra));
            }
            return new Identity(id, false, new Rule.Layered(group, temporal, spatial, vp9.switchingUpPoint(), extra));
        }
        if (independent) {
            return new Identity(lastSequence, keyframe, new Rule.Fixed(List.of()));
        }
        return new Identity(lastSequence, keyframe, new Rule.Fixed(keyframe ? List.of() : List.of(firstSequence - 1)));
    }

    /// {@return the entry of the latest picture group that a non-flexible picture follows: the pictures after the
    /// one that carried the structure cycle through its entries; an empty optional without a group, or when the
    /// entry's temporal layer is not the picture's, which means the stream left the group}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc9628.html#section-4.2.1 RFC 9628 section 4.2.1: Scalability Structure (SS)
    private Optional<Vp9ScalabilityStructure.PictureGroupEntry> pictureGroupEntry(long picture, int temporal) {
        if (pictureGroup == null || picture < pictureGroupStart) {
            return Optional.empty();
        }
        var entry = pictureGroup.get((int) ((picture - pictureGroupStart) % pictureGroup.size()));
        return entry.temporalId() == temporal ? Optional.of(entry) : Optional.empty();
    }

    /// {@return the references of a frame, or an empty optional while some cannot be named}
    Optional<List<Long>> references(Identity identity) {
        if (identity.keyframe()) {
            return Optional.of(List.of());
        }
        return switch (identity.rule()) {
            case Rule.Fixed(var references) -> Optional.of(references);
            case Rule.Layered(var group, var temporal, var spatial, var sync, var extra) -> {
                var result = new ArrayList<>(extra);
                if (temporal == 0) {
                    var base = baseFrames.get((group - 1) * SPATIAL_SLOTS + spatial);
                    if (base == null) {
                        yield Optional.empty();
                    }
                    result.add(base);
                    yield Optional.of(result);
                }
                var base = baseFrames.get(group * SPATIAL_SLOTS + spatial);
                if (base == null) {
                    yield Optional.empty();
                }
                result.add(base);
                for (var layer = 1; layer < temporal; layer++) {
                    latest(layer, spatial, identity.id(), group, group).ifPresent(result::add);
                }
                if (!sync) {
                    latest(temporal, spatial, identity.id(), group - 1, group).ifPresent(result::add);
                }
                yield Optional.of(List.copyOf(result.stream().distinct().filter(id -> id < identity.id()).toList()));
            }
        };
    }

    /// Records a frame seen in a layer.
    private void remember(long group, int temporal, int spatial, long id) {
        if (group >= 0 && temporal == 0) {
            baseFrames.merge(group * SPATIAL_SLOTS + spatial, id, Math::max);
        }
        var frames = layerFrames.computeIfAbsent(temporal * SPATIAL_SLOTS + spatial, key -> new TreeMap<>());
        frames.put(id, group);
        while (frames.size() > 64) {
            frames.pollFirstEntry();
        }
        if (baseFrames.size() > 512) {
            var oldest = baseFrames.keySet().stream().min(Long::compare).orElseThrow();
            baseFrames.remove(oldest);
        }
    }

    /// {@return the latest frame of a layer before `id` whose group is in `minGroup..maxGroup`}
    private Optional<Long> latest(int temporal, int spatial, long id, long minGroup, long maxGroup) {
        var frames = layerFrames.get(temporal * SPATIAL_SLOTS + spatial);
        if (frames == null) {
            return Optional.empty();
        }
        for (var entry : frames.headMap(id, false).descendingMap().entrySet()) {
            var group = entry.getValue();
            if (group >= minGroup && group <= maxGroup) {
                return Optional.of(entry.getKey());
            }
            if (group < minGroup) {
                break;
            }
        }
        return Optional.empty();
    }
}
