package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// The dependency descriptor of the AV1 RTP payload format: which frame a packet belongs to, the spatial and temporal
/// layer of that frame, which frames it references, and which decode targets need it, so an SFU can forward and a
/// receiver can assemble scalable video without parsing the codec bitstream.
///
/// Most packets carry only the three mandatory bytes, which name a frame dependency template of the stream's current
/// [TemplateStructure]; a keyframe's packets attach the structure itself. A descriptor therefore parses against the
/// latest structure its stream attached ([#parse(ByteBuffer, Optional)]), and the frame fields of a parsed descriptor
/// ([#spatialId()], [#decodeTargetIndications()], [#frameDependencies()], [#chainDiffs()]) are already resolved
/// from the template, with the per-frame overrides ("custom" DTIs, frame diffs and chains) applied.
///
/// The value is usually longer than 16 bytes when it attaches a structure, so it needs the two-byte header extension
/// form; the negotiated `a=extmap-allow-mixed` makes that possible on streams that otherwise use the one-byte form.
///
/// @param startOfFrame            whether the packet carries the first byte of its frame
/// @param endOfFrame              whether the packet carries the last byte of its frame
/// @param templateId              the frame dependency template id, `0..63`
/// @param frameNumber             the frame number, `0..65535`, which wraps
/// @param structure               the template structure this packet attaches, if any
/// @param activeDecodeTargets     the bitmask of active decode targets this packet signals (bit `i` for decode target
///                                `i`), if any; a receiver keeps the last one signaled, and all decode targets are
///                                active after a structure attached without one
/// @param spatialId               the frame's spatial layer id, from its template
/// @param temporalId              the frame's temporal layer id, from its template
/// @param decodeTargetIndications the frame's indication for each decode target
/// @param frameDependencies       the frame diffs (`fdiff`) of the frames this one references, each `1..4096`: frame
///                                `frameNumber - fdiff` is a reference
/// @param chainDiffs              the frame's diff to the previous frame of each chain, `0..255` each (`0` when it
///                                starts the chain)
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
public record DependencyDescriptor(boolean startOfFrame, boolean endOfFrame, int templateId, int frameNumber,
                                   Optional<TemplateStructure> structure, OptionalLong activeDecodeTargets,
                                   int spatialId, int temporalId,
                                   List<DecodeTargetIndication> decodeTargetIndications,
                                   List<Integer> frameDependencies, List<Integer> chainDiffs)
        implements HeaderExtension {
    /// The length of a descriptor carrying only the mandatory fields.
    public static final int MANDATORY_LENGTH = 3;

    /// Validates the ranges and copies the lists.
    ///
    /// @throws IllegalArgumentException if a field is out of range
    public DependencyDescriptor {
        if (templateId < 0 || templateId > 63) {
            throw new IllegalArgumentException("templateId must be in 0..63: " + templateId);
        }
        if (frameNumber < 0 || frameNumber > 0xFFFF) {
            throw new IllegalArgumentException("frameNumber must be in 0..65535: " + frameNumber);
        }
        Objects.requireNonNull(structure, "structure cannot be null");
        Objects.requireNonNull(activeDecodeTargets, "activeDecodeTargets cannot be null");
        if (activeDecodeTargets.isPresent() && (activeDecodeTargets.getAsLong() < 0
                || activeDecodeTargets.getAsLong() > 0xFFFFFFFFL)) {
            throw new IllegalArgumentException("activeDecodeTargets must fit 32 bits");
        }
        if (spatialId < 0 || spatialId > 3 || temporalId < 0 || temporalId > 7) {
            throw new IllegalArgumentException("spatialId must be in 0..3 and temporalId in 0..7");
        }
        decodeTargetIndications = List.copyOf(decodeTargetIndications);
        frameDependencies = List.copyOf(frameDependencies);
        chainDiffs = List.copyOf(chainDiffs);
        for (var fdiff : frameDependencies) {
            if (fdiff < 1 || fdiff > 4096) {
                throw new IllegalArgumentException("frame diffs must be in 1..4096: " + fdiff);
            }
        }
        for (var diff : chainDiffs) {
            if (diff < 0 || diff > 255) {
                throw new IllegalArgumentException("chain diffs must be in 0..255: " + diff);
            }
        }
    }

    /// The decode target indication of a frame: what a decoder of a decode target must do with it.
    public enum DecodeTargetIndication {
        /// The frame is not part of the decode target.
        NOT_PRESENT,
        /// The frame is part of the decode target but no later frame of it references this one.
        DISCARDABLE,
        /// The decoder can start decoding the decode target at this frame (a switch point).
        SWITCH,
        /// The frame is part of the decode target and later frames may reference it.
        REQUIRED;

        private static final DecodeTargetIndication[] VALUES = values();

        static DecodeTargetIndication of(int code) {
            return VALUES[code];
        }
    }

    /// The layer ids, decode target indications, frame diffs and chain diffs one template assigns to the frames that
    /// name it.
    ///
    /// @param spatialId               the spatial layer id, `0..3`
    /// @param temporalId              the temporal layer id, `0..7`
    /// @param decodeTargetIndications one indication per decode target of the structure
    /// @param frameDiffs              the frame diffs of the references, `1..16` each
    /// @param chainDiffs              one diff per chain of the structure, `0..15` each
    public record FrameDependencyTemplate(int spatialId, int temporalId,
                                          List<DecodeTargetIndication> decodeTargetIndications,
                                          List<Integer> frameDiffs, List<Integer> chainDiffs) {
        /// Validates the ranges and copies the lists.
        ///
        /// @throws IllegalArgumentException if a field is out of range
        public FrameDependencyTemplate {
            if (spatialId < 0 || spatialId > 3 || temporalId < 0 || temporalId > 7) {
                throw new IllegalArgumentException("spatialId must be in 0..3 and temporalId in 0..7");
            }
            decodeTargetIndications = List.copyOf(decodeTargetIndications);
            frameDiffs = List.copyOf(frameDiffs);
            chainDiffs = List.copyOf(chainDiffs);
            for (var fdiff : frameDiffs) {
                if (fdiff < 1 || fdiff > 16) {
                    throw new IllegalArgumentException("template frame diffs must be in 1..16: " + fdiff);
                }
            }
            for (var diff : chainDiffs) {
                if (diff < 0 || diff > 15) {
                    throw new IllegalArgumentException("template chain diffs must be in 0..15: " + diff);
                }
            }
        }
    }

    /// The render resolution of a spatial layer.
    ///
    /// @param width  the width in pixels, `1..65536`
    /// @param height the height in pixels, `1..65536`
    public record RenderResolution(int width, int height) {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a dimension is out of range
        public RenderResolution {
            if (width < 1 || width > 65536 || height < 1 || height > 65536) {
                throw new IllegalArgumentException("dimensions must be in 1..65536: " + width + "x" + height);
            }
        }
    }

    /// The template dependency structure of a stream: its decode targets, the frame dependency templates its
    /// descriptors name, its chains and the resolution of each spatial layer.
    ///
    /// Templates are listed in layer order: the first is spatial layer 0, temporal layer 0, and each next one has the
    /// same layers as the previous, the next temporal layer of the same spatial layer, or temporal layer 0 of the
    /// next spatial layer.
    ///
    /// @param templateIdOffset             the template id of the first template, `0..63`; template `i` has id
    ///                                     `(templateIdOffset + i) % 64`
    /// @param decodeTargetCount            the number of decode targets, `1..32`
    /// @param templates                    the templates, `1..64`
    /// @param chainCount                   the number of chains, `0..decodeTargetCount`
    /// @param decodeTargetProtectedByChain the chain protecting each decode target, `decodeTargetCount` values in
    ///                                     `0..chainCount - 1`; empty when there are no chains
    /// @param resolutions                  the render resolution of each spatial layer, from layer 0; empty when not
    ///                                     signaled
    public record TemplateStructure(int templateIdOffset, int decodeTargetCount,
                                    List<FrameDependencyTemplate> templates, int chainCount,
                                    List<Integer> decodeTargetProtectedByChain,
                                    List<RenderResolution> resolutions) {
        /// Validates the structure and copies the lists.
        ///
        /// @throws IllegalArgumentException if a field is out of range, a template does not match the decode target
        ///                                  or chain counts, the templates are not in layer order, or the
        ///                                  resolutions do not cover every spatial layer
        public TemplateStructure {
            if (templateIdOffset < 0 || templateIdOffset > 63) {
                throw new IllegalArgumentException("templateIdOffset must be in 0..63: " + templateIdOffset);
            }
            if (decodeTargetCount < 1 || decodeTargetCount > 32) {
                throw new IllegalArgumentException("decodeTargetCount must be in 1..32: " + decodeTargetCount);
            }
            templates = List.copyOf(templates);
            if (templates.isEmpty() || templates.size() > 64) {
                throw new IllegalArgumentException("1..64 templates required: " + templates.size());
            }
            if (chainCount < 0 || chainCount > decodeTargetCount) {
                throw new IllegalArgumentException("chainCount must be in 0..decodeTargetCount: " + chainCount);
            }
            decodeTargetProtectedByChain = List.copyOf(decodeTargetProtectedByChain);
            if (decodeTargetProtectedByChain.size() != (chainCount == 0 ? 0 : decodeTargetCount)) {
                throw new IllegalArgumentException("one protecting chain per decode target required");
            }
            for (var chain : decodeTargetProtectedByChain) {
                if (chain < 0 || chain >= chainCount) {
                    throw new IllegalArgumentException("protecting chain out of range: " + chain);
                }
            }
            var previous = (FrameDependencyTemplate) null;
            for (var template : templates) {
                if (template.decodeTargetIndications().size() != decodeTargetCount) {
                    throw new IllegalArgumentException("template decode target indications do not match the count");
                }
                if (template.chainDiffs().size() != chainCount) {
                    throw new IllegalArgumentException("template chain diffs do not match the chain count");
                }
                if (previous == null) {
                    if (template.spatialId() != 0 || template.temporalId() != 0) {
                        throw new IllegalArgumentException("the first template must be spatial 0, temporal 0");
                    }
                } else if (layerStep(previous, template) < 0) {
                    throw new IllegalArgumentException("templates are not in layer order");
                }
                previous = template;
            }
            resolutions = List.copyOf(resolutions);
            if (!resolutions.isEmpty() && resolutions.size() != previous.spatialId() + 1) {
                throw new IllegalArgumentException("one resolution per spatial layer required");
            }
        }

        /// {@return the `next_layer_idc` from one template to the next: `0` same layers, `1` next temporal layer,
        /// `2` next spatial layer, `-1` not allowed}
        static int layerStep(FrameDependencyTemplate from, FrameDependencyTemplate to) {
            if (to.spatialId() == from.spatialId() && to.temporalId() == from.temporalId()) {
                return 0;
            }
            if (to.spatialId() == from.spatialId() && to.temporalId() == from.temporalId() + 1) {
                return 1;
            }
            if (to.spatialId() == from.spatialId() + 1 && to.temporalId() == 0) {
                return 2;
            }
            return -1;
        }

        /// {@return the highest spatial layer id of the templates}
        public int maxSpatialId() {
            return templates.getLast().spatialId();
        }

        /// {@return the highest spatial layer id among the templates that are part of a decode target}
        ///
        /// @param decodeTarget the decode target index
        /// @throws IndexOutOfBoundsException if `decodeTarget` is out of range
        public int decodeTargetSpatialId(int decodeTarget) {
            Objects.checkIndex(decodeTarget, decodeTargetCount);
            var max = 0;
            for (var template : templates) {
                if (template.decodeTargetIndications().get(decodeTarget) != DecodeTargetIndication.NOT_PRESENT) {
                    max = Math.max(max, template.spatialId());
                }
            }
            return max;
        }

        /// {@return the highest temporal layer id among the templates that are part of a decode target}
        ///
        /// @param decodeTarget the decode target index
        /// @throws IndexOutOfBoundsException if `decodeTarget` is out of range
        public int decodeTargetTemporalId(int decodeTarget) {
            Objects.checkIndex(decodeTarget, decodeTargetCount);
            var max = 0;
            for (var template : templates) {
                if (template.decodeTargetIndications().get(decodeTarget) != DecodeTargetIndication.NOT_PRESENT) {
                    max = Math.max(max, template.temporalId());
                }
            }
            return max;
        }

        /// {@return the index in [#templates()] of a template id, or `-1` when the id names no template}
        ///
        /// @param templateId the template id, `0..63`
        public int indexOf(int templateId) {
            var index = (templateId + 64 - templateIdOffset) % 64;
            return index < templates.size() ? index : -1;
        }
    }

    /// The fields every descriptor carries, readable without a template structure.
    ///
    /// @param startOfFrame whether the packet carries the first byte of its frame
    /// @param endOfFrame   whether the packet carries the last byte of its frame
    /// @param templateId   the frame dependency template id, `0..63`
    /// @param frameNumber  the frame number, `0..65535`
    public record MandatoryFields(boolean startOfFrame, boolean endOfFrame, int templateId, int frameNumber) {
    }

    /// Reads the mandatory fields of a descriptor, which need no template structure.
    ///
    /// @param value the element value between position and limit; it is not modified
    /// @return the mandatory fields
    /// @throws RtpFormatException if the value is shorter than three bytes
    public static MandatoryFields readMandatoryFields(ByteBuffer value) throws RtpFormatException {
        Objects.requireNonNull(value, "value cannot be null");
        ExtensionCodec.require(value, MANDATORY_LENGTH, "dependency descriptor");
        var first = value.get(value.position()) & 0xFF;
        var frameNumber = value.getShort(value.position() + 1) & 0xFFFF;
        return new MandatoryFields((first & 0x80) != 0, (first & 0x40) != 0, first & 0x3F, frameNumber);
    }

    /// Creates the descriptor of a frame that uses one template of a structure unchanged.
    ///
    /// @param structure       the stream's structure
    /// @param templateIndex   the index of the template in [TemplateStructure#templates()]
    /// @param startOfFrame    whether the packet carries the first byte of its frame
    /// @param endOfFrame      whether the packet carries the last byte of its frame
    /// @param frameNumber     the frame number, `0..65535`
    /// @param attachStructure whether the packet attaches the structure (keyframes)
    /// @return the descriptor
    /// @throws IndexOutOfBoundsException if `templateIndex` is out of range
    public static DependencyDescriptor fromTemplate(TemplateStructure structure, int templateIndex,
                                                    boolean startOfFrame, boolean endOfFrame, int frameNumber,
                                                    boolean attachStructure) {
        Objects.requireNonNull(structure, "structure cannot be null");
        var template = structure.templates().get(templateIndex);
        return new DependencyDescriptor(startOfFrame, endOfFrame, (structure.templateIdOffset() + templateIndex) % 64,
                frameNumber, attachStructure ? Optional.of(structure) : Optional.empty(), OptionalLong.empty(),
                template.spatialId(), template.temporalId(), template.decodeTargetIndications(),
                template.frameDiffs(), template.chainDiffs());
    }

    /// Parses a descriptor that attaches its own template structure, as the first packet of a key frame does.
    ///
    /// @param value the element value between position and limit; it is not modified
    /// @return the descriptor, its frame fields resolved from its template
    /// @throws RtpFormatException if the value is malformed, attaches no structure, or names no template of it
    public static DependencyDescriptor parse(ByteBuffer value) throws RtpFormatException {
        Objects.requireNonNull(value, "value cannot be null");
        return read(value, Optional.empty());
    }

    /// Parses a descriptor against the latest structure the stream attached, unless the packet attaches its own.
    ///
    /// @param value  the element value between position and limit; it is not modified
    /// @param latest the latest structure the stream attached, used when this packet attaches none
    /// @return the descriptor, its frame fields resolved from its template
    /// @throws RtpFormatException if the value is malformed or names no template of its structure
    public static DependencyDescriptor parse(ByteBuffer value, TemplateStructure latest) throws RtpFormatException {
        Objects.requireNonNull(value, "value cannot be null");
        Objects.requireNonNull(latest, "latest cannot be null");
        return read(value, Optional.of(latest));
    }

    /// Parses a descriptor against an optional latest structure.
    ///
    /// @param value  the element value
    /// @param latest the latest structure, or empty
    /// @return the descriptor
    /// @throws RtpFormatException if the value is malformed
    /// @deprecated use [#parse(ByteBuffer)] or [#parse(ByteBuffer, TemplateStructure)]
    @Deprecated(forRemoval = true)
    public static DependencyDescriptor parse(ByteBuffer value, Optional<TemplateStructure> latest)
            throws RtpFormatException {
        // TODO: remove once payload.VideoDepacketizer calls the overloads (cross-group, integration).
        Objects.requireNonNull(value, "value cannot be null");
        Objects.requireNonNull(latest, "latest cannot be null");
        return read(value, latest);
    }

    private static DependencyDescriptor read(ByteBuffer value, Optional<TemplateStructure> latest)
            throws RtpFormatException {
        var size = value.remaining();
        var reader = new BitReader(value);
        var startOfFrame = reader.readFlag();
        var endOfFrame = reader.readFlag();
        var templateId = reader.readInt(6);
        var frameNumber = reader.readInt(16);
        var attached = Optional.<TemplateStructure>empty();
        var active = OptionalLong.empty();
        var customDtis = false;
        var customFdiffs = false;
        var customChains = false;
        if (size > MANDATORY_LENGTH) {
            var structurePresent = reader.readFlag();
            var activePresent = reader.readFlag();
            customDtis = reader.readFlag();
            customFdiffs = reader.readFlag();
            customChains = reader.readFlag();
            if (structurePresent) {
                attached = Optional.of(readStructure(reader));
            }
            if (activePresent) {
                var count = attached.or(() -> latest).orElseThrow(() ->
                        new RtpFormatException("active decode targets without a template structure"))
                        .decodeTargetCount();
                active = OptionalLong.of(reader.read(count));
            }
        }
        var structure = attached.isPresent() ? attached.get() : latest.orElseThrow(() ->
                new RtpFormatException("dependency descriptor without a template structure to read against"));
        var index = structure.indexOf(templateId);
        if (index < 0) {
            throw new RtpFormatException("template id " + templateId + " names no template of the structure");
        }
        var template = structure.templates().get(index);
        var dtis = template.decodeTargetIndications();
        if (customDtis) {
            var list = new ArrayList<DecodeTargetIndication>(structure.decodeTargetCount());
            for (var i = 0; i < structure.decodeTargetCount(); i++) {
                list.add(DecodeTargetIndication.of(reader.readInt(2)));
            }
            dtis = list;
        }
        var fdiffs = template.frameDiffs();
        if (customFdiffs) {
            var list = new ArrayList<Integer>();
            var nextSize = reader.readInt(2);
            while (nextSize != 0) {
                list.add(reader.readInt(4 * nextSize) + 1);
                nextSize = reader.readInt(2);
            }
            fdiffs = list;
        }
        var chains = template.chainDiffs();
        if (customChains) {
            var list = new ArrayList<Integer>(structure.chainCount());
            for (var i = 0; i < structure.chainCount(); i++) {
                list.add(reader.readInt(8));
            }
            chains = list;
        }
        try {
            return new DependencyDescriptor(startOfFrame, endOfFrame, templateId, frameNumber, attached, active,
                    template.spatialId(), template.temporalId(), dtis, fdiffs, chains);
        } catch (IllegalArgumentException exception) {
            throw new RtpFormatException("malformed dependency descriptor", exception);
        }
    }

    private static TemplateStructure readStructure(BitReader reader) throws RtpFormatException {
        var offset = reader.readInt(6);
        var decodeTargets = reader.readInt(5) + 1;
        var layers = new ArrayList<int[]>();
        var spatial = 0;
        var temporal = 0;
        while (true) {
            if (layers.size() == 64) {
                throw new RtpFormatException("more than 64 templates");
            }
            layers.add(new int[]{spatial, temporal});
            var next = reader.readInt(2);
            if (next == 3) {
                break;
            }
            if (next == 1) {
                temporal++;
            } else if (next == 2) {
                temporal = 0;
                spatial++;
            }
            if (spatial > 3 || temporal > 7) {
                throw new RtpFormatException("template layer ids out of range");
            }
        }
        var count = layers.size();
        var dtis = new ArrayList<List<DecodeTargetIndication>>(count);
        for (var t = 0; t < count; t++) {
            var list = new ArrayList<DecodeTargetIndication>(decodeTargets);
            for (var d = 0; d < decodeTargets; d++) {
                list.add(DecodeTargetIndication.of(reader.readInt(2)));
            }
            dtis.add(list);
        }
        var fdiffs = new ArrayList<List<Integer>>(count);
        for (var t = 0; t < count; t++) {
            var list = new ArrayList<Integer>();
            while (reader.readFlag()) {
                list.add(reader.readInt(4) + 1);
            }
            fdiffs.add(list);
        }
        var chainCount = reader.readNonSymmetric(decodeTargets + 1);
        var protectedBy = new ArrayList<Integer>();
        var chainDiffs = new ArrayList<List<Integer>>(count);
        if (chainCount > 0) {
            for (var d = 0; d < decodeTargets; d++) {
                protectedBy.add(reader.readNonSymmetric(chainCount));
            }
        }
        for (var t = 0; t < count; t++) {
            var list = new ArrayList<Integer>(chainCount);
            for (var c = 0; c < chainCount; c++) {
                list.add(reader.readInt(4));
            }
            chainDiffs.add(list);
        }
        var resolutions = new ArrayList<RenderResolution>();
        if (reader.readFlag()) {
            for (var s = 0; s <= spatial; s++) {
                resolutions.add(new RenderResolution(reader.readInt(16) + 1, reader.readInt(16) + 1));
            }
        }
        var templates = new ArrayList<FrameDependencyTemplate>(count);
        for (var t = 0; t < count; t++) {
            templates.add(new FrameDependencyTemplate(layers.get(t)[0], layers.get(t)[1], dtis.get(t), fdiffs.get(t),
                    chainDiffs.get(t)));
        }
        try {
            return new TemplateStructure(offset, decodeTargets, templates, chainCount, protectedBy, resolutions);
        } catch (IllegalArgumentException exception) {
            throw new RtpFormatException("malformed template structure", exception);
        }
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.DEPENDENCY_DESCRIPTOR;
    }

    /// {@inheritDoc}
    ///
    /// @throws IllegalStateException if the descriptor attaches no structure; use
    ///                               [#encodedLength(TemplateStructure)]
    @Override
    public int encodedLength() {
        return encode(attachedOrFail()).length;
    }

    /// {@inheritDoc}
    ///
    /// @throws IllegalStateException if the descriptor attaches no structure; use
    ///                               [#writeTo(ByteBuffer, TemplateStructure)]
    @Override
    public void writeTo(ByteBuffer destination) {
        writeTo(destination, attachedOrFail());
    }

    /// {@return the encoded length when written against the stream's active structure}
    ///
    /// @param active the structure the receiver will read the descriptor against; the attached one if this
    ///               descriptor attaches a structure
    /// @throws IllegalArgumentException if the frame fields do not fit the structure
    public int encodedLength(TemplateStructure active) {
        return encode(active).length;
    }

    /// Writes the descriptor against the stream's active structure.
    ///
    /// Fields that differ from the named template are written as per-frame overrides.
    ///
    /// @param destination the buffer to write into
    /// @param active      the structure the receiver will read the descriptor against; the attached one if this
    ///                    descriptor attaches a structure
    /// @throws IllegalArgumentException          if the frame fields do not fit the structure
    /// @throws java.nio.BufferOverflowException if the value does not fit in the remaining bytes
    public void writeTo(ByteBuffer destination, TemplateStructure active) {
        var bytes = encode(active);
        ExtensionCodec.checkRoom(destination, bytes.length);
        destination.put(bytes);
    }

    private TemplateStructure attachedOrFail() {
        return structure.orElseThrow(() -> new IllegalStateException(
                "the descriptor attaches no structure; pass the stream's active structure"));
    }

    private byte[] encode(TemplateStructure active) {
        Objects.requireNonNull(active, "active cannot be null");
        var used = structure.orElse(active);
        var index = used.indexOf(templateId);
        if (index < 0) {
            throw new IllegalArgumentException("template id " + templateId + " names no template of the structure");
        }
        var template = used.templates().get(index);
        if (template.spatialId() != spatialId || template.temporalId() != temporalId) {
            throw new IllegalArgumentException("the frame layers differ from those of its template");
        }
        if (decodeTargetIndications.size() != used.decodeTargetCount() || chainDiffs.size() != used.chainCount()) {
            throw new IllegalArgumentException("the frame fields do not match the structure's counts");
        }
        var customDtis = !decodeTargetIndications.equals(template.decodeTargetIndications());
        var customFdiffs = !frameDependencies.equals(template.frameDiffs());
        var customChains = !chainDiffs.equals(template.chainDiffs());
        var extended = structure.isPresent() || activeDecodeTargets.isPresent() || customDtis || customFdiffs
                || customChains;
        var writer = new BitWriter();
        writer.writeFlag(startOfFrame);
        writer.writeFlag(endOfFrame);
        writer.write(templateId, 6);
        writer.write(frameNumber, 16);
        if (extended) {
            writer.writeFlag(structure.isPresent());
            writer.writeFlag(activeDecodeTargets.isPresent());
            writer.writeFlag(customDtis);
            writer.writeFlag(customFdiffs);
            writer.writeFlag(customChains);
            structure.ifPresent(attached -> writeStructure(writer, attached));
            if (activeDecodeTargets.isPresent()) {
                writer.write(activeDecodeTargets.getAsLong(), used.decodeTargetCount());
            }
        }
        if (customDtis) {
            for (var dti : decodeTargetIndications) {
                writer.write(dti.ordinal(), 2);
            }
        }
        if (customFdiffs) {
            for (var fdiff : frameDependencies) {
                var minusOne = fdiff - 1;
                var size = minusOne < 16 ? 1 : minusOne < 256 ? 2 : 3;
                writer.write(size, 2);
                writer.write(minusOne, 4 * size);
            }
            writer.write(0, 2);
        }
        if (customChains) {
            for (var diff : chainDiffs) {
                writer.write(diff, 8);
            }
        }
        return writer.toByteArray();
    }

    private static void writeStructure(BitWriter writer, TemplateStructure structure) {
        writer.write(structure.templateIdOffset(), 6);
        writer.write(structure.decodeTargetCount() - 1, 5);
        var templates = structure.templates();
        for (var i = 1; i < templates.size(); i++) {
            writer.write(TemplateStructure.layerStep(templates.get(i - 1), templates.get(i)), 2);
        }
        writer.write(3, 2);
        for (var template : templates) {
            for (var dti : template.decodeTargetIndications()) {
                writer.write(dti.ordinal(), 2);
            }
        }
        for (var template : templates) {
            for (var fdiff : template.frameDiffs()) {
                writer.writeFlag(true);
                writer.write(fdiff - 1, 4);
            }
            writer.writeFlag(false);
        }
        writer.writeNonSymmetric(structure.chainCount(), structure.decodeTargetCount() + 1);
        if (structure.chainCount() > 0) {
            for (var chain : structure.decodeTargetProtectedByChain()) {
                writer.writeNonSymmetric(chain, structure.chainCount());
            }
        }
        for (var template : templates) {
            for (var diff : template.chainDiffs()) {
                writer.write(diff, 4);
            }
        }
        writer.writeFlag(!structure.resolutions().isEmpty());
        for (var resolution : structure.resolutions()) {
            writer.write(resolution.width() - 1, 16);
            writer.write(resolution.height() - 1, 16);
        }
    }
}
