package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Av1FrameMetadata;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.ThreadLocalRandom;

/// The AV1 packetizer of the AV1 RTP payload format.
///
/// A frame is a temporal unit (or one layer frame of it) in low-overhead bitstream format. The packetizer drops the
/// temporal delimiter, tile list and padding OBUs, clears `obu_has_size_field` and removes the size of every OBU, and
/// packs the OBU elements greedily: each packet holds as many elements as fit, an element that does not fit is
/// fragmented across packets (`Z` and `Y`), and the last element of a packet with at most three omits its length
/// (`W`). The first packet of a keyframe that carries a sequence header sets `N`.
///
/// With [PacketizerConfig#dependencyDescriptor()] every packet also carries a dependency descriptor. Its template
/// structure has one template, and one decode target, per spatial and temporal layer up to the highest seen (at least
/// three temporal layers), with no chains; the first packet of every keyframe attaches it, as does the first packet
/// of a frame in a layer the current structure lacks. Each frame names its references explicitly: a base temporal
/// layer frame the previous frame of its spatial layer's base, a higher temporal layer frame the latest frame of a
/// lower temporal layer of its spatial layer, and a higher spatial layer of a keyframe the frame below it; these are
/// the references of the usual `LxTy` scalability modes.
///
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
/// @spec https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension RTP Payload Format For AV1, Appendix A: Dependency Descriptor RTP Header Extension
final class Av1Packetizer implements Packetizer {
    /// The fewest temporal layers a template structure describes, so a stream that starts with base layer frames does
    /// not need a new structure for its first enhancement frame.
    private static final int MIN_TEMPORAL_LAYERS = 3;

    /// The largest payload.
    private final int maxPayloadSize;

    /// Whether to write the dependency descriptor.
    private final boolean dependencyDescriptor;

    /// The frame counter, whose low 16 bits are the frame number.
    private long frameCounter = ThreadLocalRandom.current().nextInt(0x10000);

    /// The current template structure, or `null` before the first frame.
    private DependencyDescriptor.TemplateStructure structure;

    /// The highest spatial layer of [#structure].
    private int structureSpatialLayers;

    /// The highest temporal layer of [#structure].
    private int structureTemporalLayers;

    /// The counter of the latest frame of each spatial and temporal layer, `-1` for none.
    private final long[][] latest = new long[4][8];

    /// Creates a packetizer.
    Av1Packetizer(PacketizerConfig config) {
        this.maxPayloadSize = config.maxPayloadSize();
        this.dependencyDescriptor = config.dependencyDescriptor();
        for (var layer : latest) {
            Arrays.fill(layer, -1);
        }
    }

    /// One piece of an OBU element in a packet.
    ///
    /// @param element the element's bytes
    /// @param offset  the offset of the piece in the element
    /// @param length  the length of the piece
    private record Piece(byte[] element, int offset, int length) {
    }

    @Override
    public List<PacketizedPayload> packetize(EncodedFrame frame) {
        Payloads.checkKind(frame, MediaKind.VIDEO);
        var elements = new ArrayList<byte[]>();
        var sequenceHeader = false;
        var spatial = -1;
        var temporal = -1;
        for (var obu : Obus.parseTemporalUnit(frame.data())) {
            if (obu.type() == Obus.TEMPORAL_DELIMITER || obu.type() == Obus.TILE_LIST || obu.type() == Obus.PADDING) {
                continue;
            }
            sequenceHeader |= obu.type() == Obus.SEQUENCE_HEADER;
            if (obu.extension() && spatial < 0) {
                spatial = obu.spatialId();
                temporal = obu.temporalId();
            }
            elements.add(obu.toElement());
        }
        if (spatial < 0) {
            var metadata = frame.metadata() instanceof Av1FrameMetadata av1 ? av1 : Av1FrameMetadata.none();
            spatial = metadata.spatialId();
            temporal = metadata.temporalId();
        }
        if (elements.isEmpty()) {
            throw new IllegalArgumentException("AV1 temporal unit without OBUs to send");
        }
        var capacity = maxPayloadSize - 1;
        var packets = new ArrayList<List<Piece>>();
        var current = new ArrayList<Piece>();
        var used = 0;
        for (var element : elements) {
            var offset = 0;
            while (offset < element.length) {
                var space = capacity - used;
                var length = Math.min(element.length - offset, space - 1);
                while (length > 0 && length + Obus.leb128Size(length) > space) {
                    length--;
                }
                if (length <= 0) {
                    packets.add(current);
                    current = new ArrayList<>();
                    used = 0;
                    continue;
                }
                current.add(new Piece(element, offset, length));
                used += length + Obus.leb128Size(length);
                offset += length;
                if (offset < element.length) {
                    packets.add(current);
                    current = new ArrayList<>();
                    used = 0;
                }
            }
        }
        if (!current.isEmpty()) {
            packets.add(current);
        }
        var newSequence = frame.keyframe() && sequenceHeader;
        var descriptors = dependencyDescriptor ? descriptors(frame.keyframe(), spatial, temporal, packets.size())
                : List.<ByteBuffer>of();
        var result = new ArrayList<PacketizedPayload>(packets.size());
        for (var p = 0; p < packets.size(); p++) {
            var pieces = packets.get(p);
            var first = pieces.getFirst();
            var last = pieces.getLast();
            var continuation = first.offset() > 0;
            var continues = last.offset() + last.length() < last.element().length;
            var count = pieces.size() <= 3 ? pieces.size() : 0;
            var size = 1;
            for (var i = 0; i < pieces.size(); i++) {
                var length = pieces.get(i).length();
                size += length + (count != 0 && i == pieces.size() - 1 ? 0 : Obus.leb128Size(length));
            }
            var out = ByteBuffer.allocate(size);
            out.put((byte) ((continuation ? 0x80 : 0) | (continues ? 0x40 : 0) | count << 4
                    | (newSequence && p == 0 ? 0x08 : 0)));
            for (var i = 0; i < pieces.size(); i++) {
                var piece = pieces.get(i);
                if (count == 0 || i < pieces.size() - 1) {
                    Obus.writeLeb128(out, piece.length());
                }
                out.put(piece.element(), piece.offset(), piece.length());
            }
            result.add(descriptors.isEmpty() ? PacketizedPayload.of(out.flip(), p == packets.size() - 1)
                    : new PacketizedPayload(out.flip(), p == packets.size() - 1,
                    Map.of(HeaderExtensionUris.DEPENDENCY_DESCRIPTOR, descriptors.get(p))));
        }
        return List.copyOf(result);
    }

    /// {@return the dependency descriptor value of each packet of a frame}
    ///
    /// @param keyframe whether the frame is a keyframe
    /// @param spatial  the frame's spatial layer, `0..3`
    /// @param temporal the frame's temporal layer, `0..7`
    /// @param count    the number of packets
    private List<ByteBuffer> descriptors(boolean keyframe, int spatial, int temporal, int count) {
        var key = keyframe && spatial == 0;
        var attach = structure == null || key || spatial > structureSpatialLayers
                || temporal > structureTemporalLayers;
        if (attach) {
            structureSpatialLayers = Math.max(structureSpatialLayers, spatial);
            structureTemporalLayers = Math.max(Math.max(structureTemporalLayers, temporal), MIN_TEMPORAL_LAYERS - 1);
            structure = structure(structureSpatialLayers, structureTemporalLayers);
        }
        if (key) {
            for (var layer : latest) {
                Arrays.fill(layer, -1);
            }
        }
        frameCounter++;
        var references = new ArrayList<Integer>();
        if (!key) {
            long reference = -1;
            if (keyframe && spatial > 0) {
                reference = latest[spatial - 1][0];
            } else if (temporal == 0) {
                reference = latest[spatial][0];
            } else {
                for (var lower = 0; lower < temporal; lower++) {
                    reference = Math.max(reference, latest[spatial][lower]);
                }
            }
            if (reference >= 0 && frameCounter - reference <= 4096) {
                references.add((int) (frameCounter - reference));
            }
        }
        latest[spatial][temporal] = frameCounter;
        var indications = indications(spatial, temporal, structureSpatialLayers, structureTemporalLayers,
                keyframe ? DependencyDescriptor.DecodeTargetIndication.SWITCH
                        : DependencyDescriptor.DecodeTargetIndication.REQUIRED);
        var templateIndex = spatial * (structureTemporalLayers + 1) + temporal;
        var result = new ArrayList<ByteBuffer>(count);
        for (var p = 0; p < count; p++) {
            var descriptor = new DependencyDescriptor(p == 0, p == count - 1, templateIndex,
                    (int) (frameCounter & 0xFFFF), attach && p == 0 ? Optional.of(structure) : Optional.empty(),
                    OptionalLong.empty(), spatial, temporal, indications, references, List.of());
            var value = ByteBuffer.allocate(descriptor.encodedLength(structure));
            descriptor.writeTo(value, structure);
            result.add(value.flip().asReadOnlyBuffer());
        }
        return result;
    }

    /// {@return the template structure of a stream with layers up to `spatialLayers` and `temporalLayers`: one
    /// template and one decode target per layer pair, spatial major, without chains}
    private static DependencyDescriptor.TemplateStructure structure(int spatialLayers, int temporalLayers) {
        var templates = new ArrayList<DependencyDescriptor.FrameDependencyTemplate>();
        for (var spatial = 0; spatial <= spatialLayers; spatial++) {
            for (var temporal = 0; temporal <= temporalLayers; temporal++) {
                templates.add(new DependencyDescriptor.FrameDependencyTemplate(spatial, temporal,
                        indications(spatial, temporal, spatialLayers, temporalLayers,
                                DependencyDescriptor.DecodeTargetIndication.REQUIRED), List.of(), List.of()));
            }
        }
        return new DependencyDescriptor.TemplateStructure(0, (spatialLayers + 1) * (temporalLayers + 1), templates,
                0, List.of(), List.of());
    }

    /// {@return the indication of a frame of a layer for every decode target: `present` for the decode targets whose
    /// spatial and temporal layers are at least the frame's, `NOT_PRESENT` for the others}
    private static List<DependencyDescriptor.DecodeTargetIndication> indications(
            int spatial, int temporal, int spatialLayers, int temporalLayers,
            DependencyDescriptor.DecodeTargetIndication present) {
        var result = new ArrayList<DependencyDescriptor.DecodeTargetIndication>();
        for (var targetSpatial = 0; targetSpatial <= spatialLayers; targetSpatial++) {
            for (var targetTemporal = 0; targetTemporal <= temporalLayers; targetTemporal++) {
                result.add(spatial <= targetSpatial && temporal <= targetTemporal ? present
                        : DependencyDescriptor.DecodeTargetIndication.NOT_PRESENT);
            }
        }
        return List.copyOf(result);
    }
}
