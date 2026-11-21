package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor;
import com.github.auties00.parley.rtp.extension.TemplateStructure;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/// A video depacketizer that takes frame boundaries, frame numbers and dependencies from the AV1 dependency
/// descriptor header extension when packets carry it, and everything else from the payload format underneath.
///
/// A packet without the extension, or whose descriptor does not parse (its template structure was lost), falls back
/// to the payload's own boundaries. A frame's id is its unwrapped 16-bit frame number and its dependencies the ids
/// its frame differences name.
///
/// @spec https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension RTP Payload Format For AV1, Appendix A: Dependency Descriptor RTP Header Extension
final class VideoDepacketizer implements Depacketizer {
    /// Reads a dependency descriptor, the seam tests replace.
    @FunctionalInterface
    interface DescriptorReader {
        /// {@return the descriptor of an extension value}
        ///
        /// @throws RtpFormatException if it does not parse
        DependencyDescriptor read(ByteBuffer value, Optional<TemplateStructure> latest) throws RtpFormatException;
    }

    /// The depacketizer of the payload format.
    private final Depacketizer inner;

    /// The negotiated id of the extension.
    private final int extensionId;

    /// The descriptor parser.
    private final DescriptorReader reader;

    /// The unwrapper of frame numbers.
    private final Unwrapper frameNumbers = new Unwrapper(16);

    /// The last template structure seen.
    private Optional<TemplateStructure> structure = Optional.empty();

    /// Creates a depacketizer.
    VideoDepacketizer(Depacketizer inner, int extensionId, DescriptorReader reader) {
        this.inner = inner;
        this.extensionId = extensionId;
        this.reader = reader;
    }

    /// {@return `inner`, wrapped to read the dependency descriptor when `config` names its extension}
    static Depacketizer withDescriptor(Depacketizer inner, DepacketizerConfig config) {
        var id = config.dependencyDescriptorExtensionId();
        return id.isPresent() ? new VideoDepacketizer(inner, id.getAsInt(), DependencyDescriptor::parse) : inner;
    }

    @Override
    public PacketBoundaries inspect(RtpPacket packet) {
        var boundaries = inner.inspect(packet);
        if (!boundaries.valid()) {
            return boundaries;
        }
        var descriptor = descriptor(packet);
        if (descriptor.isEmpty()) {
            return boundaries;
        }
        return new PacketBoundaries(true, descriptor.get().startOfFrame(), descriptor.get().endOfFrame(), true,
                boundaries.keyframe(), boundaries.spatialId(), boundaries.temporalId());
    }

    @Override
    public EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException {
        var frame = inner.assemble(packetsOfOneFrame);
        var descriptor = descriptor(packetsOfOneFrame.getFirst());
        if (descriptor.isEmpty()) {
            return frame;
        }
        var id = frameNumbers.unwrap(descriptor.get().frameNumber());
        var dependencies = new ArrayList<Long>();
        for (var difference : descriptor.get().frameDependencies()) {
            if (difference > 0 && id - difference >= 0) {
                dependencies.add(id - difference);
            }
        }
        return frame.withMetadata(frame.metadata().withDependencies(id, frame.keyframe() ? List.of() : dependencies));
    }

    /// {@return the descriptor of a packet, remembering the structure it carries}
    private Optional<DependencyDescriptor> descriptor(RtpPacket packet) {
        var value = packet.extension(extensionId);
        if (value.isEmpty()) {
            return Optional.empty();
        }
        try {
            var descriptor = reader.read(value.get(), structure);
            if (descriptor.structure().isPresent()) {
                structure = descriptor.structure();
            }
            return Optional.of(descriptor);
        } catch (RtpFormatException exception) {
            return Optional.empty();
        }
    }
}
