package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Av1FrameMetadata;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.github.auties00.parley.payload.Av1PayloadTest.obu;
import static com.github.auties00.parley.payload.TestPackets.packets;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the AV1 packetizer's dependency descriptor and the depacketizer's temporal delimiter.
@DisplayName("AV1 dependency descriptor and temporal delimiter")
class Av1DependencyDescriptorTest {
    /// The format.
    private static final Av1Format FORMAT = new Av1Format(Codec.av1());

    /// A minimal sequence header payload.
    private static final byte[] SEQUENCE_HEADER = {0x00, 0x00, 0x00};

    /// {@return the concatenation of byte arrays}
    private static byte[] concat(byte[]... parts) {
        var out = new ByteArrayOutputStream();
        for (var part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /// {@return a temporal unit with one frame OBU of a layer, with a sequence header for a keyframe}
    private static EncodedFrame frame(boolean key, int spatial, int temporal, int size) {
        var frameObu = obu(6, temporal, spatial, true, new byte[size]);
        var data = key ? concat(obu(2, 0, 0, false, new byte[0]), obu(1, 0, 0, false, SEQUENCE_HEADER), frameObu)
                : concat(obu(2, 0, 0, false, new byte[0]), frameObu);
        return new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(data), 0, key, Optional.empty(),
                Av1FrameMetadata.none());
    }

    /// {@return the descriptors of the packets of a frame, read against the latest structure}
    private static List<DependencyDescriptor> descriptors(List<PacketizedPayload> payloads,
                                                          DependencyDescriptor.TemplateStructure[] latest)
            throws RtpFormatException {
        var result = new ArrayList<DependencyDescriptor>();
        for (var payload : payloads) {
            var value = payload.extensions().get(HeaderExtensionUris.DEPENDENCY_DESCRIPTOR);
            var descriptor = DependencyDescriptor.parse(value, Optional.ofNullable(latest[0]));
            descriptor.structure().ifPresent(structure -> latest[0] = structure);
            result.add(descriptor);
        }
        return result;
    }

    @Test
    @DisplayName("writes a descriptor on every packet, the structure on keyframes, and the L1T3 references")
    void l1t3() throws RtpFormatException {
        var packetizer = FORMAT.packetizer(PacketizerConfig.defaults().withMaxPayloadSize(200)
                .withDependencyDescriptor(true));
        var latest = new DependencyDescriptor.TemplateStructure[1];
        var key = descriptors(packetizer.packetize(frame(true, 0, 0, 500)), latest);
        assertTrue(key.size() > 1);
        assertTrue(key.getFirst().structure().isPresent());
        assertTrue(key.getFirst().startOfFrame());
        assertTrue(key.getLast().endOfFrame());
        assertTrue(key.stream().skip(1).allMatch(descriptor -> descriptor.structure().isEmpty()));
        assertTrue(key.getFirst().frameDependencies().isEmpty());
        assertEquals(3, latest[0].decodeTargetCount());
        assertTrue(key.getFirst().decodeTargetIndications().stream()
                .allMatch(indication -> indication == DependencyDescriptor.DecodeTargetIndication.SWITCH));
        var frameNumber = key.getFirst().frameNumber();
        var pattern = new int[]{2, 1, 2, 0, 2, 1, 2};
        var expected = new int[]{1, 2, 1, 4, 1, 2, 1};
        for (var i = 0; i < pattern.length; i++) {
            var delta = descriptors(packetizer.packetize(frame(false, 0, pattern[i], 50)), latest);
            assertEquals(1, delta.size());
            var descriptor = delta.getFirst();
            assertEquals((frameNumber + i + 1) & 0xFFFF, descriptor.frameNumber());
            assertEquals(pattern[i], descriptor.temporalId());
            assertTrue(descriptor.structure().isEmpty(), "no new structure for layers the first one covers");
            assertEquals(List.of(expected[i]), descriptor.frameDependencies(), "references of frame " + i);
            assertEquals(pattern[i] == 0, descriptor.decodeTargetIndications().get(0)
                    != DependencyDescriptor.DecodeTargetIndication.NOT_PRESENT);
        }
    }

    @Test
    @DisplayName("attaches a new structure for a spatial layer the current one lacks, and references the layer below")
    void spatialLayers() throws RtpFormatException {
        var packetizer = FORMAT.packetizer(PacketizerConfig.defaults().withDependencyDescriptor(true));
        var latest = new DependencyDescriptor.TemplateStructure[1];
        descriptors(packetizer.packetize(frame(true, 0, 0, 100)), latest);
        var upper = descriptors(packetizer.packetize(frame(true, 1, 0, 100)), latest).getFirst();
        assertTrue(upper.structure().isPresent());
        assertEquals(1, upper.spatialId());
        assertEquals(List.of(1), upper.frameDependencies(), "the upper layer of a keyframe references the base");
        assertEquals(6, latest[0].decodeTargetCount());
    }

    @Test
    @DisplayName("writes no descriptor unless the session negotiated it")
    void disabled() {
        for (var payload : FORMAT.packetizer(PacketizerConfig.defaults()).packetize(frame(true, 0, 0, 100))) {
            assertTrue(payload.extensions().isEmpty());
        }
    }

    @Test
    @DisplayName("restores the temporal delimiter of a base layer frame, not of a higher spatial layer's")
    void temporalDelimiter() throws PayloadFormatException {
        var packetizer = FORMAT.packetizer(PacketizerConfig.defaults());
        var base = frame(true, 0, 0, 100);
        var assembled = FORMAT.depacketizer().assemble(packets(packetizer.packetize(base), 45, 1, 0));
        assertArrayEquals(base.toByteArray(), assembled.toByteArray());
        var upper = frame(false, 1, 0, 100);
        var upperAssembled = FORMAT.depacketizer().assemble(packets(packetizer.packetize(upper), 45, 1, 0));
        var withoutDelimiter = obu(6, 0, 1, true, new byte[100]);
        assertArrayEquals(withoutDelimiter, upperAssembled.toByteArray());
        assertFalse(upperAssembled.keyframe());
    }
}
