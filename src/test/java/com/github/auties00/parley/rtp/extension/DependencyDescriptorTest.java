package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor.DecodeTargetIndication;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor.FrameDependencyTemplate;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor.RenderResolution;
import com.github.auties00.parley.rtp.extension.DependencyDescriptor.TemplateStructure;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Random;

import static com.github.auties00.parley.rtp.extension.DependencyDescriptor.DecodeTargetIndication.DISCARDABLE;
import static com.github.auties00.parley.rtp.extension.DependencyDescriptor.DecodeTargetIndication.NOT_PRESENT;
import static com.github.auties00.parley.rtp.extension.DependencyDescriptor.DecodeTargetIndication.REQUIRED;
import static com.github.auties00.parley.rtp.extension.DependencyDescriptor.DecodeTargetIndication.SWITCH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the AV1 dependency descriptor: the L1T3 structure of the AV1 RTP specification's examples, mandatory-only
/// descriptors read against the latest structure, per-frame overrides, and random round trips.
@DisplayName("AV1 dependency descriptor")
class DependencyDescriptorTest {
    private static final HexFormat HEX = HexFormat.of();

    /// One spatial layer, three temporal layers (L1T3), three decode targets and one chain, as in the AV1 RTP
    /// specification's scalability examples.
    static TemplateStructure l1t3() {
        return new TemplateStructure(0, 3, List.of(
                new FrameDependencyTemplate(0, 0, List.of(SWITCH, SWITCH, SWITCH), List.of(), List.of(0)),
                new FrameDependencyTemplate(0, 0, List.of(SWITCH, SWITCH, SWITCH), List.of(4), List.of(4)),
                new FrameDependencyTemplate(0, 1, List.of(NOT_PRESENT, DISCARDABLE, REQUIRED), List.of(2),
                        List.of(2)),
                new FrameDependencyTemplate(0, 2, List.of(NOT_PRESENT, NOT_PRESENT, DISCARDABLE), List.of(1),
                        List.of(1)),
                new FrameDependencyTemplate(0, 2, List.of(NOT_PRESENT, NOT_PRESENT, DISCARDABLE), List.of(1),
                        List.of(3))),
                1, List.of(0, 0, 0), List.of(new RenderResolution(1280, 720)));
    }

    @Test
    @DisplayName("writes only the three mandatory bytes for a frame that uses its template unchanged")
    void mandatoryOnly() throws RtpFormatException {
        var structure = l1t3();
        var descriptor = DependencyDescriptor.fromTemplate(structure, 2, true, false, 0x1234, false);
        var encoded = new byte[descriptor.encodedLength(structure)];
        descriptor.writeTo(ByteBuffer.wrap(encoded), structure);
        assertEquals("821234", HEX.formatHex(encoded));
        var parsed = DependencyDescriptor.parse(ByteBuffer.wrap(encoded), structure);
        assertEquals(descriptor, parsed);
        assertEquals(1, parsed.temporalId());
        assertEquals(List.of(2), parsed.frameDependencies());
        var mandatory = DependencyDescriptor.readMandatoryFields(ByteBuffer.wrap(encoded));
        assertEquals(new DependencyDescriptor.MandatoryFields(true, false, 2, 0x1234), mandatory);
    }

    @Test
    @DisplayName("attaches the structure on a keyframe and parses without a previous structure")
    void attached() throws RtpFormatException {
        var structure = l1t3();
        var keyframe = DependencyDescriptor.fromTemplate(structure, 0, true, true, 1, true);
        var encoded = keyframe.encode();
        assertTrue(encoded.remaining() > 16);
        var parsed = DependencyDescriptor.parse(encoded);
        assertEquals(keyframe, parsed);
        assertEquals(structure, parsed.structure().orElseThrow());
        assertEquals(2, structure.decodeTargetTemporalId(2));
        assertEquals(1, structure.decodeTargetTemporalId(1));
        assertEquals(0, structure.decodeTargetSpatialId(2));
    }

    @Test
    @DisplayName("writes per-frame decode target, frame diff and chain overrides")
    void overrides() throws RtpFormatException {
        var structure = l1t3();
        var descriptor = new DependencyDescriptor(false, true, 3, 77, Optional.empty(), OptionalLong.of(0b011), 0, 2,
                List.of(NOT_PRESENT, REQUIRED, REQUIRED), List.of(1, 20, 300, 4096), List.of(200));
        var buffer = ByteBuffer.allocate(descriptor.encodedLength(structure));
        descriptor.writeTo(buffer, structure);
        var parsed = DependencyDescriptor.parse(buffer.flip(), structure);
        assertEquals(descriptor, parsed);
    }

    @Test
    @DisplayName("fails without a structure, or with a template id the structure lacks")
    void failures() {
        assertThrows(RtpFormatException.class,
                () -> DependencyDescriptor.parse(ByteBuffer.wrap(HEX.parseHex("800001"))));
        assertThrows(RtpFormatException.class,
                () -> DependencyDescriptor.parse(ByteBuffer.wrap(HEX.parseHex("8a0001")), l1t3()));
        var unattached = DependencyDescriptor.fromTemplate(l1t3(), 0, true, true, 1, false);
        assertThrows(IllegalStateException.class, unattached::encode);
    }

    @Test
    @DisplayName("rejects templates out of layer order")
    void layerOrder() {
        assertThrows(IllegalArgumentException.class, () -> new TemplateStructure(0, 1, List.of(
                new FrameDependencyTemplate(0, 0, List.of(SWITCH), List.of(), List.of()),
                new FrameDependencyTemplate(0, 2, List.of(SWITCH), List.of(), List.of())), 0, List.of(), List.of()));
    }

    @RepeatedTest(100)
    @DisplayName("round-trips random structures and frames")
    void randomRoundTrip() throws RtpFormatException {
        var random = new Random();
        var decodeTargets = random.nextInt(1, 6);
        var chains = random.nextInt(0, decodeTargets + 1);
        var templates = new ArrayList<FrameDependencyTemplate>();
        var spatial = 0;
        var temporal = 0;
        for (var t = random.nextInt(1, 12); t > 0; t--) {
            templates.add(randomTemplate(random, spatial, temporal, decodeTargets, chains));
            switch (random.nextInt(3)) {
                case 1 -> {
                    if (temporal < 7) {
                        temporal++;
                    }
                }
                case 2 -> {
                    if (spatial < 3) {
                        spatial++;
                        temporal = 0;
                    }
                }
                default -> {
                }
            }
        }
        var protectedBy = new ArrayList<Integer>();
        for (var d = 0; chains > 0 && d < decodeTargets; d++) {
            protectedBy.add(random.nextInt(chains));
        }
        var resolutions = new ArrayList<RenderResolution>();
        if (random.nextBoolean()) {
            for (var s = 0; s <= templates.getLast().spatialId(); s++) {
                resolutions.add(new RenderResolution(random.nextInt(1, 65537), random.nextInt(1, 65537)));
            }
        }
        var structure = new TemplateStructure(random.nextInt(64), decodeTargets, templates, chains, protectedBy,
                resolutions);
        var index = random.nextInt(templates.size());
        var template = templates.get(index);
        var dtis = template.decodeTargetIndications();
        var fdiffs = template.frameDiffs();
        var chainDiffs = template.chainDiffs();
        if (random.nextBoolean()) {
            dtis = randomTemplate(random, 0, 0, decodeTargets, chains).decodeTargetIndications();
        }
        if (random.nextBoolean()) {
            var list = new ArrayList<Integer>();
            for (var i = random.nextInt(4); i > 0; i--) {
                list.add(random.nextInt(1, 4097));
            }
            fdiffs = list;
        }
        if (random.nextBoolean()) {
            var list = new ArrayList<Integer>();
            for (var i = 0; i < chains; i++) {
                list.add(random.nextInt(256));
            }
            chainDiffs = list;
        }
        var attach = random.nextBoolean();
        var descriptor = new DependencyDescriptor(random.nextBoolean(), random.nextBoolean(),
                (structure.templateIdOffset() + index) % 64, random.nextInt(65536),
                attach ? Optional.of(structure) : Optional.empty(),
                random.nextBoolean() ? OptionalLong.of(random.nextLong(1L << decodeTargets)) : OptionalLong.empty(),
                template.spatialId(), template.temporalId(), dtis, fdiffs, chainDiffs);
        var buffer = ByteBuffer.allocate(descriptor.encodedLength(structure));
        descriptor.writeTo(buffer, structure);
        assertEquals(descriptor, attach ? DependencyDescriptor.parse(buffer.flip())
                : DependencyDescriptor.parse(buffer.flip(), structure));
    }

    private static FrameDependencyTemplate randomTemplate(Random random, int spatial, int temporal, int decodeTargets,
                                                          int chains) {
        var dtis = new ArrayList<DecodeTargetIndication>();
        for (var d = 0; d < decodeTargets; d++) {
            dtis.add(DecodeTargetIndication.values()[random.nextInt(4)]);
        }
        var fdiffs = new ArrayList<Integer>();
        for (var i = random.nextInt(4); i > 0; i--) {
            fdiffs.add(random.nextInt(1, 17));
        }
        var chainDiffs = new ArrayList<Integer>();
        for (var c = 0; c < chains; c++) {
            chainDiffs.add(random.nextInt(16));
        }
        return new FrameDependencyTemplate(spatial, temporal, dtis, fdiffs, chainDiffs);
    }

    @RepeatedTest(10)
    @DisplayName("throws only RtpFormatException on random descriptors")
    void fuzz() {
        var random = new Random();
        for (var i = 0; i < 2_000; i++) {
            var data = new byte[random.nextInt(40)];
            random.nextBytes(data);
            try {
                if (random.nextBoolean()) {
                    DependencyDescriptor.parse(ByteBuffer.wrap(data), l1t3());
                } else {
                    DependencyDescriptor.parse(ByteBuffer.wrap(data));
                }
            } catch (RtpFormatException expected) {
                // malformed descriptors are reported, never anything else
            }
        }
    }
}
