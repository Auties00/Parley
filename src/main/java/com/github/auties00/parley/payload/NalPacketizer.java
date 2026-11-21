package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/// The packetizer of the NAL-unit formats, H.264 and H.265: a frame is an Annex B access unit, each NAL unit goes
/// into a packet of its own, several small ones into an aggregation packet, a large one into fragmentation units.
///
/// Before a random access picture whose access unit lacks a parameter set, the packetizer inserts the last one it saw
/// (or the one the format parameters declared), so a receiver that joins at the keyframe can decode it.
abstract sealed class NalPacketizer implements Packetizer permits H264Packetizer, H265Packetizer {
    /// The largest payload.
    final int maxPayloadSize;

    /// Whether aggregation and fragmentation packets may be used.
    private final boolean nonInterleaved;

    /// The last parameter set of each type, by type, in the order they precede a random access picture.
    private final Map<Integer, ByteBuffer> parameterSets = new LinkedHashMap<>();

    /// Creates a packetizer.
    ///
    /// @param config         the settings
    /// @param nonInterleaved whether aggregation and fragmentation are allowed
    /// @param initialSets    the parameter sets the format parameters declare
    NalPacketizer(PacketizerConfig config, boolean nonInterleaved, List<ByteBuffer> initialSets) {
        this.maxPayloadSize = config.maxPayloadSize();
        this.nonInterleaved = nonInterleaved;
        for (var type : parameterSetTypes()) {
            parameterSets.put(type, null);
        }
        for (var set : initialSets) {
            remember(set);
        }
    }

    /// {@return the NAL unit type of a NAL unit}
    abstract int type(ByteBuffer nal);

    /// {@return the parameter set types, in the order they precede a random access picture}
    abstract int[] parameterSetTypes();

    /// {@return whether a NAL unit type is a random access picture's slice}
    abstract boolean isRandomAccess(int type);

    /// {@return the header size of the NAL units}
    abstract int headerSize();

    /// {@return an aggregation packet holding several NAL units}
    abstract ByteBuffer aggregate(List<ByteBuffer> nals);

    /// Splits one NAL unit too large for a packet into fragmentation units, each a header the packetizer writes and
    /// a body that is a slice of the NAL unit.
    ///
    /// @param headers receives the fragmentation unit headers
    /// @param bodies  receives the bodies, in step with `headers`
    abstract void fragment(ByteBuffer nal, List<ByteBuffer> headers, List<ByteBuffer> bodies);

    @Override
    public final List<PacketizedPayload> packetize(EncodedFrame frame) {
        Payloads.checkKind(frame, MediaKind.VIDEO);
        var nals = new ArrayList<>(NalUnits.splitAnnexB(frame.data()));
        for (var nal : nals) {
            if (nal.remaining() < headerSize()) {
                throw new IllegalArgumentException("NAL unit shorter than its header");
            }
        }
        insertParameterSets(nals);
        var payloads = new ArrayList<ByteBuffer>();
        // In step with `payloads`: the fragmentation unit header of a fragment, `null` for a whole payload
        var headers = new ArrayList<ByteBuffer>();
        var i = 0;
        while (i < nals.size()) {
            var nal = nals.get(i);
            if (nal.remaining() > maxPayloadSize) {
                if (!nonInterleaved) {
                    throw new IllegalArgumentException("NAL unit of " + nal.remaining()
                            + " bytes exceeds the payload size in single NAL unit mode");
                }
                fragment(nal, headers, payloads);
                i++;
                continue;
            }
            var size = headerSize();
            var j = i;
            while (nonInterleaved && j < nals.size() && size + 2 + nals.get(j).remaining() <= maxPayloadSize) {
                size += 2 + nals.get(j).remaining();
                j++;
            }
            if (j - i >= 2) {
                payloads.add(aggregate(nals.subList(i, j)));
                i = j;
            } else {
                payloads.add(nal);
                i++;
            }
            headers.add(null);
        }
        var result = new ArrayList<PacketizedPayload>(payloads.size());
        for (var k = 0; k < payloads.size(); k++) {
            var header = headers.get(k);
            var marker = k == payloads.size() - 1;
            result.add(header == null ? PacketizedPayload.of(payloads.get(k), marker)
                    : PacketizedPayload.of(header, payloads.get(k), marker));
        }
        return List.copyOf(result);
    }

    /// Remembers the parameter sets of the access unit, and inserts the missing ones before its first random access
    /// slice.
    private void insertParameterSets(List<ByteBuffer> nals) {
        var present = new HashSet<Integer>();
        var firstRandomAccess = -1;
        for (var i = 0; i < nals.size(); i++) {
            var nal = nals.get(i);
            var type = type(nal);
            if (parameterSets.containsKey(type)) {
                remember(nal);
                if (firstRandomAccess < 0) {
                    present.add(type);
                }
            } else if (firstRandomAccess < 0 && isRandomAccess(type)) {
                firstRandomAccess = i;
            }
        }
        if (firstRandomAccess < 0) {
            return;
        }
        var missing = new ArrayList<ByteBuffer>();
        for (var entry : parameterSets.entrySet()) {
            if (!present.contains(entry.getKey()) && entry.getValue() != null) {
                missing.add(entry.getValue().duplicate());
            }
        }
        nals.addAll(firstRandomAccess, missing);
    }

    /// Stores a copy of a parameter set as the last one of its type.
    private void remember(ByteBuffer nal) {
        if (nal.remaining() >= headerSize() && parameterSets.containsKey(type(nal))) {
            parameterSets.put(type(nal), NalUnits.copy(nal));
        }
    }
}
