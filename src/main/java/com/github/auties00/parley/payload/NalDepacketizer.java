package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.FrameMetadata;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

/// The depacketizer of the NAL-unit formats, H.264 and H.265: it rebuilds an Annex B access unit from single NAL
/// unit, aggregation and fragmentation packets.
///
/// It remembers the last parameter set of each type, seeded from the format parameters, and inserts the missing ones
/// before a random access picture, so the frame it reports as a keyframe decodes on its own. A random access picture
/// whose parameter sets were never seen is not reported as a keyframe. When the units carry decoding order numbers
/// (H.265 with `sprop-max-don-diff` above zero), the NAL units of an access unit are put back in decoding order.
abstract sealed class NalDepacketizer implements Depacketizer permits H264Depacketizer, H265Depacketizer {
    /// The last parameter set of each type, by type, in the order they precede a random access picture.
    private final Map<Integer, ByteBuffer> parameterSets = new LinkedHashMap<>();

    /// The resolution of the last sequence parameter set seen.
    private Optional<Resolution> lastResolution = Optional.empty();

    /// Creates a depacketizer.
    ///
    /// @param initialSets the parameter sets the format parameters declare
    NalDepacketizer(List<ByteBuffer> initialSets) {
        for (var type : parameterSetTypes()) {
            parameterSets.put(type, null);
        }
        for (var set : initialSets) {
            remember(set);
        }
    }

    /// One unit of a payload: a whole NAL unit or a fragment of one.
    sealed interface Unit {
        /// A whole NAL unit.
        ///
        /// @param nal the NAL unit, header included
        /// @param don its decoding order number, when the stream carries them
        record Whole(ByteBuffer nal, OptionalInt don) implements Unit {
            /// Creates a unit without a decoding order number.
            Whole(ByteBuffer nal) {
                this(nal, OptionalInt.empty());
            }
        }

        /// A fragment of a NAL unit.
        ///
        /// @param header the reconstructed NAL unit header
        /// @param start  whether the fragment starts the NAL unit
        /// @param end    whether the fragment ends it
        /// @param data   the fragment's bytes after the header
        /// @param don    the decoding order number of the NAL unit, which its first fragment carries when the stream
        ///               has them
        record Fragment(byte[] header, boolean start, boolean end, ByteBuffer data, OptionalInt don) implements Unit {
            /// Creates a fragment without a decoding order number.
            Fragment(byte[] header, boolean start, boolean end, ByteBuffer data) {
                this(header, start, end, data, OptionalInt.empty());
            }
        }
    }

    /// {@return the units of a payload}
    ///
    /// @throws PayloadFormatException if the payload is malformed or uses a packet type the format forbids
    abstract List<Unit> units(ByteBuffer payload) throws PayloadFormatException;

    /// {@return the NAL unit type of a NAL unit or header}
    abstract int type(ByteBuffer nal);

    /// {@return the header size}
    abstract int headerSize();

    /// {@return the parameter set types, in the order they precede a random access picture}
    abstract int[] parameterSetTypes();

    /// {@return the sequence parameter set type}
    abstract int spsType();

    /// {@return whether a type is a random access picture's slice}
    abstract boolean isRandomAccess(int type);

    /// {@return whether a NAL unit (or the start of one) begins an access unit}
    abstract boolean startsAccessUnit(ByteBuffer nalStart);

    /// {@return the resolution of a sequence parameter set}
    abstract Optional<Resolution> resolution(ByteBuffer sps);

    /// {@return the temporal layer of a NAL unit header}
    abstract int temporalId(ByteBuffer nal);

    /// {@return the metadata of an access unit}
    abstract FrameMetadata metadata(boolean randomAccess, int temporalId, List<Integer> types,
                                    Optional<Resolution> resolution);

    @Override
    public final PacketBoundaries inspect(RtpPacket packet) {
        List<Unit> units;
        try {
            units = units(packet.payload());
        } catch (PayloadFormatException exception) {
            return PacketBoundaries.invalid();
        }
        var start = false;
        var keyframe = false;
        var temporal = 0;
        for (var i = 0; i < units.size(); i++) {
            var head = switch (units.get(i)) {
                case Unit.Whole whole -> whole.nal();
                case Unit.Fragment fragment -> fragmentStart(fragment);
            };
            var type = type(head);
            keyframe |= isRandomAccess(type) || type == spsType();
            temporal = temporalId(head);
            if (i == 0) {
                start = switch (units.get(i)) {
                    case Unit.Whole whole -> startsAccessUnit(whole.nal());
                    case Unit.Fragment fragment -> fragment.start() && startsAccessUnit(head);
                };
            }
        }
        return new PacketBoundaries(true, start, packet.marker(), false, keyframe, 0, temporal);
    }

    /// {@return the reconstructed header of a fragment followed by its data}
    private static ByteBuffer fragmentStart(Unit.Fragment fragment) {
        var buffer = ByteBuffer.allocate(fragment.header().length + Math.min(fragment.data().remaining(), 8));
        buffer.put(fragment.header());
        buffer.put(fragment.data().slice(fragment.data().position(), buffer.remaining()));
        return buffer.flip();
    }

    @Override
    public final EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException {
        Payloads.checkRun(packetsOfOneFrame);
        // Whole NAL units stay views of the packets, which outlive this call; a fragmented one is joined once, into
        // an array of its exact size, from the fragments collected until its end
        var nals = new ArrayList<ByteBuffer>();
        var dons = new ArrayList<Integer>();
        List<ByteBuffer> pending = null;
        byte[] pendingHeader = null;
        var pendingSize = 0;
        var pendingDon = -1;
        for (var packet : packetsOfOneFrame) {
            for (var unit : units(packet.payload())) {
                switch (unit) {
                    case Unit.Whole whole -> {
                        if (pending != null) {
                            throw new PayloadFormatException("NAL unit inside an unfinished fragmented NAL unit");
                        }
                        nals.add(whole.nal());
                        dons.add(whole.don().orElse(-1));
                    }
                    case Unit.Fragment fragment -> {
                        if (fragment.start()) {
                            if (pending != null) {
                                throw new PayloadFormatException("fragmentation unit restarted before its end");
                            }
                            pending = new ArrayList<>();
                            pendingHeader = fragment.header();
                            pendingSize = pendingHeader.length;
                            pendingDon = fragment.don().orElse(-1);
                        } else if (pending == null) {
                            throw new PayloadFormatException("fragmentation unit without its start");
                        }
                        pending.add(fragment.data());
                        pendingSize += fragment.data().remaining();
                        if (fragment.end()) {
                            var nal = new byte[pendingSize];
                            System.arraycopy(pendingHeader, 0, nal, 0, pendingHeader.length);
                            var at = pendingHeader.length;
                            for (var index = 0; index < pending.size(); index++) {
                                var data = pending.get(index);
                                data.get(data.position(), nal, at, data.remaining());
                                at += data.remaining();
                            }
                            nals.add(ByteBuffer.wrap(nal).asReadOnlyBuffer());
                            dons.add(pendingDon);
                            pending = null;
                        }
                    }
                }
            }
        }
        if (pending != null) {
            throw new PayloadFormatException("fragmentation unit without its end");
        }
        decodingOrder(nals, dons);
        if (nals.isEmpty()) {
            throw new PayloadFormatException("access unit without NAL units");
        }
        var present = new HashSet<Integer>();
        var firstRandomAccess = -1;
        var resolution = Optional.<Resolution>empty();
        var temporal = 0;
        for (var i = 0; i < nals.size(); i++) {
            var nal = nals.get(i);
            var type = type(nal);
            if (parameterSets.containsKey(type)) {
                remember(nal);
                present.add(type);
                if (type == spsType()) {
                    var parsed = resolution(nal);
                    if (parsed.isPresent()) {
                        resolution = parsed;
                        lastResolution = parsed;
                    }
                }
            } else if (firstRandomAccess < 0 && isRandomAccess(type)) {
                firstRandomAccess = i;
            }
            temporal = temporalId(nal);
        }
        var keyframe = false;
        if (firstRandomAccess >= 0) {
            var missing = new ArrayList<ByteBuffer>();
            keyframe = true;
            for (var entry : parameterSets.entrySet()) {
                if (present.contains(entry.getKey())) {
                    continue;
                }
                if (entry.getValue() == null) {
                    keyframe = false;
                } else {
                    missing.add(entry.getValue().duplicate());
                }
            }
            nals.addAll(firstRandomAccess, missing);
        }
        var types = new ArrayList<Integer>(nals.size());
        var total = 0;
        for (var index = 0; index < nals.size(); index++) {
            total += NalUnits.START_CODE.length + nals.get(index).remaining();
        }
        var out = new byte[total];
        var at = 0;
        for (var index = 0; index < nals.size(); index++) {
            var nal = nals.get(index);
            System.arraycopy(NalUnits.START_CODE, 0, out, at, NalUnits.START_CODE.length);
            at += NalUnits.START_CODE.length;
            nal.get(nal.position(), out, at, nal.remaining());
            at += nal.remaining();
            types.add(type(nal));
        }
        var first = packetsOfOneFrame.getFirst();
        return new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(out), first.timestamp(), keyframe,
                Optional.empty(), metadata(firstRandomAccess >= 0, temporal, types,
                resolution.isPresent() ? resolution : lastResolution));
    }

    /// Puts NAL units that carry decoding order numbers back in decoding order: by their 16-bit numbers relative to
    /// the first one, keeping the transmission order of equal numbers; units without numbers keep their order.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc7798.html#section-6 RFC 7798 section 6: Packetization Rules
    private static void decodingOrder(List<ByteBuffer> nals, List<Integer> dons) {
        if (dons.isEmpty() || dons.contains(-1)) {
            return;
        }
        var base = dons.getFirst();
        var order = new ArrayList<Integer>(nals.size());
        for (var index = 0; index < nals.size(); index++) {
            order.add(index);
        }
        order.sort(java.util.Comparator.comparingInt(index -> (short) (dons.get(index) - base)));
        var sorted = new ArrayList<ByteBuffer>(nals.size());
        for (var index : order) {
            sorted.add(nals.get(index));
        }
        nals.clear();
        nals.addAll(sorted);
    }

    /// Stores a copy of a parameter set as the last one of its type.
    private void remember(ByteBuffer nal) {
        if (nal.remaining() >= headerSize() && parameterSets.containsKey(type(nal))) {
            parameterSets.put(type(nal), NalUnits.copy(nal));
            if (type(nal) == spsType()) {
                var parsed = resolution(nal);
                if (parsed.isPresent()) {
                    lastResolution = parsed;
                }
            }
        }
    }
}
