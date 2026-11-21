package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Av1FrameMetadata;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.rtp.RtpPacket;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/// The AV1 depacketizer of the AV1 RTP payload format.
///
/// It reassembles the OBU elements of the packets, joining fragments across packets, and writes them back in
/// low-overhead bitstream format, each OBU with `obu_has_size_field` set and its size. A frame is a keyframe when its
/// first packet sets `N`, or when it carries a sequence header and a shown key frame. The resolution is the maximum
/// frame size of the latest sequence header.
///
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
final class Av1Depacketizer implements Depacketizer {
    /// The latest sequence header fields of the stream.
    private Optional<Obus.SequenceInfo> sequence = Optional.empty();

    /// The parsed aggregation header and OBU elements of one packet.
    ///
    /// @param continuation the `Z` bit
    /// @param continues    the `Y` bit
    /// @param newSequence  the `N` bit
    /// @param elements     the elements
    private record Elements(boolean continuation, boolean continues, boolean newSequence, List<ByteBuffer> elements) {
    }

    /// Parses the aggregation header and elements of a payload.
    private static Elements elements(ByteBuffer payload) throws PayloadFormatException {
        if (payload.remaining() < 2) {
            throw new PayloadFormatException("truncated AV1 payload");
        }
        var start = payload.position();
        var header = Payloads.u8(payload, start);
        var count = (header >>> 4) & 0x03;
        var newSequence = (header & 0x08) != 0;
        var continuation = (header & 0x80) != 0;
        if (newSequence && continuation) {
            throw new PayloadFormatException("AV1 N bit on a continuation packet");
        }
        var result = new ArrayList<ByteBuffer>();
        var offset = start + 1;
        while (offset < payload.limit()) {
            int length;
            if (count != 0 && result.size() == count - 1) {
                length = payload.limit() - offset;
            } else {
                var value = Obus.readLeb128(payload, offset, payload.limit());
                offset += Obus.leb128Size(value);
                if (value > payload.limit() - offset) {
                    throw new PayloadFormatException("AV1 OBU element overruns the payload");
                }
                length = (int) value;
            }
            if (length == 0) {
                throw new PayloadFormatException("empty AV1 OBU element");
            }
            result.add(payload.slice(offset, length));
            offset += length;
        }
        if (result.isEmpty() || count != 0 && result.size() != count) {
            throw new PayloadFormatException("AV1 element count does not match W");
        }
        return new Elements(continuation, (header & 0x40) != 0, newSequence, result);
    }

    @Override
    public PacketBoundaries inspect(RtpPacket packet) {
        Elements parsed;
        try {
            parsed = elements(packet.payload());
        } catch (PayloadFormatException exception) {
            return PacketBoundaries.invalid();
        }
        var keyframe = parsed.newSequence();
        var start = false;
        var temporal = 0;
        var spatial = 0;
        if (!parsed.continuation()) {
            var first = parsed.elements().getFirst();
            var obuHeader = first.get(first.position()) & 0xFF;
            var type = (obuHeader >>> 3) & 0x0F;
            keyframe |= type == Obus.SEQUENCE_HEADER;
            start = parsed.newSequence() || type == Obus.SEQUENCE_HEADER || type == Obus.FRAME_HEADER
                    || type == Obus.FRAME;
            if ((obuHeader & 0x04) != 0 && first.remaining() > 1) {
                var ext = first.get(first.position() + 1) & 0xFF;
                temporal = ext >>> 5;
                spatial = (ext >>> 3) & 0x03;
            }
        }
        return new PacketBoundaries(true, start, packet.marker(), false, keyframe, spatial, temporal);
    }

    @Override
    public EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException {
        Payloads.checkRun(packetsOfOneFrame);
        var obus = new ArrayList<Obus.Obu>();
        ByteArrayOutputStream pending = null;
        var newSequence = false;
        for (var p = 0; p < packetsOfOneFrame.size(); p++) {
            var parsed = elements(packetsOfOneFrame.get(p).payload());
            if (p == 0) {
                if (parsed.continuation()) {
                    throw new PayloadFormatException("AV1 frame starts with a continuation");
                }
                newSequence = parsed.newSequence();
            } else if (parsed.continuation() != (pending != null)) {
                throw new PayloadFormatException("AV1 fragment continuity broken");
            }
            var elements = parsed.elements();
            for (var i = 0; i < elements.size(); i++) {
                var element = elements.get(i);
                var bytes = new byte[element.remaining()];
                element.get(element.position(), bytes);
                if (i == 0 && pending != null) {
                    pending.writeBytes(bytes);
                    bytes = pending.toByteArray();
                    pending = null;
                }
                if (i == elements.size() - 1 && parsed.continues()) {
                    pending = new ByteArrayOutputStream();
                    pending.writeBytes(bytes);
                    continue;
                }
                var buffer = ByteBuffer.wrap(bytes);
                obus.add(Obus.parse(buffer, 0, bytes.length, false));
            }
        }
        if (pending != null) {
            throw new PayloadFormatException("AV1 frame ends inside a fragmented OBU");
        }
        var out = new ByteArrayOutputStream();
        var hasSequenceHeader = false;
        var keyFrame = false;
        var temporal = 0;
        var spatial = 0;
        var layerKnown = false;
        for (var obu : obus) {
            if (obu.type() == Obus.SEQUENCE_HEADER) {
                hasSequenceHeader = true;
                var info = Obus.parseSequenceHeader(obu.payload());
                if (info.isPresent()) {
                    sequence = info;
                }
            }
            if ((obu.type() == Obus.FRAME || obu.type() == Obus.FRAME_HEADER) && hasSequenceHeader && !keyFrame) {
                keyFrame = Obus.isKeyFrame(obu.payload(),
                        sequence.map(Obus.SequenceInfo::reducedStillPictureHeader).orElse(false));
            }
            if (obu.extension() && !layerKnown) {
                temporal = obu.temporalId();
                spatial = obu.spatialId();
                layerKnown = true;
            }
            obu.writeLowOverhead(out);
        }
        var keyframe = newSequence || keyFrame;
        var resolution = sequence.flatMap(Obus.SequenceInfo::maxResolution);
        var metadata = new Av1FrameMetadata(spatial, temporal, hasSequenceHeader, newSequence,
                resolution, OptionalLong.empty(), List.of());
        return new EncodedFrame(MediaKind.VIDEO, ByteBuffer.wrap(out.toByteArray()),
                packetsOfOneFrame.getFirst().timestamp(), keyframe, Optional.empty(), metadata);
    }

    /// {@return the maximum frame size of the latest sequence header, for tests}
    Optional<Resolution> lastResolution() {
        return sequence.flatMap(Obus.SequenceInfo::maxResolution);
    }
}
