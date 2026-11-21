package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Resolution;
import com.github.auties00.parley.media.Vp9ScalabilityStructure;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/// The VP9 payload descriptor of RFC 9628, with its scalability structure.
///
/// ```text
///      0 1 2 3 4 5 6 7
///     +-+-+-+-+-+-+-+-+
///     |I|P|L|F|B|E|V|Z| (REQUIRED)
///     +-+-+-+-+-+-+-+-+
/// I:  |M| PICTURE ID  | (RECOMMENDED)
///     +-+-+-+-+-+-+-+-+
/// M:  | EXTENDED PID  | (RECOMMENDED)
///     +-+-+-+-+-+-+-+-+
/// L:  | TID |U| SID |D| (Conditionally RECOMMENDED)
///     +-+-+-+-+-+-+-+-+
///     |   TL0PICIDX   | (non-flexible mode only)
///     +-+-+-+-+-+-+-+-+
/// P,F:| P_DIFF      |N| (flexible mode only, up to 3 times)
///     +-+-+-+-+-+-+-+-+
/// V:  | SS            |
///     | ..            |
///     +-+-+-+-+-+-+-+-+
/// ```
///
/// @param interPicturePredicted the `P` bit
/// @param flexible              the `F` bit
/// @param begin                 the `B` bit
/// @param end                   the `E` bit
/// @param notUpperReference     the `Z` bit
/// @param pictureId             the picture id
/// @param longPictureId         whether the picture id has 15 bits
/// @param layered               whether the layer indices are present (`L`)
/// @param temporalId            the `TID`
/// @param switchingUpPoint      the `U` bit
/// @param spatialId             the `SID`
/// @param interLayerPredicted   the `D` bit
/// @param tl0PicIndex           the `TL0PICIDX`
/// @param referenceDiffs        the `P_DIFF` values
/// @param structure             the scalability structure
/// @param size                  the encoded size of the descriptor
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html#section-4.2 RFC 9628 section 4.2: VP9 Payload Descriptor
record Vp9Descriptor(boolean interPicturePredicted, boolean flexible, boolean begin, boolean end,
                     boolean notUpperReference, OptionalInt pictureId, boolean longPictureId, boolean layered,
                     int temporalId, boolean switchingUpPoint, int spatialId, boolean interLayerPredicted,
                     OptionalInt tl0PicIndex, List<Integer> referenceDiffs,
                     Optional<Vp9ScalabilityStructure> structure, int size) {
    /// Parses the descriptor at the position of a payload.
    ///
    /// @throws PayloadFormatException if it is truncated, inconsistent, or leaves no payload
    static Vp9Descriptor parse(ByteBuffer payload) throws PayloadFormatException {
        var reader = new Cursor(payload);
        var first = reader.next();
        var hasPictureId = (first & 0x80) != 0;
        var predicted = (first & 0x40) != 0;
        var layered = (first & 0x20) != 0;
        var flexible = (first & 0x10) != 0;
        var begin = (first & 0x08) != 0;
        var end = (first & 0x04) != 0;
        var hasStructure = (first & 0x02) != 0;
        var notUpper = (first & 0x01) != 0;
        var pictureId = OptionalInt.empty();
        var longPictureId = false;
        if (hasPictureId) {
            var high = reader.next();
            if ((high & 0x80) != 0) {
                pictureId = OptionalInt.of((high & 0x7F) << 8 | reader.next());
                longPictureId = true;
            } else {
                pictureId = OptionalInt.of(high);
            }
        }
        var temporalId = 0;
        var switchingUp = false;
        var spatialId = 0;
        var interLayer = false;
        var tl0 = OptionalInt.empty();
        if (layered) {
            var layers = reader.next();
            temporalId = layers >>> 5;
            switchingUp = (layers & 0x10) != 0;
            spatialId = (layers >>> 1) & 0x07;
            interLayer = (layers & 0x01) != 0;
            if (!flexible) {
                tl0 = OptionalInt.of(reader.next());
            }
        }
        var diffs = new ArrayList<Integer>(3);
        if (flexible && predicted) {
            int value;
            do {
                if (diffs.size() == 3) {
                    throw new PayloadFormatException("more than 3 VP9 reference indices");
                }
                value = reader.next();
                if (value >>> 1 == 0) {
                    throw new PayloadFormatException("zero VP9 P_DIFF");
                }
                diffs.add(value >>> 1);
            } while ((value & 0x01) != 0);
        }
        var structure = Optional.<Vp9ScalabilityStructure>empty();
        if (hasStructure) {
            structure = Optional.of(parseStructure(reader));
        }
        if (!reader.hasRemaining()) {
            throw new PayloadFormatException("VP9 payload without data after its descriptor");
        }
        return new Vp9Descriptor(predicted, flexible, begin, end, notUpper, pictureId, longPictureId, layered,
                temporalId, switchingUp, spatialId, interLayer, tl0, List.copyOf(diffs), structure,
                reader.offset - payload.position());
    }

    /// Parses a scalability structure.
    private static Vp9ScalabilityStructure parseStructure(Cursor reader) throws PayloadFormatException {
        var header = reader.next();
        var spatialLayers = (header >>> 5) + 1;
        var hasResolutions = (header & 0x10) != 0;
        var hasGroup = (header & 0x08) != 0;
        var resolutions = new ArrayList<Resolution>();
        if (hasResolutions) {
            for (var i = 0; i < spatialLayers; i++) {
                var width = reader.next() << 8 | reader.next();
                var height = reader.next() << 8 | reader.next();
                if (width == 0 || height == 0) {
                    throw new PayloadFormatException("zero VP9 layer resolution");
                }
                resolutions.add(new Resolution(width, height));
            }
        }
        var group = new ArrayList<Vp9ScalabilityStructure.PictureGroupEntry>();
        if (hasGroup) {
            var count = reader.next();
            for (var i = 0; i < count; i++) {
                var entry = reader.next();
                var references = (entry >>> 2) & 0x03;
                var diffs = new ArrayList<Integer>(references);
                for (var r = 0; r < references; r++) {
                    var diff = reader.next();
                    if (diff == 0) {
                        throw new PayloadFormatException("zero VP9 picture group P_DIFF");
                    }
                    diffs.add(diff);
                }
                group.add(new Vp9ScalabilityStructure.PictureGroupEntry(entry >>> 5, (entry & 0x10) != 0, diffs));
            }
        }
        return new Vp9ScalabilityStructure(spatialLayers, resolutions, group);
    }

    /// {@return the encoded size of a scalability structure}
    static int sizeOf(Vp9ScalabilityStructure structure) {
        var size = 1 + 4 * structure.resolutions().size();
        if (!structure.pictureGroup().isEmpty()) {
            size++;
            for (var entry : structure.pictureGroup()) {
                size += 1 + entry.referenceDiffs().size();
            }
        }
        return size;
    }

    /// Writes a scalability structure.
    static void writeStructure(ByteBuffer out, Vp9ScalabilityStructure structure) {
        var hasGroup = !structure.pictureGroup().isEmpty();
        out.put((byte) ((structure.spatialLayers() - 1) << 5 | (structure.resolutions().isEmpty() ? 0 : 0x10)
                | (hasGroup ? 0x08 : 0)));
        for (var resolution : structure.resolutions()) {
            out.putShort((short) resolution.width());
            out.putShort((short) resolution.height());
        }
        if (hasGroup) {
            out.put((byte) structure.pictureGroup().size());
            for (var entry : structure.pictureGroup()) {
                out.put((byte) (entry.temporalId() << 5 | (entry.switchingUpPoint() ? 0x10 : 0)
                        | entry.referenceDiffs().size() << 2));
                for (var diff : entry.referenceDiffs()) {
                    out.put((byte) (int) diff);
                }
            }
        }
    }

    /// Reads the bytes of a descriptor, failing at the end of the payload.
    private static final class Cursor {
        /// The payload.
        private final ByteBuffer payload;

        /// The absolute offset of the next byte.
        private int offset;

        /// Creates a cursor at the payload's position.
        Cursor(ByteBuffer payload) {
            this.payload = payload;
            this.offset = payload.position();
        }

        /// {@return the next unsigned byte}
        ///
        /// @throws PayloadFormatException at the end of the payload
        int next() throws PayloadFormatException {
            if (offset >= payload.limit()) {
                throw new PayloadFormatException("truncated VP9 payload descriptor");
            }
            return payload.get(offset++) & 0xFF;
        }

        /// {@return whether bytes remain}
        boolean hasRemaining() {
            return offset < payload.limit();
        }
    }
}
