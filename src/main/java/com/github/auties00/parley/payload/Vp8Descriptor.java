package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;
import java.util.OptionalInt;

/// The VP8 payload descriptor of RFC 7741.
///
/// ```text
///      0 1 2 3 4 5 6 7
///     +-+-+-+-+-+-+-+-+
///     |X|R|N|S|R| PID | (REQUIRED)
///     +-+-+-+-+-+-+-+-+
/// X:  |I|L|T|K| RSV   | (OPTIONAL)
///     +-+-+-+-+-+-+-+-+
/// I:  |M| PictureID   | (OPTIONAL)
///     +-+-+-+-+-+-+-+-+
///     |   PictureID   | (when M is set)
///     +-+-+-+-+-+-+-+-+
/// L:  |   TL0PICIDX   | (OPTIONAL)
///     +-+-+-+-+-+-+-+-+
/// T/K:|TID|Y| KEYIDX  | (OPTIONAL)
///     +-+-+-+-+-+-+-+-+
/// ```
///
/// @param nonReference    the `N` bit
/// @param startOfPartition the `S` bit
/// @param partitionIndex  the `PID`
/// @param pictureId       the picture id
/// @param longPictureId   whether the picture id has 15 bits (`M` set)
/// @param tl0PicIndex     the `TL0PICIDX`
/// @param temporalId      the `TID`, present with the `T` bit
/// @param layerSync       the `Y` bit
/// @param keyIndex        the `KEYIDX`, present with the `K` bit
/// @param size            the encoded size of the descriptor
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html#section-4.2 RFC 7741 section 4.2: VP8 Payload Descriptor
record Vp8Descriptor(boolean nonReference, boolean startOfPartition, int partitionIndex, OptionalInt pictureId,
                     boolean longPictureId, OptionalInt tl0PicIndex, OptionalInt temporalId, boolean layerSync,
                     OptionalInt keyIndex, int size) {
    /// The offset of the picture id within a descriptor that has one: after the required byte and the X byte.
    static final int PICTURE_ID_OFFSET = 2;

    /// Parses the descriptor at the position of a payload.
    ///
    /// @throws PayloadFormatException if it is truncated or leaves no payload
    static Vp8Descriptor parse(ByteBuffer payload) throws PayloadFormatException {
        var start = payload.position();
        var limit = payload.limit();
        if (start >= limit) {
            throw new PayloadFormatException("empty VP8 payload");
        }
        var first = Payloads.u8(payload, start);
        var offset = start + 1;
        var pictureId = OptionalInt.empty();
        var longPictureId = false;
        var tl0 = OptionalInt.empty();
        var temporalId = OptionalInt.empty();
        var layerSync = false;
        var keyIndex = OptionalInt.empty();
        if ((first & 0x80) != 0) {
            if (offset >= limit) {
                throw new PayloadFormatException("truncated VP8 extension byte");
            }
            var extension = Payloads.u8(payload, offset++);
            if ((extension & 0x80) != 0) {
                if (offset >= limit) {
                    throw new PayloadFormatException("truncated VP8 picture id");
                }
                var high = Payloads.u8(payload, offset++);
                if ((high & 0x80) != 0) {
                    if (offset >= limit) {
                        throw new PayloadFormatException("truncated VP8 picture id");
                    }
                    pictureId = OptionalInt.of((high & 0x7F) << 8 | Payloads.u8(payload, offset++));
                    longPictureId = true;
                } else {
                    pictureId = OptionalInt.of(high);
                }
            }
            if ((extension & 0x40) != 0) {
                if (offset >= limit) {
                    throw new PayloadFormatException("truncated VP8 TL0PICIDX");
                }
                tl0 = OptionalInt.of(Payloads.u8(payload, offset++));
            }
            if ((extension & 0x30) != 0) {
                if (offset >= limit) {
                    throw new PayloadFormatException("truncated VP8 TID/KEYIDX");
                }
                var value = Payloads.u8(payload, offset++);
                if ((extension & 0x20) != 0) {
                    temporalId = OptionalInt.of(value >>> 6);
                    layerSync = (value & 0x20) != 0;
                }
                if ((extension & 0x10) != 0) {
                    keyIndex = OptionalInt.of(value & 0x1F);
                }
            }
        }
        if (offset >= limit) {
            throw new PayloadFormatException("VP8 payload without data after its descriptor");
        }
        return new Vp8Descriptor((first & 0x20) != 0, (first & 0x10) != 0, first & 0x07, pictureId, longPictureId,
                tl0, temporalId, layerSync, keyIndex, offset - start);
    }

    /// {@return the size of a descriptor with these fields}
    static int sizeOf(boolean pictureId, boolean tl0, boolean temporalOrKey) {
        var extended = pictureId || tl0 || temporalOrKey;
        return 1 + (extended ? 1 : 0) + (pictureId ? 2 : 0) + (tl0 ? 1 : 0) + (temporalOrKey ? 1 : 0);
    }

    /// Writes a descriptor with a 15-bit picture id when present.
    static void write(ByteBuffer out, boolean nonReference, boolean start, OptionalInt pictureId, OptionalInt tl0,
                      OptionalInt temporalId, boolean layerSync, OptionalInt keyIndex) {
        var extended = pictureId.isPresent() || tl0.isPresent() || temporalId.isPresent() || keyIndex.isPresent();
        out.put((byte) ((extended ? 0x80 : 0) | (nonReference ? 0x20 : 0) | (start ? 0x10 : 0)));
        if (!extended) {
            return;
        }
        out.put((byte) ((pictureId.isPresent() ? 0x80 : 0) | (tl0.isPresent() ? 0x40 : 0)
                | (temporalId.isPresent() ? 0x20 : 0) | (keyIndex.isPresent() ? 0x10 : 0)));
        if (pictureId.isPresent()) {
            out.putShort((short) (0x8000 | pictureId.getAsInt()));
        }
        if (tl0.isPresent()) {
            out.put((byte) tl0.getAsInt());
        }
        if (temporalId.isPresent() || keyIndex.isPresent()) {
            out.put((byte) (temporalId.orElse(0) << 6 | (layerSync ? 0x20 : 0) | keyIndex.orElse(0)));
        }
    }
}
