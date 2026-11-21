package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;

/// The picture id and `TL0PICIDX` continuity a forwarding unit keeps across source switches, shared by the VP8 and
/// VP9 rewriters.
///
/// Each source's values are unwrapped, shifted by an offset chosen at the switch so the first output picture follows
/// the last one sent, and written back modulo the field's width.
abstract sealed class PictureIdRewriter permits Vp8PayloadRewriter, Vp9PayloadRewriter {
    /// The unwrapper of the current source's picture ids, created with the width of its first picture id.
    private Unwrapper pictureIds;

    /// The unwrapper of the current source's `TL0PICIDX`.
    private Unwrapper tl0Indices = new Unwrapper(8);

    /// The offset added to the current source's unwrapped picture ids, or `null` before its first picture.
    private Long pictureIdOffset;

    /// The offset added to the current source's unwrapped `TL0PICIDX`, or `null` before its first.
    private Long tl0Offset;

    /// The highest unwrapped output picture id, or `-1` before the first.
    private long lastPictureId = -1;

    /// The highest unwrapped output `TL0PICIDX`, or `-1` before the first.
    private long lastTl0 = -1;

    /// Creates a rewriter.
    PictureIdRewriter() {
    }

    /// Marks that the next packets come from another source stream, such as another simulcast layer.
    ///
    /// The next picture id and `TL0PICIDX` written follow the last ones sent. A forwarding unit switches at a keyframe
    /// of the new source and stops forwarding the old one; a late packet of the old source would be renumbered as
    /// part of the new one.
    public final void switchSource() {
        pictureIds = null;
        tl0Indices = new Unwrapper(8);
        pictureIdOffset = null;
        tl0Offset = null;
    }

    /// {@return the output picture id of an input one}
    ///
    /// @param input     the input picture id
    /// @param longField whether the field has 15 bits rather than 7
    final int mapPictureId(int input, boolean longField) {
        if (pictureIds == null) {
            pictureIds = new Unwrapper(longField ? 15 : 7);
        }
        var unwrapped = pictureIds.unwrap(input);
        if (pictureIdOffset == null) {
            pictureIdOffset = lastPictureId < 0 ? 0 : lastPictureId + 1 - unwrapped;
        }
        var output = unwrapped + pictureIdOffset;
        lastPictureId = Math.max(lastPictureId, output);
        return (int) Math.floorMod(output, longField ? 0x8000L : 0x80L);
    }

    /// {@return the output `TL0PICIDX` of an input one}
    final int mapTl0(int input) {
        var unwrapped = tl0Indices.unwrap(input);
        if (tl0Offset == null) {
            tl0Offset = lastTl0 < 0 ? 0 : lastTl0 + 1 - unwrapped;
        }
        var output = unwrapped + tl0Offset;
        lastTl0 = Math.max(lastTl0, output);
        return (int) Math.floorMod(output, 0x100L);
    }

    /// Writes a picture id back at an absolute offset.
    static void writePictureId(ByteBuffer payload, int offset, int value, boolean longField) {
        if (longField) {
            payload.putShort(offset, (short) (0x8000 | value));
        } else {
            payload.put(offset, (byte) value);
        }
    }
}
