package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;

/// Rewrites the picture id and `TL0PICIDX` of forwarded VP8 payloads so a receiver sees one continuous stream while
/// a forwarding unit switches between simulcast streams.
///
/// A receiver uses the picture id to detect lost frames and the `TL0PICIDX` to resolve temporal layer references; a
/// jump in either at a simulcast switch looks like loss. The rewriter renumbers each source so its first picture
/// follows the last one forwarded. The RTP sequence number, timestamp and SSRC are the RTP layer's to rewrite.
///
/// {@snippet lang = java :
/// var rewriter = new Vp8PayloadRewriter();
/// // on every forwarded packet, its payload as a writable buffer
/// rewriter.rewrite(payload);
/// // when switching to another simulcast layer, at its keyframe
/// rewriter.switchSource();
/// }
///
/// A rewriter belongs to one forwarded stream and is not safe for concurrent use.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html RFC 7741: RTP Payload Format for VP8 Video
/// @spec https://www.rfc-editor.org/rfc/rfc7667.html#section-3.7 RFC 7667 section 3.7: Selective Forwarding Middlebox
public final class Vp8PayloadRewriter extends PictureIdRewriter {
    /// Creates a rewriter that starts with the first source's own numbering.
    public Vp8PayloadRewriter() {
    }

    /// Rewrites the picture id and `TL0PICIDX` of one payload in place, keeping their widths; a payload without them
    /// is left unchanged.
    ///
    /// @param payload the VP8 payload, from position to limit, writable; its position does not change
    /// @throws PayloadFormatException          if the payload descriptor is malformed
    /// @throws java.nio.ReadOnlyBufferException if the buffer is read-only and has a field to rewrite
    public void rewrite(ByteBuffer payload) throws PayloadFormatException {
        var descriptor = Vp8Descriptor.parse(payload);
        var offset = payload.position() + Vp8Descriptor.PICTURE_ID_OFFSET;
        if (descriptor.pictureId().isPresent()) {
            var longField = descriptor.longPictureId();
            writePictureId(payload, offset, mapPictureId(descriptor.pictureId().getAsInt(), longField), longField);
            offset += longField ? 2 : 1;
        }
        if (descriptor.tl0PicIndex().isPresent()) {
            payload.put(offset, (byte) mapTl0(descriptor.tl0PicIndex().getAsInt()));
        }
    }
}
