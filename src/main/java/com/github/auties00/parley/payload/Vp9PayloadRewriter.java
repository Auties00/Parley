package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;

/// Rewrites the picture id and `TL0PICIDX` of forwarded VP9 payloads so a receiver sees one continuous stream while
/// a forwarding unit switches between simulcast streams.
///
/// The layer frames of one picture share a picture id, so they keep sharing the rewritten one. Flexible-mode
/// reference differences are relative and need no rewriting. The RTP sequence number, timestamp and SSRC are the RTP
/// layer's to rewrite.
///
/// A rewriter belongs to one forwarded stream and is not safe for concurrent use.
///
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
/// @spec https://www.rfc-editor.org/rfc/rfc7667.html#section-3.7 RFC 7667 section 3.7: Selective Forwarding Middlebox
public final class Vp9PayloadRewriter extends PictureIdRewriter {
    /// Creates a rewriter that starts with the first source's own numbering.
    public Vp9PayloadRewriter() {
    }

    /// Rewrites the picture id and `TL0PICIDX` of one payload in place, keeping their widths; a payload without them
    /// is left unchanged.
    ///
    /// @param payload the VP9 payload, from position to limit, writable; its position does not change
    /// @throws PayloadFormatException          if the payload descriptor is malformed
    /// @throws java.nio.ReadOnlyBufferException if the buffer is read-only and has a field to rewrite
    public void rewrite(ByteBuffer payload) throws PayloadFormatException {
        var descriptor = Vp9Descriptor.parse(payload);
        var offset = payload.position() + 1;
        if (descriptor.pictureId().isPresent()) {
            var longField = descriptor.longPictureId();
            writePictureId(payload, offset, mapPictureId(descriptor.pictureId().getAsInt(), longField), longField);
            offset += longField ? 2 : 1;
        }
        if (descriptor.tl0PicIndex().isPresent()) {
            payload.put(offset + 1, (byte) mapTl0(descriptor.tl0PicIndex().getAsInt()));
        }
    }
}
