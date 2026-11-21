package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// A source description (`SDES`): text items, such as the canonical name, describing up to 31 sources.
///
/// @param chunks the chunks, one per described source, at most 31
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc8852.html RFC 8852: RTP Stream Identifier Source Description (SDES)
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
public record SourceDescription(List<Chunk> chunks) implements RtcpPacket {
    /// Validates the chunk count and copies `chunks`.
    ///
    /// @throws IllegalArgumentException if there are more than 31 chunks
    public SourceDescription {
        chunks = List.copyOf(Objects.requireNonNull(chunks, "chunks cannot be null"));
        if (chunks.size() > 31) {
            throw new IllegalArgumentException("at most 31 SDES chunks: " + chunks.size());
        }
    }

    /// {@return a source description with one chunk holding the canonical name of `ssrc`}
    ///
    /// @param ssrc  the source, an unsigned 32-bit value
    /// @param cname the canonical name
    public static SourceDescription ofCname(long ssrc, String cname) {
        return new SourceDescription(List.of(new Chunk(ssrc, List.of(Item.cname(cname)))));
    }

    /// The items describing one source.
    ///
    /// @param ssrc  the described source, an unsigned 32-bit value
    /// @param items the items, in order
    public record Chunk(long ssrc, List<Item> items) {
        /// Validates `ssrc` and copies `items`.
        ///
        /// @throws IllegalArgumentException if `ssrc` is out of range
        public Chunk {
            RtcpCodec.checkUint32(ssrc, "ssrc");
            items = List.copyOf(Objects.requireNonNull(items, "items cannot be null"));
        }

        /// {@return the value of the first item of a type}
        ///
        /// @param type the item type, such as [Item#CNAME]
        public Optional<String> find(int type) {
            for (var item : items) {
                if (item.type() == type) {
                    return Optional.of(item.value());
                }
            }
            return Optional.empty();
        }

        int encodedLength() {
            var length = 4;
            for (var item : items) {
                length += 2 + item.encodedValue().length;
            }
            return RtcpCodec.padTo4(length + 1);
        }
    }

    /// One source description item.
    ///
    /// Values are UTF-8 text on the wire, at most 255 bytes; a longer value is cut when written, on a character
    /// boundary.
    ///
    /// @param type  the item type, `1..255`
    /// @param value the text
    public record Item(int type, String value) {
        /// The canonical end-point identifier.
        public static final int CNAME = 1;
        /// The user name.
        public static final int NAME = 2;
        /// The electronic mail address.
        public static final int EMAIL = 3;
        /// The phone number.
        public static final int PHONE = 4;
        /// The geographic location.
        public static final int LOC = 5;
        /// The application or tool name.
        public static final int TOOL = 6;
        /// A notice about the source.
        public static final int NOTE = 7;
        /// A private extension.
        public static final int PRIV = 8;
        /// The RTP stream identifier (`rid`) of the source.
        public static final int RTP_STREAM_ID = 12;
        /// The RTP stream identifier of the stream the source repairs.
        public static final int REPAIRED_RTP_STREAM_ID = 13;
        /// The media identification (`mid`) of the source.
        public static final int MID = 15;

        /// Validates the type.
        ///
        /// @throws IllegalArgumentException if `type` is out of `1..255`
        public Item {
            if (type < 1 || type > 255) {
                throw new IllegalArgumentException("SDES item type must be in 1..255: " + type);
            }
            Objects.requireNonNull(value, "value cannot be null");
        }

        /// {@return a canonical name item}
        ///
        /// @param cname the canonical name
        public static Item cname(String cname) {
            return new Item(CNAME, cname);
        }

        /// {@return an RTP stream identifier item}
        ///
        /// @param rid the stream identifier
        public static Item rtpStreamId(String rid) {
            return new Item(RTP_STREAM_ID, rid);
        }

        /// {@return a repaired RTP stream identifier item}
        ///
        /// @param rid the identifier of the repaired stream
        public static Item repairedRtpStreamId(String rid) {
            return new Item(REPAIRED_RTP_STREAM_ID, rid);
        }

        /// {@return a media identification item}
        ///
        /// @param mid the media identification
        public static Item mid(String mid) {
            return new Item(MID, mid);
        }

        byte[] encodedValue() {
            var bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length <= 255) {
                return bytes;
            }
            var cut = 255;
            while (cut > 0 && (bytes[cut] & 0xC0) == 0x80) {
                cut--;
            }
            var out = new byte[cut];
            System.arraycopy(bytes, 0, out, 0, cut);
            return out;
        }
    }

    static SourceDescription parse(int count, ByteBuffer body) throws RtcpFormatException {
        var chunks = new ArrayList<Chunk>(count);
        for (var i = 0; i < count; i++) {
            var chunkStart = body.position();
            RtcpCodec.requireRemaining(body, 4, "SDES chunk");
            var ssrc = RtcpCodec.uint32(body);
            var items = new ArrayList<Item>();
            while (true) {
                RtcpCodec.requireRemaining(body, 1, "SDES item list");
                var type = body.get() & 0xFF;
                if (type == 0) {
                    break;
                }
                RtcpCodec.requireRemaining(body, 1, "SDES item");
                var length = body.get() & 0xFF;
                RtcpCodec.requireRemaining(body, length, "SDES item value");
                var bytes = new byte[length];
                body.get(bytes);
                items.add(new Item(type, new String(bytes, StandardCharsets.UTF_8)));
            }
            var consumed = body.position() - chunkStart;
            var aligned = RtcpCodec.padTo4(consumed);
            if (chunkStart + aligned > body.limit()) {
                throw new RtcpFormatException("SDES chunk padding overruns the packet");
            }
            body.position(chunkStart + aligned);
            chunks.add(new Chunk(ssrc, items));
        }
        return new SourceDescription(chunks);
    }

    @Override
    public int encodedLength() {
        var length = RtcpCodec.HEADER_LENGTH;
        for (var chunk : chunks) {
            length += chunk.encodedLength();
        }
        return length;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, chunks.size(), SOURCE_DESCRIPTION, length);
        for (var chunk : chunks) {
            var start = destination.position();
            destination.putInt((int) chunk.ssrc());
            for (var item : chunk.items()) {
                var value = item.encodedValue();
                destination.put((byte) item.type());
                destination.put((byte) value.length);
                destination.put(value);
            }
            var end = start + chunk.encodedLength();
            while (destination.position() < end) {
                destination.put((byte) 0);
            }
        }
        return length;
    }
}
