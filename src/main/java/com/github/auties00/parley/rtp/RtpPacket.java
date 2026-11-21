package com.github.auties00.parley.rtp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/// A read-only view of one RTP packet over the buffer that holds it.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           synchronization source (SSRC) identifier            |
/// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
/// |            contributing source (CSRC) identifiers             |
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   defined by profile          |           length              |
/// |                       header extension                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     payload ...   | padding ...   | pad count |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [#parse(ByteBuffer)] validates the whole layout once and indexes the header extension elements, so every accessor
/// is a constant-time read of the underlying bytes. Nothing is copied: [#payload()], [#extension(int)] and
/// [#buffer()] are read-only slices of the parsed buffer.
///
/// Header extensions are read in both RFC 8285 forms: one-byte elements (profile `0xBEDE`, ids `1..14`) and
/// two-byte elements (profile `0x100X`, ids `1..255`), so a session that negotiated `a=extmap-allow-mixed` can
/// receive either form packet by packet. A header extension of any other profile is kept as opaque data
/// ([#extensionData()]) without elements.
///
/// # Ownership
///
/// The view is valid only as long as the bytes it was parsed from do not change. A packet handed to a receiver
/// callback is backed by the transport's receive buffer and is valid only during that callback; call [#copy()] to
/// keep it. Instances are immutable and safe to share between threads as long as the bytes do not change.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public final class RtpPacket {
    /// The size of the fixed header, without CSRCs or extension.
    public static final int FIXED_HEADER_LENGTH = 12;

    /// The "defined by profile" value of a header extension made of one-byte elements.
    public static final int ONE_BYTE_PROFILE = 0xBEDE;

    /// The "defined by profile" value of a header extension made of two-byte elements, with the four "appbits" zero.
    public static final int TWO_BYTE_PROFILE = 0x1000;

    private static final int[] NO_ELEMENTS = new int[0];

    /// The parsed bytes; index `start` is the first byte of the packet.
    private final ByteBuffer source;
    private final int start;
    private final int end;
    private final int csrcCount;
    private final int extensionProfile;
    /// Absolute index of the first byte of the extension data (after the 4-byte extension header), or `-1`.
    private final int extensionDataStart;
    private final int extensionDataEnd;
    private final int payloadStart;
    private final int payloadEnd;
    /// Element triples `id, absolute value offset, length`, in packet order.
    private final int[] elements;

    private RtpPacket(ByteBuffer source, int start, int end, int csrcCount, int extensionProfile,
                      int extensionDataStart, int extensionDataEnd, int payloadStart, int payloadEnd, int[] elements) {
        this.source = source;
        this.start = start;
        this.end = end;
        this.csrcCount = csrcCount;
        this.extensionProfile = extensionProfile;
        this.extensionDataStart = extensionDataStart;
        this.extensionDataEnd = extensionDataEnd;
        this.payloadStart = payloadStart;
        this.payloadEnd = payloadEnd;
        this.elements = elements;
    }

    /// Parses the packet between the position and the limit of `packet`.
    ///
    /// The buffer's position and limit are left unchanged; the view keeps a duplicate of it, so later changes to the
    /// buffer's position or limit do not affect the view, but changes to its content do.
    ///
    /// @param packet the buffer holding the packet
    /// @return a view of the packet
    /// @throws RtpFormatException if the bytes are not a version 2 RTP packet whose CSRC list, header extension and
    ///                            padding fit in them, or if a one-byte or two-byte extension element overruns the
    ///                            extension
    public static RtpPacket parse(ByteBuffer packet) throws RtpFormatException {
        Objects.requireNonNull(packet, "packet cannot be null");
        // Read-only, so the slices the accessors hand out are read-only without a second view each
        var source = packet.asReadOnlyBuffer();
        var start = source.position();
        var end = source.limit();
        var length = end - start;
        if (length < FIXED_HEADER_LENGTH) {
            throw new RtpFormatException("RTP packet shorter than the fixed header: " + length);
        }
        var first = source.get(start) & 0xFF;
        if ((first & 0xC0) != 0x80) {
            throw new RtpFormatException("RTP version is not 2");
        }
        var csrcCount = first & 0x0F;
        var cursor = start + FIXED_HEADER_LENGTH + 4 * csrcCount;
        if (cursor > end) {
            throw new RtpFormatException("RTP CSRC list overruns the packet");
        }
        var extensionProfile = 0;
        var extensionDataStart = -1;
        var extensionDataEnd = -1;
        var elements = NO_ELEMENTS;
        if ((first & 0x10) != 0) {
            if (cursor + 4 > end) {
                throw new RtpFormatException("RTP header extension header overruns the packet");
            }
            extensionProfile = source.getShort(cursor) & 0xFFFF;
            var words = source.getShort(cursor + 2) & 0xFFFF;
            extensionDataStart = cursor + 4;
            extensionDataEnd = extensionDataStart + 4 * words;
            if (extensionDataEnd > end) {
                throw new RtpFormatException("RTP header extension overruns the packet");
            }
            if (extensionProfile == ONE_BYTE_PROFILE) {
                elements = parseOneByteElements(source, extensionDataStart, extensionDataEnd);
            } else if ((extensionProfile & 0xFFF0) == TWO_BYTE_PROFILE) {
                elements = parseTwoByteElements(source, extensionDataStart, extensionDataEnd);
            }
            cursor = extensionDataEnd;
        }
        var payloadEnd = end;
        if ((first & 0x20) != 0) {
            if (end == cursor) {
                throw new RtpFormatException("RTP padding bit set on a packet without room for the count");
            }
            var padding = source.get(end - 1) & 0xFF;
            if (padding == 0 || padding > end - cursor) {
                throw new RtpFormatException("RTP padding count out of range: " + padding);
            }
            payloadEnd = end - padding;
        }
        return new RtpPacket(source, start, end, csrcCount, extensionProfile, extensionDataStart, extensionDataEnd,
                cursor, payloadEnd, elements);
    }

    private static int[] parseOneByteElements(ByteBuffer source, int from, int to) throws RtpFormatException {
        var count = scanOneByteElements(source, from, to, null);
        if (count == 0) {
            return NO_ELEMENTS;
        }
        var out = new int[count * 3];
        scanOneByteElements(source, from, to, out);
        return out;
    }

    /// Walks the one-byte elements, validating them and, when `out` is not `null`, recording each as id, value
    /// offset and length; one pass counts, so the array is allocated at its size.
    ///
    /// @return the number of elements
    private static int scanOneByteElements(ByteBuffer source, int from, int to, int[] out) throws RtpFormatException {
        var count = 0;
        var cursor = from;
        while (cursor < to) {
            var header = source.get(cursor) & 0xFF;
            if (header >>> 4 == 0) {
                cursor++;
                continue;
            }
            var id = header >>> 4;
            if (id == 15) {
                break;
            }
            var length = (header & 0x0F) + 1;
            if (cursor + 1 + length > to) {
                throw new RtpFormatException("one-byte extension element " + id + " overruns the extension");
            }
            if (out != null) {
                out[count * 3] = id;
                out[count * 3 + 1] = cursor + 1;
                out[count * 3 + 2] = length;
            }
            count++;
            cursor += 1 + length;
        }
        return count;
    }

    private static int[] parseTwoByteElements(ByteBuffer source, int from, int to) throws RtpFormatException {
        var count = scanTwoByteElements(source, from, to, null);
        if (count == 0) {
            return NO_ELEMENTS;
        }
        var out = new int[count * 3];
        scanTwoByteElements(source, from, to, out);
        return out;
    }

    /// Walks the two-byte elements like [#scanOneByteElements(ByteBuffer,int,int,int\[\])].
    ///
    /// @return the number of elements
    private static int scanTwoByteElements(ByteBuffer source, int from, int to, int[] out) throws RtpFormatException {
        var count = 0;
        var cursor = from;
        while (cursor < to) {
            var id = source.get(cursor) & 0xFF;
            if (id == 0) {
                cursor++;
                continue;
            }
            if (cursor + 2 > to) {
                throw new RtpFormatException("two-byte extension element " + id + " has no length");
            }
            var length = source.get(cursor + 1) & 0xFF;
            if (cursor + 2 + length > to) {
                throw new RtpFormatException("two-byte extension element " + id + " overruns the extension");
            }
            if (out != null) {
                out[count * 3] = id;
                out[count * 3 + 1] = cursor + 2;
                out[count * 3 + 2] = length;
            }
            count++;
            cursor += 2 + length;
        }
        return count;
    }

    /// {@return whether a datagram on a port shared by RTP and RTCP is RTCP: its second byte, the RTCP packet type,
    /// is in `192..223`}
    ///
    /// The test is meaningful only for a datagram whose first byte is in `128..191` (RTP or RTCP rather than STUN or
    /// DTLS). The buffer's position and limit are not changed.
    ///
    /// @param datagram the datagram, between its position and limit
    /// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
    public static boolean isRtcp(ByteBuffer datagram) {
        Objects.requireNonNull(datagram, "datagram cannot be null");
        if (datagram.remaining() < 2) {
            return false;
        }
        var type = datagram.get(datagram.position() + 1) & 0xFF;
        return type >= 192 && type <= 223;
    }

    /// {@return the payload type, `0..127`}
    public int payloadType() {
        return source.get(start + 1) & 0x7F;
    }

    /// {@return the marker bit}
    public boolean marker() {
        return (source.get(start + 1) & 0x80) != 0;
    }

    /// {@return the sequence number, `0..65535`}
    public int sequence() {
        return source.getShort(start + 2) & 0xFFFF;
    }

    /// {@return the RTP timestamp, an unsigned 32-bit value}
    public long timestamp() {
        return source.getInt(start + 4) & 0xFFFFFFFFL;
    }

    /// {@return the synchronization source, an unsigned 32-bit value}
    public long ssrc() {
        return source.getInt(start + 8) & 0xFFFFFFFFL;
    }

    /// {@return the contributing sources, unsigned 32-bit values in packet order; empty when there are none}
    public List<Long> csrcs() {
        if (csrcCount == 0) {
            return List.of();
        }
        var out = new Long[csrcCount];
        for (var i = 0; i < csrcCount; i++) {
            out[i] = source.getInt(start + FIXED_HEADER_LENGTH + 4 * i) & 0xFFFFFFFFL;
        }
        return List.of(out);
    }

    /// {@return the header fields as a detached record}
    public RtpHeader header() {
        return new RtpHeader(payloadType(), marker(), sequence(), timestamp(), ssrc(), csrcs(), extensionProfile);
    }

    /// {@return a read-only slice of the payload, without header and padding}
    public ByteBuffer payload() {
        return slice(payloadStart, payloadEnd);
    }

    /// {@return the payload length in bytes, without padding}
    public int payloadLength() {
        return payloadEnd - payloadStart;
    }

    /// {@return a read-only slice of the whole packet, header and padding included}
    public ByteBuffer buffer() {
        return slice(start, end);
    }

    /// {@return the packet length in bytes, header and padding included}
    public int length() {
        return end - start;
    }

    /// {@return the header length in bytes: the fixed header, the CSRC list and the header extension}
    public int headerLength() {
        return payloadStart - start;
    }

    /// {@return the number of padding bytes at the end of the packet, the count byte included; `0` without padding}
    public int paddingLength() {
        return end - payloadEnd;
    }

    /// {@return whether the packet has a header extension}
    public boolean hasExtension() {
        return extensionDataStart >= 0;
    }

    /// {@return the "defined by profile" field of the header extension, or `0` when the packet has none}
    public int extensionProfile() {
        return extensionProfile;
    }

    /// {@return whether the header extension uses the RFC 8285 two-byte element form}
    public boolean hasTwoByteExtensions() {
        return extensionDataStart >= 0 && (extensionProfile & 0xFFF0) == TWO_BYTE_PROFILE;
    }

    /// {@return a read-only slice of the whole header extension data after its 4-byte header; empty when the packet
    /// has no header extension}
    public Optional<ByteBuffer> extensionData() {
        return extensionDataStart < 0 ? Optional.empty() : Optional.of(slice(extensionDataStart, extensionDataEnd));
    }

    /// Returns the value of the first header extension element with an id.
    ///
    /// The id is the one negotiated for the extension's URI (see `HeaderExtensionMap` in the
    /// `com.github.auties00.parley.rtp.extension` package).
    ///
    /// @param id the element id, `1..255`
    /// @return a read-only slice of the element's value, or empty when the packet has no such element
    public Optional<ByteBuffer> extension(int id) {
        var index = elementIndex(id);
        return index < 0 ? Optional.empty()
                : Optional.of(slice(elements[index + 1], elements[index + 1] + elements[index + 2]));
    }

    /// Returns the absolute index of an element's value in the buffer this packet was parsed from.
    ///
    /// The packet's owner uses it to rewrite a reserved element in place, such as the transport-wide sequence
    /// number stamped at send time; the index is relative to index zero of that buffer, not to its position.
    ///
    /// @param id the element id, `1..255`
    /// @return the index of the first value byte, or empty when the packet has no such element
    public OptionalInt extensionOffset(int id) {
        var index = elementIndex(id);
        return index < 0 ? OptionalInt.empty() : OptionalInt.of(elements[index + 1]);
    }

    /// {@return the ids of the header extension elements, in packet order; empty for a packet without RFC 8285
    /// elements}
    public List<Integer> extensionIds() {
        var out = new ArrayList<Integer>(elements.length / 3);
        for (var i = 0; i < elements.length; i += 3) {
            out.add(elements[i]);
        }
        return List.copyOf(out);
    }

    /// {@return a view of an independent copy of the packet, backed by a new heap buffer}
    public RtpPacket copy() {
        var bytes = new byte[end - start];
        source.get(start, bytes);
        var delta = -start;
        var shifted = elements.clone();
        for (var i = 1; i < shifted.length; i += 3) {
            shifted[i] += delta;
        }
        return new RtpPacket(ByteBuffer.wrap(bytes).asReadOnlyBuffer(), 0, bytes.length, csrcCount, extensionProfile,
                extensionDataStart < 0 ? -1 : extensionDataStart + delta,
                extensionDataEnd < 0 ? -1 : extensionDataEnd + delta,
                payloadStart + delta, payloadEnd + delta, shifted);
    }

    private int elementIndex(int id) {
        for (var i = 0; i < elements.length; i += 3) {
            if (elements[i] == id) {
                return i;
            }
        }
        return -1;
    }

    private ByteBuffer slice(int from, int to) {
        return source.slice(from, to - from);
    }

    static void checkUint32(long value, String name) {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(name + " must be an unsigned 32-bit value: " + value);
        }
    }

    @Override
    public String toString() {
        return "RtpPacket[pt=" + payloadType() + ", seq=" + sequence() + ", ts=" + timestamp() + ", ssrc="
                + ssrc() + ", marker=" + marker() + ", payload=" + payloadLength() + "B]";
    }
}
