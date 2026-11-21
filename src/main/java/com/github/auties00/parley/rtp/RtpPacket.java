package com.github.auties00.parley.rtp;

import java.util.Objects;

/// The fields of an RTP packet, with the codec of its fixed header.
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
/// ```
///
/// [#encode(int)] writes a version 2 header without padding, extension or CSRC list, followed by the payload and
/// `tailroom` spare bytes, the room SRTP needs to append its authentication tag in place. [#decode(byte\[\],int,int)]
/// skips a CSRC list and a header extension, discarding both, and strips padding.
///
/// The record does not copy the payload: the array passed in and the one [#payload()] returns are shared.
///
/// @param payloadType the payload type, `0..127`; only the low seven bits are encoded
/// @param marker      the marker bit
/// @param sequence    the sequence number, `0..65535`; only the low sixteen bits are encoded
/// @param timestamp   the timestamp, an unsigned 32-bit value
/// @param ssrc        the synchronization source, an unsigned 32-bit value
/// @param payload     the payload
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record RtpPacket(int payloadType, boolean marker, int sequence, long timestamp, long ssrc, byte[] payload) {
    /// The size of the fixed header.
    public static final int HEADER_LENGTH = 12;

    /// Creates a packet.
    ///
    /// @param payloadType the payload type
    /// @param marker      the marker bit
    /// @param sequence    the sequence number
    /// @param timestamp   the timestamp
    /// @param ssrc        the synchronization source
    /// @param payload     the payload, which the packet keeps without copying
    public RtpPacket {
        Objects.requireNonNull(payload, "payload cannot be null");
    }

    /// {@return whether a datagram is RTCP rather than RTP when both share a port: its second byte, the packet type
    /// for RTCP, is in `192..223`}
    ///
    /// The result is meaningful only for a datagram that [#isRtpOrRtcp(byte\[\],int,int)] accepts.
    ///
    /// @param data   the buffer
    /// @param offset the offset of the packet in `data`
    /// @param length the length of the packet
    /// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
    public static boolean isRtcp(byte[] data, int offset, int length) {
        if (length < 2) {
            return false;
        }
        var type = data[offset + 1] & 0xFF;
        return type >= 192 && type <= 223;
    }

    /// {@return whether a datagram is RTP or RTCP on a port shared with STUN and DTLS: its first byte is in
    /// `128..191`}
    ///
    /// @param data   the buffer
    /// @param offset the offset of the packet in `data`
    /// @param length the length of the packet
    /// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
    public static boolean isRtpOrRtcp(byte[] data, int offset, int length) {
        if (length < 2) {
            return false;
        }
        var first = data[offset] & 0xFF;
        return first >= 128 && first <= 191;
    }

    /// Decodes an RTP packet, copying its payload out of the buffer.
    ///
    /// @param data   the buffer
    /// @param offset the offset of the packet in `data`
    /// @param length the length of the packet; for an SRTP packet unprotected in place, the length the
    ///               unprotection reports, so the authentication tag is not read as payload
    /// @return the packet
    /// @throws IllegalArgumentException if the packet is not version 2 or is truncated
    public static RtpPacket decode(byte[] data, int offset, int length) {
        if (length < HEADER_LENGTH || (data[offset] & 0xC0) != 0x80) {
            throw new IllegalArgumentException("not an RTP packet");
        }
        var first = data[offset] & 0xFF;
        var csrcCount = first & 0x0F;
        var headerLength = HEADER_LENGTH + 4 * csrcCount;
        if ((first & 0x10) != 0) {
            if (length < headerLength + 4) {
                throw new IllegalArgumentException("truncated RTP header extension");
            }
            var words = (data[offset + headerLength + 2] & 0xFF) << 8 | (data[offset + headerLength + 3] & 0xFF);
            headerLength += 4 + 4 * words;
        }
        var end = length;
        if ((first & 0x20) != 0 && length > headerLength) {
            end -= data[offset + length - 1] & 0xFF;
        }
        if (end < headerLength) {
            throw new IllegalArgumentException("truncated RTP packet");
        }
        var payload = new byte[end - headerLength];
        System.arraycopy(data, offset + headerLength, payload, 0, payload.length);
        return new RtpPacket(
                data[offset + 1] & 0x7F,
                (data[offset + 1] & 0x80) != 0,
                (data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF),
                readUint32(data, offset + 4),
                readUint32(data, offset + 8),
                payload);
    }

    /// Encodes the packet into a new buffer with spare room after it.
    ///
    /// @param tailroom the number of spare zero bytes to leave after the payload, such as the size of the SRTP
    ///                 authentication tag
    /// @return a buffer of `12 + payload.length + tailroom` bytes whose first [#length()] bytes are the packet
    /// @throws NegativeArraySizeException if `tailroom` is so negative that the buffer size is negative
    public byte[] encode(int tailroom) {
        var out = new byte[HEADER_LENGTH + payload.length + tailroom];
        out[0] = (byte) 0x80;
        out[1] = (byte) ((marker ? 0x80 : 0) | (payloadType & 0x7F));
        out[2] = (byte) (sequence >>> 8);
        out[3] = (byte) sequence;
        writeUint32(out, 4, timestamp);
        writeUint32(out, 8, ssrc);
        System.arraycopy(payload, 0, out, HEADER_LENGTH, payload.length);
        return out;
    }

    /// {@return the encoded length of the packet, `12 + payload.length`}
    public int length() {
        return HEADER_LENGTH + payload.length;
    }

    /// {@return the unsigned 32-bit big-endian value at `offset`}
    static long readUint32(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24) | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
    }

    /// Writes the low 32 bits of `value` big-endian at `offset`.
    static void writeUint32(byte[] data, int offset, long value) {
        data[offset] = (byte) (value >>> 24);
        data[offset + 1] = (byte) (value >>> 16);
        data[offset + 2] = (byte) (value >>> 8);
        data[offset + 3] = (byte) value;
    }
}
