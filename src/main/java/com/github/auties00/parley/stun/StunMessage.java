package com.github.auties00.parley.stun;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.zip.CRC32;

/// A STUN message with the attributes Interactive Connectivity Establishment uses.
///
/// A message is a 20-byte header followed by type-length-value attributes, each padded to four bytes:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0 0|     STUN Message Type     |         Message Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Magic Cookie (0x2112A442)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Transaction ID (96 bits)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A message is built with [#create(int)] or [#response(int,StunMessage)] and the `add` methods, which append in
/// place and return the message, then written with [#encode(byte\[\],boolean)]. That method appends
/// `MESSAGE-INTEGRITY` (HMAC-SHA1 under a short-term credential key) and `FINGERPRINT` (CRC-32 XOR `0x5354554E`) as
/// the last two attributes, in that order, whatever the message already holds. A received datagram is read with
/// [#decode(byte\[\],int,int)], which keeps the raw bytes so [#verifyIntegrity(byte\[\])] can check the integrity
/// attribute against them; a decoded message never verifies its `FINGERPRINT`.
///
/// A message is not safe for use by several threads at once while it is being built; once built it is only read.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc5389.html RFC 5389: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
public final class StunMessage {
    /// The Binding request message type.
    public static final int BINDING_REQUEST = 0x0001;

    /// The Binding success response message type.
    public static final int BINDING_SUCCESS = 0x0101;

    /// The Binding error response message type.
    public static final int BINDING_ERROR = 0x0111;

    /// The Binding indication message type.
    public static final int BINDING_INDICATION = 0x0011;

    /// The `USERNAME` attribute type, a UTF-8 string; ICE writes `<remote ufrag>:<local ufrag>`.
    public static final int USERNAME = 0x0006;

    /// The `MESSAGE-INTEGRITY` attribute type, an HMAC-SHA1 written by [#encode(byte\[\],boolean)].
    public static final int MESSAGE_INTEGRITY = 0x0008;

    /// The `ERROR-CODE` attribute type.
    public static final int ERROR_CODE = 0x0009;

    /// The `XOR-MAPPED-ADDRESS` attribute type, the source address of the request a response answers.
    public static final int XOR_MAPPED_ADDRESS = 0x0020;

    /// The ICE `PRIORITY` attribute type, a 32-bit priority.
    public static final int PRIORITY = 0x0024;

    /// The ICE `USE-CANDIDATE` attribute type, which has no value and nominates the pair a check runs on.
    public static final int USE_CANDIDATE = 0x0025;

    /// The `FINGERPRINT` attribute type, a CRC-32 written by [#encode(byte\[\],boolean)].
    public static final int FINGERPRINT = 0x8028;

    /// The ICE `ICE-CONTROLLED` attribute type, a 64-bit tie-breaker.
    public static final int ICE_CONTROLLED = 0x8029;

    /// The ICE `ICE-CONTROLLING` attribute type, a 64-bit tie-breaker.
    public static final int ICE_CONTROLLING = 0x802A;

    /// The magic cookie every message since RFC 5389 carries at offset 4.
    public static final int MAGIC_COOKIE = 0x2112A442;

    /// The size of the message header.
    private static final int HEADER_LENGTH = 20;

    /// The value `FINGERPRINT` XORs into the CRC-32, the ASCII bytes of `STUN`.
    private static final long FINGERPRINT_XOR = 0x5354554EL;

    /// The source of transaction ids.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// The message type.
    private final int type;

    /// The 12-byte transaction id.
    private final byte[] transactionId;

    /// The attributes in order; an integrity or fingerprint attribute is skipped on encode.
    private final List<Attribute> attributes;

    /// The bytes the message was decoded from, or `null` for a message built locally.
    private final byte[] raw;

    /// The offset in [#raw] of the `MESSAGE-INTEGRITY` attribute, or `-1` when there is none.
    private final int integrityOffset;

    /// Creates a message from its parts, taking ownership of the arrays and the list.
    private StunMessage(int type, byte[] transactionId, List<Attribute> attributes, byte[] raw, int integrityOffset) {
        this.type = type;
        this.transactionId = transactionId;
        this.attributes = attributes;
        this.raw = raw;
        this.integrityOffset = integrityOffset;
    }

    /// {@return a new message of a type, with a fresh random transaction id and no attributes}
    ///
    /// @param type the message type, such as [#BINDING_REQUEST]
    public static StunMessage create(int type) {
        var transactionId = new byte[12];
        RANDOM.nextBytes(transactionId);
        return new StunMessage(type, transactionId, new ArrayList<>(), null, -1);
    }

    /// {@return a new message of a type that answers a request, reusing its transaction id, with no attributes}
    ///
    /// @param type    the response type, such as [#BINDING_SUCCESS]
    /// @param request the request being answered
    public static StunMessage response(int type, StunMessage request) {
        return new StunMessage(type, request.transactionId.clone(), new ArrayList<>(), null, -1);
    }

    /// {@return whether a datagram looks like a STUN message: at least 20 bytes, a first byte in `0..3` and the magic
    /// cookie at offset 4}
    ///
    /// The first-byte range is the one RFC 7983 assigns to STUN on a port shared with DTLS and SRTP.
    ///
    /// @param data   the buffer
    /// @param offset the offset of the datagram in `data`
    /// @param length the length of the datagram
    /// @throws IndexOutOfBoundsException if the range lies outside `data`
    /// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
    public static boolean isStun(byte[] data, int offset, int length) {
        if (length < HEADER_LENGTH || (data[offset] & 0xFF) > 3) {
            return false;
        }
        return ByteBuffer.wrap(data, offset + 4, 4).getInt() == MAGIC_COOKIE;
    }

    /// Decodes a STUN message, copying it out of the buffer.
    ///
    /// @param data   the buffer
    /// @param offset the offset of the message in `data`
    /// @param length the length of the datagram; bytes after the length the header declares are ignored
    /// @return the message
    /// @throws IllegalArgumentException if the datagram fails [#isStun(byte\[\],int,int)], its declared length
    ///                                  exceeds the datagram or is not a multiple of four, or an attribute overflows
    ///                                  the message
    /// @throws IndexOutOfBoundsException if the range lies outside `data`
    public static StunMessage decode(byte[] data, int offset, int length) {
        if (!isStun(data, offset, length)) {
            throw new IllegalArgumentException("not a STUN message");
        }
        var raw = Arrays.copyOfRange(data, offset, offset + length);
        var buffer = ByteBuffer.wrap(raw);
        var type = buffer.getShort() & 0xFFFF;
        var bodyLength = buffer.getShort() & 0xFFFF;
        if (bodyLength + HEADER_LENGTH > raw.length || (bodyLength & 3) != 0) {
            throw new IllegalArgumentException("STUN length mismatch");
        }
        buffer.getInt();
        var transactionId = new byte[12];
        buffer.get(transactionId);
        var attributes = new ArrayList<Attribute>();
        var integrityOffset = -1;
        var end = HEADER_LENGTH + bodyLength;
        while (buffer.position() + 4 <= end) {
            var start = buffer.position();
            var attributeType = buffer.getShort() & 0xFFFF;
            var attributeLength = buffer.getShort() & 0xFFFF;
            if (buffer.position() + attributeLength > end) {
                throw new IllegalArgumentException("STUN attribute overflows the message");
            }
            var value = new byte[attributeLength];
            buffer.get(value);
            buffer.position(buffer.position() + ((4 - (attributeLength & 3)) & 3));
            if (attributeType == MESSAGE_INTEGRITY) {
                integrityOffset = start;
            }
            attributes.add(new Attribute(attributeType, value));
        }
        return new StunMessage(type, transactionId, attributes, raw, integrityOffset);
    }

    /// {@return the message type, such as [#BINDING_REQUEST]}
    public int type() {
        return type;
    }

    /// {@return a copy of the 12-byte transaction id}
    public byte[] transactionId() {
        return transactionId.clone();
    }

    /// {@return whether this message has the same transaction id as `other`}
    ///
    /// @param other the other message
    public boolean sameTransaction(StunMessage other) {
        return Arrays.equals(transactionId, other.transactionId);
    }

    /// Appends an attribute, copying its value.
    ///
    /// @param attributeType the attribute type
    /// @param value         the attribute value, without padding, at most 65535 bytes
    /// @return this message
    public StunMessage add(int attributeType, byte[] value) {
        attributes.add(new Attribute(attributeType, value.clone()));
        return this;
    }

    /// Appends a UTF-8 string attribute.
    ///
    /// @param attributeType the attribute type, such as [#USERNAME]
    /// @param value         the string value
    /// @return this message
    public StunMessage add(int attributeType, String value) {
        return add(attributeType, value.getBytes(StandardCharsets.UTF_8));
    }

    /// Appends a 32-bit attribute, such as [#PRIORITY].
    ///
    /// @param attributeType the attribute type
    /// @param value         the value; its low 32 bits are written big-endian
    /// @return this message
    public StunMessage addInt(int attributeType, long value) {
        return add(attributeType, ByteBuffer.allocate(4).putInt((int) value).array());
    }

    /// Appends a 64-bit attribute, such as [#ICE_CONTROLLING] or [#ICE_CONTROLLED].
    ///
    /// @param attributeType the attribute type
    /// @param value         the value, written big-endian
    /// @return this message
    public StunMessage addLong(int attributeType, long value) {
        return add(attributeType, ByteBuffer.allocate(8).putLong(value).array());
    }

    /// Appends an [#XOR_MAPPED_ADDRESS] attribute, an IPv4 or IPv6 address XORed with the magic cookie and, for IPv6,
    /// the transaction id.
    ///
    /// @param address the address to report; it must be resolved
    /// @return this message
    /// @throws NullPointerException if `address` is unresolved
    public StunMessage addXorMappedAddress(InetSocketAddress address) {
        var ip = address.getAddress().getAddress();
        var value = ByteBuffer.allocate(4 + ip.length);
        value.put((byte) 0);
        value.put((byte) (ip.length == 4 ? 0x01 : 0x02));
        value.putShort((short) (address.getPort() ^ (MAGIC_COOKIE >>> 16)));
        value.put(xorAddress(ip));
        return add(XOR_MAPPED_ADDRESS, value.array());
    }

    /// {@return a copy of the value of the first attribute of a type, or an empty optional when the message has no
    /// such attribute}
    ///
    /// @param attributeType the attribute type
    public Optional<byte[]> attribute(int attributeType) {
        for (var attribute : attributes) {
            if (attribute.type() == attributeType) {
                return Optional.of(attribute.value().clone());
            }
        }
        return Optional.empty();
    }

    /// {@return whether the message carries at least one attribute of a type}
    ///
    /// @param attributeType the attribute type
    public boolean has(int attributeType) {
        return attributes.stream().anyMatch(attribute -> attribute.type() == attributeType);
    }

    /// {@return the value of the first attribute of a type decoded as UTF-8, or an empty optional when the message
    /// has no such attribute}
    ///
    /// @param attributeType the attribute type, such as [#USERNAME]
    public Optional<String> stringAttribute(int attributeType) {
        return attribute(attributeType).map(value -> new String(value, StandardCharsets.UTF_8));
    }

    /// {@return the address of the [#XOR_MAPPED_ADDRESS] attribute, or an empty optional when the message has none
    /// or it is malformed}
    public Optional<InetSocketAddress> xorMappedAddress() {
        return attribute(XOR_MAPPED_ADDRESS).flatMap(value -> {
            if (value.length != 8 && value.length != 20) {
                return Optional.empty();
            }
            var port = ((value[2] & 0xFF) << 8 | (value[3] & 0xFF)) ^ (MAGIC_COOKIE >>> 16);
            var ip = xorAddress(Arrays.copyOfRange(value, 4, value.length));
            try {
                return Optional.of(new InetSocketAddress(InetAddress.getByAddress(ip), port));
            } catch (UnknownHostException exception) {
                return Optional.empty();
            }
        });
    }

    /// {@return whether the message carries a `MESSAGE-INTEGRITY` attribute that verifies under `key`}
    ///
    /// Only a decoded message can be verified; a message built locally returns `false`. The HMAC covers the message
    /// up to the integrity attribute with the header length rewritten to end right after it, as RFC 8489 section
    /// 14.5 defines, so attributes after it (a `FINGERPRINT`) do not affect the result. The comparison runs in
    /// constant time.
    ///
    /// @param key the short-term credential key, the UTF-8 bytes of the ICE password of the side that signed the
    ///            message
    public boolean verifyIntegrity(byte[] key) {
        if (raw == null || integrityOffset < 0) {
            return false;
        }
        var covered = Arrays.copyOf(raw, integrityOffset);
        var adjusted = integrityOffset - HEADER_LENGTH + 24;
        covered[2] = (byte) (adjusted >>> 8);
        covered[3] = (byte) adjusted;
        var expected = hmacSha1(key, covered);
        var actual = Arrays.copyOfRange(raw, integrityOffset + 4, integrityOffset + 24);
        return MessageDigest.isEqual(expected, actual);
    }

    /// Encodes the message.
    ///
    /// Any `MESSAGE-INTEGRITY` or `FINGERPRINT` attribute the message holds (a decoded one does) is left out and
    /// replaced by the ones this method computes.
    ///
    /// @param integrityKey the short-term credential key of `MESSAGE-INTEGRITY`, the UTF-8 bytes of the ICE
    ///                     password of the side that receives the request (or that sends the response), or `null`
    ///                     to omit the attribute
    /// @param fingerprint  whether to append `FINGERPRINT`
    /// @return the encoded message
    /// @throws IllegalStateException if the JDK provides no HmacSHA1
    public byte[] encode(byte[] integrityKey, boolean fingerprint) {
        var body = new ByteArrayOutputStream();
        for (var attribute : attributes) {
            if (attribute.type() == MESSAGE_INTEGRITY || attribute.type() == FINGERPRINT) {
                continue;
            }
            writeAttribute(body, attribute.type(), attribute.value());
        }
        var message = withHeader(body.toByteArray(), body.size());
        if (integrityKey != null) {
            var withLength = withHeader(body.toByteArray(), body.size() + 24);
            writeAttribute(body, MESSAGE_INTEGRITY, hmacSha1(integrityKey, withLength));
            message = withHeader(body.toByteArray(), body.size());
        }
        if (fingerprint) {
            var withLength = withHeader(body.toByteArray(), body.size() + 8);
            var crc = new CRC32();
            crc.update(withLength);
            var value = ByteBuffer.allocate(4).putInt((int) (crc.getValue() ^ FINGERPRINT_XOR)).array();
            writeAttribute(body, FINGERPRINT, value);
            message = withHeader(body.toByteArray(), body.size());
        }
        return message;
    }

    /// {@return the header followed by `body`, with `lengthInField` in the length field}
    ///
    /// The length field may differ from the body length: integrity and fingerprint are computed over a header that
    /// already counts the attribute being computed.
    private byte[] withHeader(byte[] body, int lengthInField) {
        var buffer = ByteBuffer.allocate(HEADER_LENGTH + body.length);
        buffer.putShort((short) type);
        buffer.putShort((short) lengthInField);
        buffer.putInt(MAGIC_COOKIE);
        buffer.put(transactionId);
        buffer.put(body);
        return buffer.array();
    }

    /// Writes one attribute with its padding.
    private static void writeAttribute(ByteArrayOutputStream out, int type, byte[] value) {
        out.write(type >>> 8);
        out.write(type);
        out.write(value.length >>> 8);
        out.write(value.length);
        out.writeBytes(value);
        for (var i = 0; i < ((4 - (value.length & 3)) & 3); i++) {
            out.write(0);
        }
    }

    /// {@return a 4- or 16-byte address XORed with the magic cookie followed by the transaction id}
    ///
    /// For IPv4 only the cookie takes part; the operation is its own inverse.
    private byte[] xorAddress(byte[] ip) {
        var mask = ByteBuffer.allocate(16).putInt(MAGIC_COOKIE).put(transactionId).array();
        var result = new byte[ip.length];
        for (var i = 0; i < ip.length; i++) {
            result[i] = (byte) (ip[i] ^ mask[i]);
        }
        return result;
    }

    /// {@return the 20-byte HMAC-SHA1 of `data` under `key`}
    ///
    /// @throws IllegalStateException if the JDK provides no HmacSHA1
    private static byte[] hmacSha1(byte[] key, byte[] data) {
        try {
            var mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HmacSHA1 unavailable", exception);
        }
    }

    /// {@return the message type in hex and the number of attributes}
    @Override
    public String toString() {
        return "StunMessage[type=0x" + Integer.toHexString(type) + ", attributes=" + attributes.size() + "]";
    }

    /// One attribute.
    ///
    /// @param type  the attribute type
    /// @param value the attribute value, without padding
    private record Attribute(int type, byte[] value) {
        /// Creates an attribute without copying its value.
        private Attribute {
            Objects.requireNonNull(value, "value cannot be null");
        }
    }
}
