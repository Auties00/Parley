package com.github.auties00.parley.stun;

import com.github.auties00.parley.stun.StunAttribute.ErrorCode;
import com.github.auties00.parley.stun.StunAttribute.Fingerprint;
import com.github.auties00.parley.stun.StunAttribute.MessageIntegrity;
import com.github.auties00.parley.stun.StunAttribute.MessageIntegritySha256;
import com.github.auties00.parley.stun.StunAttribute.Unknown;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.zip.CRC32;

/// A STUN message: a class, a method, a transaction id and a list of [StunAttribute]s.
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
/// # Building and encoding
///
/// A message is immutable. [#request(StunMethod,List)], [#indication(StunMethod,List)] and the response factories
/// build one; the `encode` methods write it, appending `MESSAGE-INTEGRITY` or `MESSAGE-INTEGRITY-SHA256` under a
/// [StunKey] and `FINGERPRINT` as the last attributes, in that order. Integrity and fingerprint attributes in the
/// attribute list are not written: they are always computed.
///
/// {@snippet lang = java :
/// var request = StunMessage.request(StunMethod.BINDING, List.of(
///         new StunAttribute.Username(remoteUfrag + ":" + localUfrag),
///         new StunAttribute.Priority(priority),
///         new StunAttribute.IceControlling(tieBreaker)));
/// ByteBuffer datagram = request.encode(StunKey.shortTerm(remotePassword), StunIntegrity.HMAC_SHA1, true);
/// }
///
/// # Decoding
///
/// [#decode(ByteBuffer)] parses without copying the packet: [StunAttribute.Data] and [StunAttribute.Unknown] values
/// are views of the buffer, and [#verifyIntegrity(StunKey)] reads the buffer. Such a message is valid only as long as
/// the buffer is, typically the duration of a [com.github.auties00.parley.net.PacketReceiver] call; [#copy()] makes
/// one that owns its bytes. Decoding checks `FINGERPRINT` when present, keeps the attributes after
/// `MESSAGE-INTEGRITY` only when they are `MESSAGE-INTEGRITY-SHA256` or `FINGERPRINT` (RFC 8489 section 14.5), and
/// ignores everything after `FINGERPRINT`.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
public final class StunMessage {
    /// The magic cookie every message since RFC 5389 carries at offset 4.
    public static final int MAGIC_COOKIE = 0x2112A442;

    /// The length of the message header.
    public static final int HEADER_LENGTH = 20;

    /// The class.
    private final StunClass messageClass;

    /// The method.
    private final StunMethod method;

    /// The transaction id.
    private final StunTransactionId transactionId;

    /// The unmodifiable attributes, in order.
    private final List<StunAttribute> attributes;

    /// The bytes the message was decoded from, from the header to the end of the last attribute kept, or `null` for
    /// a message built locally.
    private final ByteBuffer raw;

    /// The offset in [#raw] of the `MESSAGE-INTEGRITY` attribute, or `-1` when there is none.
    private final int integrityOffset;

    /// The offset in [#raw] of the `MESSAGE-INTEGRITY-SHA256` attribute, or `-1` when there is none.
    private final int integritySha256Offset;

    /// Creates a message from its parts.
    private StunMessage(StunClass messageClass, StunMethod method, StunTransactionId transactionId,
                        List<StunAttribute> attributes, ByteBuffer raw, int integrityOffset, int integritySha256Offset) {
        this.messageClass = messageClass;
        this.method = method;
        this.transactionId = transactionId;
        this.attributes = attributes;
        this.raw = raw;
        this.integrityOffset = integrityOffset;
        this.integritySha256Offset = integritySha256Offset;
    }

    /// {@return a message with the given parts}
    ///
    /// @param messageClass  the class
    /// @param method        the method
    /// @param transactionId the transaction id
    /// @param attributes    the attributes, copied
    public static StunMessage of(StunClass messageClass, StunMethod method, StunTransactionId transactionId,
                                 List<StunAttribute> attributes) {
        Objects.requireNonNull(messageClass, "messageClass cannot be null");
        Objects.requireNonNull(method, "method cannot be null");
        Objects.requireNonNull(transactionId, "transactionId cannot be null");
        return new StunMessage(messageClass, method, transactionId, List.copyOf(attributes), null, -1, -1);
    }

    /// {@return a request with a fresh random transaction id}
    ///
    /// @param method     the method
    /// @param attributes the attributes, copied
    public static StunMessage request(StunMethod method, List<StunAttribute> attributes) {
        return of(StunClass.REQUEST, method, StunTransactionId.random(), attributes);
    }

    /// {@return an indication with a fresh random transaction id}
    ///
    /// @param method     the method
    /// @param attributes the attributes, copied
    public static StunMessage indication(StunMethod method, List<StunAttribute> attributes) {
        return of(StunClass.INDICATION, method, StunTransactionId.random(), attributes);
    }

    /// {@return a success response to this request, with its method and transaction id}
    ///
    /// @param attributes the attributes, copied
    public StunMessage successResponse(List<StunAttribute> attributes) {
        return of(StunClass.SUCCESS_RESPONSE, method, transactionId, attributes);
    }

    /// {@return an error response to this request, with an `ERROR-CODE` first and then `attributes`}
    ///
    /// @param code       the error code, `300..699`
    /// @param reason     the reason phrase
    /// @param attributes the other attributes, copied
    /// @throws IllegalArgumentException if `code` is outside `300..699`
    public StunMessage errorResponse(int code, String reason, List<StunAttribute> attributes) {
        var all = new ArrayList<StunAttribute>(attributes.size() + 1);
        all.add(new ErrorCode(code, reason));
        all.addAll(attributes);
        return of(StunClass.ERROR_RESPONSE, method, transactionId, all);
    }

    /// {@return whether a packet looks like a STUN message}
    ///
    /// The packet is the buffer's remaining bytes, which are not moved. It qualifies when it holds at least the
    /// header, its first byte is in `0..3` (the range RFC 7983 assigns to STUN on a shared port), the magic cookie
    /// is at offset 4, and the declared length is a multiple of four that fits in the packet.
    ///
    /// @param packet the packet
    /// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
    public static boolean isStun(ByteBuffer packet) {
        var start = packet.position();
        if (packet.remaining() < HEADER_LENGTH || (packet.get(start) & 0xFF) > 3) {
            return false;
        }
        var length = packet.getShort(start + 2) & 0xFFFF;
        return packet.getInt(start + 4) == MAGIC_COOKIE
                && (length & 3) == 0
                && HEADER_LENGTH + length <= packet.remaining();
    }

    /// {@return the total length of the message whose header starts at the buffer's position, or `-1` when fewer
    /// than four bytes remain}
    ///
    /// This is how a reader of a stream (TURN over TCP) finds the end of a message before all of it has arrived.
    ///
    /// @param packet the buffer, not moved
    public static int frameLength(ByteBuffer packet) {
        if (packet.remaining() < 4) {
            return -1;
        }
        return HEADER_LENGTH + (packet.getShort(packet.position() + 2) & 0xFFFF);
    }

    /// Decodes a STUN message without copying it.
    ///
    /// The message is the buffer's remaining bytes; the buffer's position is not moved. Bytes after the length the
    /// header declares are ignored. The returned message holds views of the buffer (see the class documentation).
    ///
    /// @param packet the packet
    /// @return the message
    /// @throws StunFormatException if the bytes fail [#isStun(ByteBuffer)], the method is unknown, an attribute
    ///                             overflows the message, a value of a known type is malformed, or `FINGERPRINT`
    ///                             does not match
    public static StunMessage decode(ByteBuffer packet) throws StunFormatException {
        Objects.requireNonNull(packet, "packet cannot be null");
        if (!isStun(packet)) {
            throw new StunFormatException("not a STUN message");
        }
        var start = packet.position();
        var type = packet.getShort(start) & 0xFFFF;
        var length = packet.getShort(start + 2) & 0xFFFF;
        var raw = packet.slice(start, HEADER_LENGTH + length);
        var classBits = ((type >>> 7) & 0b10) | ((type >>> 4) & 0b01);
        var methodCode = (type & 0x000F) | ((type >>> 1) & 0x0070) | ((type >>> 2) & 0x0F80);
        var messageClass = StunClass.ofBits(classBits);
        var method = StunMethod.ofCode(methodCode)
                .orElseThrow(() -> new StunFormatException("unknown STUN method 0x" + Integer.toHexString(methodCode)));
        var transactionId = StunTransactionId.read(raw, 8);
        var attributes = new ArrayList<StunAttribute>();
        var integrityOffset = -1;
        var integritySha256Offset = -1;
        var offset = HEADER_LENGTH;
        var end = HEADER_LENGTH + length;
        while (offset + 4 <= end) {
            var attributeType = raw.getShort(offset) & 0xFFFF;
            var attributeLength = raw.getShort(offset + 2) & 0xFFFF;
            var valueStart = offset + 4;
            if (valueStart + attributeLength > end) {
                throw new StunFormatException("attribute 0x" + Integer.toHexString(attributeType) + " overflows the message");
            }
            var next = valueStart + ((attributeLength + 3) & ~3);
            var value = raw.slice(valueStart, attributeLength);
            if (attributeType == Fingerprint.TYPE) {
                var fingerprint = (Fingerprint) StunAttributeCodec.decode(attributeType, value, transactionId);
                if (fingerprint.crc() != fingerprint(raw, offset)) {
                    throw new StunFormatException("FINGERPRINT does not match");
                }
                attributes.add(fingerprint);
                break;
            }
            var afterIntegrity = integrityOffset >= 0 || integritySha256Offset >= 0;
            if (afterIntegrity && (attributeType != MessageIntegritySha256.TYPE || integritySha256Offset >= 0)) {
                offset = next;
                continue;
            }
            if (attributeType == MessageIntegrity.TYPE) {
                integrityOffset = offset;
            } else if (attributeType == MessageIntegritySha256.TYPE) {
                integritySha256Offset = offset;
            }
            StunAttribute attribute;
            try {
                attribute = StunAttributeCodec.decode(attributeType, value, transactionId);
            } catch (StunFormatException exception) {
                if (StunAttribute.isComprehensionRequired(attributeType)) {
                    throw exception;
                }
                attribute = new Unknown(attributeType, value);
            }
            attributes.add(attribute);
            offset = next;
        }
        return new StunMessage(messageClass, method, transactionId, List.copyOf(attributes), raw, integrityOffset,
                integritySha256Offset);
    }

    /// {@return the class}
    public StunClass messageClass() {
        return messageClass;
    }

    /// {@return the method}
    public StunMethod method() {
        return method;
    }

    /// {@return the transaction id}
    public StunTransactionId transactionId() {
        return transactionId;
    }

    /// {@return the unmodifiable attributes, in order}
    public List<StunAttribute> attributes() {
        return attributes;
    }

    /// {@return the first attribute of a record type, or an empty optional when the message has none}
    ///
    /// @param type the attribute record, such as `StunAttribute.XorMappedAddress.class`
    /// @param <T>  the attribute record
    public <T extends StunAttribute> Optional<T> attribute(Class<T> type) {
        Objects.requireNonNull(type, "type cannot be null");
        for (var attribute : attributes) {
            if (type.isInstance(attribute)) {
                return Optional.of(type.cast(attribute));
            }
        }
        return Optional.empty();
    }

    /// {@return every attribute of a record type, in order}
    ///
    /// @param type the attribute record
    /// @param <T>  the attribute record
    public <T extends StunAttribute> List<T> attributes(Class<T> type) {
        Objects.requireNonNull(type, "type cannot be null");
        return attributes.stream().filter(type::isInstance).map(type::cast).toList();
    }

    /// {@return whether the message carries an attribute of a record type}
    ///
    /// @param type the attribute record
    public boolean has(Class<? extends StunAttribute> type) {
        return attribute(type).isPresent();
    }

    /// {@return the error code of an error response, or an empty optional when the message has no `ERROR-CODE`}
    public Optional<ErrorCode> errorCode() {
        return attribute(ErrorCode.class);
    }

    /// {@return the comprehension-required attribute types the message carries that Parley does not understand}
    ///
    /// A server answers a request with such types with a 420 error listing them; a client discards a response with
    /// them.
    public List<Integer> unknownComprehensionRequired() {
        return attributes.stream()
                .filter(attribute -> attribute instanceof Unknown && StunAttribute.isComprehensionRequired(attribute.type()))
                .map(StunAttribute::type)
                .toList();
    }

    /// {@return whether the message was decoded and carries a message integrity attribute that verifies under
    /// `key`}
    ///
    /// When the message carries `MESSAGE-INTEGRITY-SHA256`, that attribute is checked; otherwise
    /// `MESSAGE-INTEGRITY`. The HMAC covers the message up to the attribute, with the header length rewritten to end
    /// right after it, as RFC 8489 sections 14.5 and 14.6 define. The comparison runs in constant time. A message
    /// built locally returns `false`.
    ///
    /// @param key the key the sender signed with
    public boolean verifyIntegrity(StunKey key) {
        Objects.requireNonNull(key, "key cannot be null");
        if (raw == null) {
            return false;
        }
        if (integritySha256Offset >= 0) {
            var length = raw.getShort(integritySha256Offset + 2) & 0xFFFF;
            var expected = hmac("HmacSHA256", key, raw, integritySha256Offset, integritySha256Offset - HEADER_LENGTH + 4 + length);
            return equalsPrefix(expected, raw, integritySha256Offset + 4, length);
        }
        if (integrityOffset >= 0) {
            var expected = hmac("HmacSHA1", key, raw, integrityOffset, integrityOffset - HEADER_LENGTH + 24);
            return equalsPrefix(expected, raw, integrityOffset + 4, MessageIntegrity.LENGTH);
        }
        return false;
    }

    /// {@return the integrity attribute the message carries, or an empty optional when it carries none}
    public Optional<StunIntegrity> integrity() {
        if (has(MessageIntegritySha256.class)) {
            return Optional.of(StunIntegrity.HMAC_SHA256);
        }
        return has(MessageIntegrity.class) ? Optional.of(StunIntegrity.HMAC_SHA1) : Optional.empty();
    }

    /// {@return a message equal to this one that owns every byte it references, valid after the decoded buffer is
    /// reused}
    public StunMessage copy() {
        if (raw == null) {
            return this;
        }
        var owned = ByteBuffer.allocate(raw.remaining()).put(raw.duplicate()).flip();
        try {
            return decode(owned);
        } catch (StunFormatException exception) {
            throw new IllegalStateException("a decoded message no longer decodes", exception);
        }
    }

    /// {@return the encoded length of the message without integrity or `FINGERPRINT`}
    public int encodedLength() {
        return length(Optional.empty(), false);
    }

    /// {@return the encoded length of the message without integrity}
    ///
    /// @param fingerprint whether `FINGERPRINT` is appended
    public int encodedLength(boolean fingerprint) {
        return length(Optional.empty(), fingerprint);
    }

    /// {@return the encoded length of the message signed with an integrity attribute}
    ///
    /// @param integrity   the integrity attribute appended
    /// @param fingerprint whether `FINGERPRINT` is appended after it
    public int encodedLength(StunIntegrity integrity, boolean fingerprint) {
        Objects.requireNonNull(integrity, "integrity cannot be null");
        return length(Optional.of(integrity), fingerprint);
    }

    private int length(Optional<StunIntegrity> integrity, boolean fingerprint) {
        var length = HEADER_LENGTH;
        for (var attribute : attributes) {
            if (isComputed(attribute)) {
                continue;
            }
            length += 4 + ((StunAttributeCodec.valueLength(attribute) + 3) & ~3);
        }
        if (integrity.isPresent()) {
            length += integrity.get() == StunIntegrity.HMAC_SHA256 ? 36 : 24;
        }
        return fingerprint ? length + 8 : length;
    }

    /// {@return the message encoded into a new buffer, without integrity}
    ///
    /// @param fingerprint whether to append `FINGERPRINT`
    /// @throws IllegalArgumentException if the attributes do not fit in 65535 bytes
    public ByteBuffer encode(boolean fingerprint) {
        var buffer = ByteBuffer.allocate(length(Optional.empty(), fingerprint));
        write(buffer, Optional.empty(), StunIntegrity.HMAC_SHA1, fingerprint);
        return buffer.flip();
    }

    /// {@return the message encoded into a new buffer, signed with `key`}
    ///
    /// @param key         the key
    /// @param integrity   the integrity attribute to append
    /// @param fingerprint whether to append `FINGERPRINT` after it
    /// @throws IllegalArgumentException if the attributes do not fit in 65535 bytes
    public ByteBuffer encode(StunKey key, StunIntegrity integrity, boolean fingerprint) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(integrity, "integrity cannot be null");
        var buffer = ByteBuffer.allocate(length(Optional.of(integrity), fingerprint));
        write(buffer, Optional.of(key), integrity, fingerprint);
        return buffer.flip();
    }

    /// Encodes the message at the buffer's position, which advances past it, without integrity or `FINGERPRINT`.
    ///
    /// @param destination the buffer, with at least [#encodedLength()] bytes remaining
    /// @return the number of bytes written
    /// @throws java.nio.BufferOverflowException if the message does not fit
    /// @throws IllegalArgumentException         if the attributes do not fit in 65535 bytes
    public int encodeTo(ByteBuffer destination) {
        return write(destination, Optional.empty(), StunIntegrity.HMAC_SHA1, false);
    }

    /// Encodes the message at the buffer's position, which advances past it, without integrity.
    ///
    /// @param destination the buffer, with at least [#encodedLength(boolean)] bytes remaining
    /// @param fingerprint whether to append `FINGERPRINT`
    /// @return the number of bytes written
    /// @throws java.nio.BufferOverflowException if the message does not fit
    /// @throws IllegalArgumentException         if the attributes do not fit in 65535 bytes
    public int encodeTo(ByteBuffer destination, boolean fingerprint) {
        return write(destination, Optional.empty(), StunIntegrity.HMAC_SHA1, fingerprint);
    }

    /// Encodes the message at the buffer's position, which advances past it, signed with `key`.
    ///
    /// Padding bytes are zero. The integrity attribute is computed over everything written before it, then
    /// `FINGERPRINT` over everything before it.
    ///
    /// @param destination the buffer, with at least [#encodedLength(StunIntegrity,boolean)] bytes remaining
    /// @param key         the integrity key
    /// @param integrity   the integrity attribute to append
    /// @param fingerprint whether to append `FINGERPRINT`
    /// @return the number of bytes written
    /// @throws java.nio.BufferOverflowException if the message does not fit
    /// @throws IllegalArgumentException         if the attributes do not fit in 65535 bytes
    public int encodeTo(ByteBuffer destination, StunKey key, StunIntegrity integrity, boolean fingerprint) {
        Objects.requireNonNull(key, "key cannot be null");
        return write(destination, Optional.of(key), integrity, fingerprint);
    }

    private int write(ByteBuffer destination, Optional<StunKey> key, StunIntegrity integrity, boolean fingerprint) {
        Objects.requireNonNull(destination, "destination cannot be null");
        Objects.requireNonNull(integrity, "integrity cannot be null");
        var total = length(key.map(_ -> integrity), fingerprint);
        if (total - HEADER_LENGTH > 0xFFFF) {
            throw new IllegalArgumentException("STUN message longer than 65535 bytes");
        }
        if (destination.remaining() < total) {
            throw new java.nio.BufferOverflowException();
        }
        var start = destination.position();
        var view = destination.slice(start, total);
        var type = method.code();
        var classBits = messageClass.bits();
        var messageType = (type & 0x000F) | ((type & 0x0070) << 1) | ((type & 0x0F80) << 2)
                | ((classBits & 0b01) << 4) | ((classBits & 0b10) << 7);
        view.putShort((short) messageType);
        view.putShort((short) 0);
        view.putInt(MAGIC_COOKIE);
        transactionId.write(view);
        for (var attribute : attributes) {
            if (isComputed(attribute)) {
                continue;
            }
            var length = StunAttributeCodec.valueLength(attribute);
            view.putShort((short) attribute.type());
            view.putShort((short) length);
            StunAttributeCodec.encode(attribute, view, transactionId);
            for (var pad = (4 - (length & 3)) & 3; pad > 0; pad--) {
                view.put((byte) 0);
            }
        }
        if (key.isPresent()) {
            var offset = view.position();
            if (integrity == StunIntegrity.HMAC_SHA256) {
                var hmac = hmac("HmacSHA256", key.get(), view, offset, offset - HEADER_LENGTH + 36);
                view.putShort((short) MessageIntegritySha256.TYPE).putShort((short) 32).put(hmac);
            } else {
                var hmac = hmac("HmacSHA1", key.get(), view, offset, offset - HEADER_LENGTH + 24);
                view.putShort((short) MessageIntegrity.TYPE).putShort((short) 20).put(hmac);
            }
        }
        if (fingerprint) {
            var offset = view.position();
            view.putShort(2, (short) (offset - HEADER_LENGTH + 8));
            var crc = fingerprint(view, offset);
            view.putShort((short) Fingerprint.TYPE).putShort((short) 4).putInt((int) crc);
        }
        view.putShort(2, (short) (view.position() - HEADER_LENGTH));
        destination.position(start + total);
        return total;
    }

    /// {@return whether an attribute is one the encoder computes instead of copying}
    private static boolean isComputed(StunAttribute attribute) {
        return attribute instanceof MessageIntegrity || attribute instanceof MessageIntegritySha256
                || attribute instanceof Fingerprint;
    }

    /// {@return the HMAC of the first `coveredLength` bytes of `message` (its offset `0`), with the header length
    /// field replaced by `lengthInHeader`}
    private static byte[] hmac(String algorithm, StunKey key, ByteBuffer message, int coveredLength, int lengthInHeader) {
        var mac = StunMacs.get(algorithm, key.bytes());
        var header = new byte[HEADER_LENGTH];
        message.get(0, header);
        header[2] = (byte) (lengthInHeader >>> 8);
        header[3] = (byte) lengthInHeader;
        mac.update(header);
        mac.update(message.slice(HEADER_LENGTH, coveredLength - HEADER_LENGTH));
        return mac.doFinal();
    }

    /// {@return the `FINGERPRINT` value of the first `coveredLength` bytes of `message`, with the header length
    /// field counting the fingerprint attribute}
    private static long fingerprint(ByteBuffer message, int coveredLength) {
        var lengthInHeader = coveredLength - HEADER_LENGTH + 8;
        var crc = new CRC32();
        var header = new byte[HEADER_LENGTH];
        message.get(0, header);
        header[2] = (byte) (lengthInHeader >>> 8);
        header[3] = (byte) lengthInHeader;
        crc.update(header);
        crc.update(message.slice(HEADER_LENGTH, coveredLength - HEADER_LENGTH));
        return crc.getValue() ^ Fingerprint.XOR;
    }

    /// {@return whether the first `length` bytes of `expected` equal the bytes at `offset` in `message`, compared in
    /// constant time}
    private static boolean equalsPrefix(byte[] expected, ByteBuffer message, int offset, int length) {
        if (length > expected.length) {
            return false;
        }
        // Constant time: every byte is compared whatever the earlier ones were
        var difference = 0;
        for (var i = 0; i < length; i++) {
            difference |= expected[i] ^ message.get(offset + i);
        }
        return difference == 0;
    }

    /// {@return whether `other` is a message with the same class, method, transaction id and attributes}
    @Override
    public boolean equals(Object other) {
        return other instanceof StunMessage that
                && messageClass == that.messageClass
                && method == that.method
                && transactionId.equals(that.transactionId)
                && attributes.equals(that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(messageClass, method, transactionId, attributes);
    }

    /// {@return the class, method, transaction id and attribute types}
    @Override
    public String toString() {
        return "StunMessage[" + method + " " + messageClass + ", id=" + transactionId + ", attributes="
                + attributes.stream().map(attribute -> attribute.getClass().getSimpleName()).toList() + "]";
    }
}
