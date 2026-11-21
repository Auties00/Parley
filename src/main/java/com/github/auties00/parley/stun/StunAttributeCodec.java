package com.github.auties00.parley.stun;

import com.github.auties00.parley.stun.StunAttribute.AdditionalAddressFamily;
import com.github.auties00.parley.stun.StunAttribute.AddressErrorCode;
import com.github.auties00.parley.stun.StunAttribute.AlternateDomain;
import com.github.auties00.parley.stun.StunAttribute.AlternateServer;
import com.github.auties00.parley.stun.StunAttribute.ChannelNumber;
import com.github.auties00.parley.stun.StunAttribute.Data;
import com.github.auties00.parley.stun.StunAttribute.DontFragment;
import com.github.auties00.parley.stun.StunAttribute.ErrorCode;
import com.github.auties00.parley.stun.StunAttribute.EvenPort;
import com.github.auties00.parley.stun.StunAttribute.Fingerprint;
import com.github.auties00.parley.stun.StunAttribute.IceControlled;
import com.github.auties00.parley.stun.StunAttribute.IceControlling;
import com.github.auties00.parley.stun.StunAttribute.Icmp;
import com.github.auties00.parley.stun.StunAttribute.Lifetime;
import com.github.auties00.parley.stun.StunAttribute.MappedAddress;
import com.github.auties00.parley.stun.StunAttribute.MessageIntegrity;
import com.github.auties00.parley.stun.StunAttribute.MessageIntegritySha256;
import com.github.auties00.parley.stun.StunAttribute.Nonce;
import com.github.auties00.parley.stun.StunAttribute.PasswordAlgorithm;
import com.github.auties00.parley.stun.StunAttribute.PasswordAlgorithms;
import com.github.auties00.parley.stun.StunAttribute.Priority;
import com.github.auties00.parley.stun.StunAttribute.Realm;
import com.github.auties00.parley.stun.StunAttribute.RequestedAddressFamily;
import com.github.auties00.parley.stun.StunAttribute.RequestedTransport;
import com.github.auties00.parley.stun.StunAttribute.ReservationToken;
import com.github.auties00.parley.stun.StunAttribute.Software;
import com.github.auties00.parley.stun.StunAttribute.Unknown;
import com.github.auties00.parley.stun.StunAttribute.UnknownAttributes;
import com.github.auties00.parley.stun.StunAttribute.UseCandidate;
import com.github.auties00.parley.stun.StunAttribute.UserHash;
import com.github.auties00.parley.stun.StunAttribute.Username;
import com.github.auties00.parley.stun.StunAttribute.XorMappedAddress;
import com.github.auties00.parley.stun.StunAttribute.XorPeerAddress;
import com.github.auties00.parley.stun.StunAttribute.XorRelayedAddress;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;

/// Encodes and decodes attribute values; the framing (type, length, padding) belongs to [StunMessage].
final class StunAttributeCodec {
    /// The magic cookie the XOR address attributes mix in.
    static final int MAGIC_COOKIE = 0x2112A442;

    /// Not instantiated.
    private StunAttributeCodec() {
    }

    /// Decodes one attribute value.
    ///
    /// A value of a known type that is malformed throws, because a comprehension-required attribute must be
    /// understood and a damaged optional one would be misread.
    ///
    /// @param type          the attribute type
    /// @param value         the value, its remaining bytes, without padding; read without moving the original
    /// @param transactionId the transaction id of the message, for the XOR address attributes
    /// @return the attribute; an [Unknown] for a type Parley does not model, viewing `value`
    /// @throws StunFormatException if a value of a known type is malformed
    static StunAttribute decode(int type, ByteBuffer value, StunTransactionId transactionId) throws StunFormatException {
        var length = value.remaining();
        var view = value.duplicate();
        return switch (type) {
            case MappedAddress.TYPE -> new MappedAddress(readAddress(view, null));
            case XorMappedAddress.TYPE -> new XorMappedAddress(readAddress(view, transactionId));
            case XorPeerAddress.TYPE -> new XorPeerAddress(readAddress(view, transactionId));
            case XorRelayedAddress.TYPE -> new XorRelayedAddress(readAddress(view, transactionId));
            case AlternateServer.TYPE -> new AlternateServer(readAddress(view, null));
            case Username.TYPE -> new Username(readString(view));
            case Realm.TYPE -> new Realm(readString(view));
            case Nonce.TYPE -> new Nonce(readString(view));
            case Software.TYPE -> new Software(readString(view));
            case AlternateDomain.TYPE -> new AlternateDomain(readString(view));
            case MessageIntegrity.TYPE -> {
                requireLength(type, length, MessageIntegrity.LENGTH);
                yield new MessageIntegrity(readBytes(view));
            }
            case MessageIntegritySha256.TYPE -> {
                if (length < 16 || length > 32 || (length & 3) != 0) {
                    throw new StunFormatException("MESSAGE-INTEGRITY-SHA256 of " + length + " bytes");
                }
                yield new MessageIntegritySha256(readBytes(view));
            }
            case UserHash.TYPE -> {
                requireLength(type, length, 32);
                yield new UserHash(readBytes(view));
            }
            case Fingerprint.TYPE -> {
                requireLength(type, length, 4);
                yield new Fingerprint(Integer.toUnsignedLong(view.getInt()));
            }
            case ErrorCode.TYPE -> {
                var error = readError(view, type);
                yield new ErrorCode(error.code(), error.reason());
            }
            case UnknownAttributes.TYPE -> {
                if ((length & 1) != 0) {
                    throw new StunFormatException("UNKNOWN-ATTRIBUTES of odd length " + length);
                }
                var types = new ArrayList<Integer>(length / 2);
                while (view.hasRemaining()) {
                    types.add(view.getShort() & 0xFFFF);
                }
                yield new UnknownAttributes(types);
            }
            case ChannelNumber.TYPE -> {
                requireLength(type, length, 4);
                yield new ChannelNumber(view.getShort() & 0xFFFF);
            }
            case Lifetime.TYPE -> {
                requireLength(type, length, 4);
                yield new Lifetime(Duration.ofSeconds(Integer.toUnsignedLong(view.getInt())));
            }
            case Data.TYPE -> new Data(view);
            case RequestedAddressFamily.TYPE -> {
                requireLength(type, length, 4);
                yield new RequestedAddressFamily(readFamily(view.get() & 0xFF));
            }
            case AdditionalAddressFamily.TYPE -> {
                requireLength(type, length, 4);
                yield new AdditionalAddressFamily(readFamily(view.get() & 0xFF));
            }
            case EvenPort.TYPE -> {
                if (length < 1) {
                    throw new StunFormatException("empty EVEN-PORT");
                }
                yield new EvenPort((view.get() & 0x80) != 0);
            }
            case RequestedTransport.TYPE -> {
                requireLength(type, length, 4);
                yield new RequestedTransport(view.get() & 0xFF);
            }
            case DontFragment.TYPE -> {
                requireLength(type, length, 0);
                yield new DontFragment();
            }
            case UseCandidate.TYPE -> {
                requireLength(type, length, 0);
                yield new UseCandidate();
            }
            case ReservationToken.TYPE -> {
                requireLength(type, length, 8);
                yield new ReservationToken(view.getLong());
            }
            case Priority.TYPE -> {
                requireLength(type, length, 4);
                yield new Priority(Integer.toUnsignedLong(view.getInt()));
            }
            case IceControlled.TYPE -> {
                requireLength(type, length, 8);
                yield new IceControlled(view.getLong());
            }
            case IceControlling.TYPE -> {
                requireLength(type, length, 8);
                yield new IceControlling(view.getLong());
            }
            case PasswordAlgorithm.TYPE -> {
                if (length < 4) {
                    throw new StunFormatException("PASSWORD-ALGORITHM of " + length + " bytes");
                }
                var algorithm = view.getShort() & 0xFFFF;
                var parameters = view.getShort() & 0xFFFF;
                if (parameters + 4 > length) {
                    throw new StunFormatException("PASSWORD-ALGORITHM parameters overflow the attribute");
                }
                yield new PasswordAlgorithm(algorithm);
            }
            case PasswordAlgorithms.TYPE -> {
                var algorithms = new ArrayList<Integer>();
                while (view.hasRemaining()) {
                    if (view.remaining() < 4) {
                        throw new StunFormatException("truncated PASSWORD-ALGORITHMS entry");
                    }
                    algorithms.add(view.getShort() & 0xFFFF);
                    var parameters = view.getShort() & 0xFFFF;
                    var padded = (parameters + 3) & ~3;
                    if (padded > view.remaining()) {
                        throw new StunFormatException("PASSWORD-ALGORITHMS parameters overflow the attribute");
                    }
                    view.position(view.position() + padded);
                }
                yield new PasswordAlgorithms(algorithms);
            }
            case AddressErrorCode.TYPE -> {
                if (length < 4) {
                    throw new StunFormatException("ADDRESS-ERROR-CODE of " + length + " bytes");
                }
                var family = readFamily(view.get(view.position()) & 0xFF);
                var error = readError(view, type);
                yield new AddressErrorCode(family, error.code(), error.reason());
            }
            case Icmp.TYPE -> {
                requireLength(type, length, 8);
                view.getShort();
                var icmpType = view.get() & 0x7F;
                var icmpCode = view.get() & 0xFF;
                yield new Icmp(icmpType, icmpCode, Integer.toUnsignedLong(view.getInt()));
            }
            default -> new Unknown(type, view);
        };
    }

    /// {@return the length of an attribute's value, without padding}
    ///
    /// @throws IllegalArgumentException if a string value is longer than 65535 bytes
    static int valueLength(StunAttribute attribute) {
        return switch (attribute) {
            case MappedAddress(var address) -> addressLength(address);
            case XorMappedAddress(var address) -> addressLength(address);
            case XorPeerAddress(var address) -> addressLength(address);
            case XorRelayedAddress(var address) -> addressLength(address);
            case AlternateServer(var address) -> addressLength(address);
            case Username(var value) -> stringLength(value);
            case Realm(var value) -> stringLength(value);
            case Nonce(var value) -> stringLength(value);
            case Software(var value) -> stringLength(value);
            case AlternateDomain(var value) -> stringLength(value);
            case MessageIntegrity _ -> MessageIntegrity.LENGTH;
            case MessageIntegritySha256 integrity -> integrity.hmac().length;
            case UserHash _ -> 32;
            case Fingerprint _ -> 4;
            case ErrorCode(var _, var reason) -> 4 + stringLength(reason);
            case UnknownAttributes(var types) -> types.size() * 2;
            case ChannelNumber _, Lifetime _, RequestedAddressFamily _, AdditionalAddressFamily _,
                 RequestedTransport _, Priority _, PasswordAlgorithm _ -> 4;
            case Data data -> data.value().remaining();
            case EvenPort _ -> 1;
            case DontFragment _, UseCandidate _ -> 0;
            case ReservationToken _, IceControlled _, IceControlling _, Icmp _ -> 8;
            case PasswordAlgorithms(var algorithms) -> algorithms.size() * 4;
            case AddressErrorCode(var _, var _, var reason) -> 4 + stringLength(reason);
            case Unknown unknown -> unknown.value().remaining();
        };
    }

    /// Writes an attribute's value, without padding, at the buffer's position.
    ///
    /// @param attribute     the attribute
    /// @param out           the destination, with at least [#valueLength(StunAttribute)] bytes remaining
    /// @param transactionId the transaction id of the message, for the XOR address attributes
    static void encode(StunAttribute attribute, ByteBuffer out, StunTransactionId transactionId) {
        switch (attribute) {
            case MappedAddress(var address) -> writeAddress(out, address, null);
            case XorMappedAddress(var address) -> writeAddress(out, address, transactionId);
            case XorPeerAddress(var address) -> writeAddress(out, address, transactionId);
            case XorRelayedAddress(var address) -> writeAddress(out, address, transactionId);
            case AlternateServer(var address) -> writeAddress(out, address, null);
            case Username(var value) -> out.put(value.getBytes(StandardCharsets.UTF_8));
            case Realm(var value) -> out.put(value.getBytes(StandardCharsets.UTF_8));
            case Nonce(var value) -> out.put(value.getBytes(StandardCharsets.UTF_8));
            case Software(var value) -> out.put(value.getBytes(StandardCharsets.UTF_8));
            case AlternateDomain(var value) -> out.put(value.getBytes(StandardCharsets.UTF_8));
            case MessageIntegrity integrity -> out.put(integrity.hmac());
            case MessageIntegritySha256 integrity -> out.put(integrity.hmac());
            case UserHash hash -> out.put(hash.hash());
            case Fingerprint(var crc) -> out.putInt((int) crc);
            case ErrorCode(var code, var reason) -> writeError(out, 0, code, reason);
            case UnknownAttributes(var types) -> types.forEach(type -> out.putShort((short) (int) type));
            case ChannelNumber(var channel) -> out.putShort((short) channel).putShort((short) 0);
            case Lifetime(var lifetime) -> out.putInt((int) lifetime.getSeconds());
            case Data data -> out.put(data.value());
            case RequestedAddressFamily(var family) -> out.put((byte) family.code()).put((byte) 0).putShort((short) 0);
            case AdditionalAddressFamily(var family) -> out.put((byte) family.code()).put((byte) 0).putShort((short) 0);
            case EvenPort(var reserveNext) -> out.put((byte) (reserveNext ? 0x80 : 0));
            case RequestedTransport(var protocol) -> out.put((byte) protocol).put((byte) 0).putShort((short) 0);
            case DontFragment _, UseCandidate _ -> {
            }
            case ReservationToken(var token) -> out.putLong(token);
            case Priority(var priority) -> out.putInt((int) priority);
            case IceControlled(var tieBreaker) -> out.putLong(tieBreaker);
            case IceControlling(var tieBreaker) -> out.putLong(tieBreaker);
            case PasswordAlgorithm(var algorithm) -> out.putShort((short) algorithm).putShort((short) 0);
            case PasswordAlgorithms(var algorithms) -> algorithms.forEach(algorithm -> out.putShort((short) (int) algorithm).putShort((short) 0));
            case AddressErrorCode(var family, var code, var reason) -> writeError(out, family.code(), code, reason);
            case Icmp(var icmpType, var icmpCode, var errorData) -> out.putShort((short) 0).put((byte) icmpType).put((byte) icmpCode).putInt((int) errorData);
            case Unknown unknown -> out.put(unknown.value());
        }
    }

    /// Fails unless an attribute value has the expected length.
    private static void requireLength(int type, int length, int expected) throws StunFormatException {
        if (length != expected) {
            throw new StunFormatException("attribute 0x" + Integer.toHexString(type) + " has " + length + " bytes, not " + expected);
        }
    }

    /// {@return the remaining bytes of a buffer, copied}
    private static byte[] readBytes(ByteBuffer view) {
        var bytes = new byte[view.remaining()];
        view.get(bytes);
        return bytes;
    }

    /// {@return the remaining bytes of a buffer decoded as strict UTF-8}
    private static String readString(ByteBuffer view) throws StunFormatException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(view)
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new StunFormatException("attribute is not valid UTF-8", exception);
        }
    }

    /// {@return the UTF-8 length of a string attribute}
    private static int stringLength(String value) {
        var length = StandardCharsets.UTF_8.encode(CharBuffer.wrap(value)).remaining();
        if (length > 0xFFFF) {
            throw new IllegalArgumentException("attribute value longer than 65535 bytes");
        }
        return length;
    }

    /// The code and reason of an error attribute.
    private record Error(int code, String reason) {
    }

    /// {@return the class, number and reason of an `ERROR-CODE`-style value}
    private static Error readError(ByteBuffer view, int type) throws StunFormatException {
        if (view.remaining() < 4) {
            throw new StunFormatException("attribute 0x" + Integer.toHexString(type) + " shorter than 4 bytes");
        }
        view.getShort();
        var errorClass = view.get() & 0x07;
        var number = view.get() & 0xFF;
        if (errorClass < 3 || errorClass > 6 || number > 99) {
            throw new StunFormatException("error code out of range: class " + errorClass + ", number " + number);
        }
        return new Error(errorClass * 100 + number, readString(view));
    }

    /// Writes an `ERROR-CODE`-style value whose first byte is `first`.
    private static void writeError(ByteBuffer out, int first, int code, String reason) {
        out.put((byte) first).put((byte) 0).put((byte) (code / 100)).put((byte) (code % 100));
        out.put(reason.getBytes(StandardCharsets.UTF_8));
    }

    /// {@return the family a code names}
    private static StunAddressFamily readFamily(int code) throws StunFormatException {
        return StunAddressFamily.ofCode(code)
                .orElseThrow(() -> new StunFormatException("unknown address family 0x" + Integer.toHexString(code)));
    }

    /// {@return the value length of an address attribute}
    private static int addressLength(InetSocketAddress address) {
        return 4 + address.getAddress().getAddress().length;
    }

    /// {@return an address attribute value, XORed when `transactionId` is not `null`}
    private static InetSocketAddress readAddress(ByteBuffer view, StunTransactionId transactionId) throws StunFormatException {
        if (view.remaining() < 4) {
            throw new StunFormatException("address attribute shorter than 4 bytes");
        }
        view.get();
        var family = readFamily(view.get() & 0xFF);
        var port = view.getShort() & 0xFFFF;
        if (view.remaining() != family.addressLength()) {
            throw new StunFormatException("address attribute of family " + family + " has " + view.remaining() + " address bytes");
        }
        var ip = readBytes(view);
        if (transactionId != null) {
            port ^= MAGIC_COOKIE >>> 16;
            xor(ip, transactionId);
        }
        try {
            return new InetSocketAddress(InetAddress.getByAddress(ip), port);
        } catch (UnknownHostException exception) {
            throw new StunFormatException("malformed address", exception);
        }
    }

    /// Writes an address attribute value, XORed when `transactionId` is not `null`.
    private static void writeAddress(ByteBuffer out, InetSocketAddress address, StunTransactionId transactionId) {
        var ip = address.getAddress().getAddress();
        var port = address.getPort();
        if (transactionId != null) {
            port ^= MAGIC_COOKIE >>> 16;
            xor(ip, transactionId);
        }
        out.put((byte) 0).put((byte) (ip.length == 4 ? StunAddressFamily.IPV4.code() : StunAddressFamily.IPV6.code()));
        out.putShort((short) port);
        out.put(ip);
    }

    /// XORs an address in place with the magic cookie followed by the transaction id; for IPv4 only the cookie takes
    /// part.
    private static void xor(byte[] ip, StunTransactionId transactionId) {
        var mask = ByteBuffer.allocate(16).putInt(MAGIC_COOKIE);
        transactionId.write(mask);
        var bytes = mask.array();
        for (var i = 0; i < ip.length; i++) {
            ip[i] ^= bytes[i];
        }
    }
}
