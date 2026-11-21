package com.github.auties00.parley.stun;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// One attribute of a STUN message: the attributes of STUN, of the long-term credential mechanism, of ICE and of
/// TURN, each as a record, and [Unknown] for any other type.
///
/// An attribute is a type-length-value element padded to four bytes. Types `0x0000..0x7FFF` are
/// comprehension-required: an agent that does not understand one must reject the message (a request with a 420
/// error, a response by discarding it); [StunMessage#unknownComprehensionRequired()] lists them. Types
/// `0x8000..0xFFFF` are comprehension-optional and are ignored when unknown.
///
/// Address attributes hold resolved [InetSocketAddress]es. The `XOR-` variants are XORed with the magic cookie (and,
/// for IPv6, the transaction id) on the wire; the records hold the plain address and the codec applies the XOR.
///
/// `MESSAGE-INTEGRITY`, `MESSAGE-INTEGRITY-SHA256` and `FINGERPRINT` appear in decoded messages; when a message is
/// encoded they are computed, so instances of [MessageIntegrity], [MessageIntegritySha256] and [Fingerprint] in its
/// attribute list are ignored.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
public sealed interface StunAttribute {
    /// {@return the 16-bit attribute type}
    int type();

    /// {@return whether `type` is comprehension-required, `0x0000..0x7FFF`}
    ///
    /// @param type the 16-bit attribute type
    static boolean isComprehensionRequired(int type) {
        return type < 0x8000;
    }

    /// `MAPPED-ADDRESS`, the reflexive address in its plain form, which only pre-RFC 5389 servers send.
    ///
    /// @param address the address, resolved
    record MappedAddress(InetSocketAddress address) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0001;

        /// Creates the attribute.
        ///
        /// @param address the address, resolved
        /// @throws IllegalArgumentException if `address` is unresolved
        public MappedAddress {
            requireResolved(address);
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `USERNAME`, the user of a short-term (`<remote ufrag>:<local ufrag>` in ICE) or long-term credential.
    ///
    /// @param value the username, UTF-8 on the wire, less than 513 bytes
    record Username(String value) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0006;

        /// Creates the attribute.
        ///
        /// @param value the username
        public Username {
            Objects.requireNonNull(value, "value cannot be null");
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `MESSAGE-INTEGRITY`, the HMAC-SHA1 of the message up to this attribute.
    ///
    /// @param hmac the 20-byte HMAC, copied in and out
    record MessageIntegrity(byte[] hmac) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0008;

        /// The value length.
        public static final int LENGTH = 20;

        /// Creates the attribute.
        ///
        /// @param hmac the 20-byte HMAC, copied
        /// @throws IllegalArgumentException if `hmac` is not 20 bytes long
        public MessageIntegrity {
            hmac = Objects.requireNonNull(hmac, "hmac cannot be null").clone();
            if (hmac.length != LENGTH) {
                throw new IllegalArgumentException("MESSAGE-INTEGRITY has 20 bytes, not " + hmac.length);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }

        /// {@return a copy of the HMAC}
        @Override
        public byte[] hmac() {
            return hmac.clone();
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof MessageIntegrity that && MessageDigest.isEqual(hmac, that.hmac);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(hmac);
        }

        @Override
        public String toString() {
            return "MessageIntegrity[" + HexFormat.of().formatHex(hmac) + "]";
        }
    }

    /// `ERROR-CODE`, the error of an error response.
    ///
    /// @param code   the error code, `300..699`
    /// @param reason the reason phrase, UTF-8 on the wire
    record ErrorCode(int code, String reason) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0009;

        /// 300 Try Alternate: the client should contact the server in `ALTERNATE-SERVER`.
        public static final int TRY_ALTERNATE = 300;

        /// 400 Bad Request: the request was malformed.
        public static final int BAD_REQUEST = 400;

        /// 401 Unauthenticated: the request lacked valid credentials.
        public static final int UNAUTHENTICATED = 401;

        /// 403 Forbidden: the request was valid but cannot be performed (TURN).
        public static final int FORBIDDEN = 403;

        /// 420 Unknown Attribute: the request had a comprehension-required attribute the server does not understand.
        public static final int UNKNOWN_ATTRIBUTE = 420;

        /// 437 Allocation Mismatch (TURN).
        public static final int ALLOCATION_MISMATCH = 437;

        /// 438 Stale Nonce: retry with the new `NONCE`.
        public static final int STALE_NONCE = 438;

        /// 440 Address Family not Supported (TURN).
        public static final int ADDRESS_FAMILY_NOT_SUPPORTED = 440;

        /// 441 Wrong Credentials (TURN).
        public static final int WRONG_CREDENTIALS = 441;

        /// 442 Unsupported Transport Protocol (TURN).
        public static final int UNSUPPORTED_TRANSPORT_PROTOCOL = 442;

        /// 443 Peer Address Family Mismatch (TURN).
        public static final int PEER_ADDRESS_FAMILY_MISMATCH = 443;

        /// 486 Allocation Quota Reached (TURN).
        public static final int ALLOCATION_QUOTA_REACHED = 486;

        /// 487 Role Conflict (ICE): the agents claimed the same role.
        public static final int ROLE_CONFLICT = 487;

        /// 500 Server Error.
        public static final int SERVER_ERROR = 500;

        /// 508 Insufficient Capacity (TURN).
        public static final int INSUFFICIENT_CAPACITY = 508;

        /// Creates the attribute.
        ///
        /// @param code   the error code
        /// @param reason the reason phrase
        /// @throws IllegalArgumentException if `code` is outside `300..699`
        public ErrorCode {
            Objects.requireNonNull(reason, "reason cannot be null");
            if (code < 300 || code > 699) {
                throw new IllegalArgumentException("error code out of range: " + code);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `UNKNOWN-ATTRIBUTES`, the comprehension-required types a 420 error response did not understand.
    ///
    /// @param types the unmodifiable 16-bit attribute types
    record UnknownAttributes(List<Integer> types) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x000A;

        /// Creates the attribute.
        ///
        /// @param types the attribute types, copied
        public UnknownAttributes {
            types = List.copyOf(types);
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `CHANNEL-NUMBER` (TURN), the channel a ChannelBind request binds.
    ///
    /// @param channel the channel number, `0x4000..0x4FFF` for a valid binding
    record ChannelNumber(int channel) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x000C;

        /// Creates the attribute.
        ///
        /// @param channel the channel number
        /// @throws IllegalArgumentException if `channel` does not fit in 16 bits
        public ChannelNumber {
            if (channel < 0 || channel > 0xFFFF) {
                throw new IllegalArgumentException("channel out of range: " + channel);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `LIFETIME` (TURN), the time an allocation lives until refreshed.
    ///
    /// @param lifetime the lifetime, whole seconds up to `2^32 - 1`
    record Lifetime(Duration lifetime) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x000D;

        /// Creates the attribute.
        ///
        /// @param lifetime the lifetime
        /// @throws IllegalArgumentException if `lifetime` is negative or longer than `2^32 - 1` seconds
        public Lifetime {
            Objects.requireNonNull(lifetime, "lifetime cannot be null");
            if (lifetime.isNegative() || lifetime.getSeconds() > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("lifetime out of range: " + lifetime);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `XOR-PEER-ADDRESS` (TURN), the address of a peer as the relay sees it.
    ///
    /// @param address the address, resolved
    record XorPeerAddress(InetSocketAddress address) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0012;

        /// Creates the attribute.
        ///
        /// @param address the address, resolved
        /// @throws IllegalArgumentException if `address` is unresolved
        public XorPeerAddress {
            requireResolved(address);
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `DATA` (TURN), the application data of a Send or Data indication.
    ///
    /// A decoded attribute is a read-only view of the decoded buffer, valid only as long as that buffer is; see
    /// [StunMessage#decode(ByteBuffer)].
    ///
    /// @param value the data, its remaining bytes
    record Data(ByteBuffer value) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0013;

        /// Creates the attribute.
        ///
        /// @param value the data; a read-only view of its remaining bytes is kept
        public Data {
            value = Objects.requireNonNull(value, "value cannot be null").slice().asReadOnlyBuffer();
        }

        /// {@return a read-only view of the data, with its own position and limit}
        @Override
        public ByteBuffer value() {
            return value.duplicate();
        }

        @Override
        public int type() {
            return TYPE;
        }

        @Override
        public String toString() {
            return "Data[" + value.remaining() + " bytes]";
        }
    }

    /// `REALM`, the realm of a long-term credential challenge.
    ///
    /// @param value the realm, UTF-8 on the wire, less than 763 bytes
    record Realm(String value) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0014;

        /// Creates the attribute.
        ///
        /// @param value the realm
        public Realm {
            Objects.requireNonNull(value, "value cannot be null");
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `NONCE`, the server nonce of a long-term credential challenge, which may start with the "nonce cookie" that
    /// announces the security features of RFC 8489.
    ///
    /// @param value the nonce, less than 763 bytes
    record Nonce(String value) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0015;

        /// The prefix of the nonce cookie.
        public static final String COOKIE_PREFIX = "obMatJos2";

        /// Creates the attribute.
        ///
        /// @param value the nonce
        public Nonce {
            Objects.requireNonNull(value, "value cannot be null");
        }

        @Override
        public int type() {
            return TYPE;
        }

        /// {@return the 24 security feature bits of the nonce cookie, bit 0 the most significant, or an empty optional
        /// when the nonce carries no well-formed cookie}
        public Optional<Integer> securityFeatures() {
            if (value.length() < COOKIE_PREFIX.length() + 4 || !value.startsWith(COOKIE_PREFIX)) {
                return Optional.empty();
            }
            try {
                var bytes = java.util.Base64.getDecoder().decode(value.substring(COOKIE_PREFIX.length(), COOKIE_PREFIX.length() + 4));
                return Optional.of((bytes[0] & 0xFF) << 16 | (bytes[1] & 0xFF) << 8 | (bytes[2] & 0xFF));
            } catch (IllegalArgumentException exception) {
                return Optional.empty();
            }
        }

        /// {@return whether the nonce cookie sets the "Password algorithms" security feature, bit 0}
        public boolean passwordAlgorithmsFeature() {
            return securityFeatures().map(bits -> (bits & 0x800000) != 0).orElse(false);
        }

        /// {@return whether the nonce cookie sets the "Username anonymity" security feature, bit 1}
        public boolean usernameAnonymityFeature() {
            return securityFeatures().map(bits -> (bits & 0x400000) != 0).orElse(false);
        }
    }

    /// `XOR-RELAYED-ADDRESS` (TURN), the relayed transport address of an allocation.
    ///
    /// @param address the address, resolved
    record XorRelayedAddress(InetSocketAddress address) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0016;

        /// Creates the attribute.
        ///
        /// @param address the address, resolved
        /// @throws IllegalArgumentException if `address` is unresolved
        public XorRelayedAddress {
            requireResolved(address);
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `REQUESTED-ADDRESS-FAMILY` (TURN), the family of the relayed address an Allocate asks for.
    ///
    /// @param family the family
    record RequestedAddressFamily(StunAddressFamily family) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0017;

        /// Creates the attribute.
        ///
        /// @param family the family
        public RequestedAddressFamily {
            Objects.requireNonNull(family, "family cannot be null");
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `EVEN-PORT` (TURN), which asks for an even relayed port.
    ///
    /// @param reserveNext whether the next higher port should be reserved too
    record EvenPort(boolean reserveNext) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0018;

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `REQUESTED-TRANSPORT` (TURN), the protocol between the relay and peers.
    ///
    /// @param protocol the IANA protocol number, `17` for UDP
    record RequestedTransport(int protocol) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0019;

        /// The protocol number of UDP.
        public static final int UDP = 17;

        /// Creates the attribute.
        ///
        /// @param protocol the protocol number
        /// @throws IllegalArgumentException if `protocol` does not fit in 8 bits
        public RequestedTransport {
            if (protocol < 0 || protocol > 0xFF) {
                throw new IllegalArgumentException("protocol out of range: " + protocol);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `DONT-FRAGMENT` (TURN), which asks the relay to set the DF bit on the datagrams it sends to peers.
    record DontFragment() implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x001A;

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `MESSAGE-INTEGRITY-SHA256`, the HMAC-SHA256 of the message up to this attribute, possibly truncated.
    ///
    /// @param hmac the HMAC, `16..32` bytes in multiples of four, copied in and out
    record MessageIntegritySha256(byte[] hmac) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x001C;

        /// Creates the attribute.
        ///
        /// @param hmac the HMAC, copied
        /// @throws IllegalArgumentException if `hmac` is not `16..32` bytes in multiples of four
        public MessageIntegritySha256 {
            hmac = Objects.requireNonNull(hmac, "hmac cannot be null").clone();
            if (hmac.length < 16 || hmac.length > 32 || (hmac.length & 3) != 0) {
                throw new IllegalArgumentException("MESSAGE-INTEGRITY-SHA256 has 16 to 32 bytes, not " + hmac.length);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }

        /// {@return a copy of the HMAC}
        @Override
        public byte[] hmac() {
            return hmac.clone();
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof MessageIntegritySha256 that && MessageDigest.isEqual(hmac, that.hmac);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(hmac);
        }

        @Override
        public String toString() {
            return "MessageIntegritySha256[" + HexFormat.of().formatHex(hmac) + "]";
        }
    }

    /// `PASSWORD-ALGORITHM`, the algorithm a long-term credential request keys its integrity with.
    ///
    /// @param algorithm the 16-bit algorithm number; see [StunPasswordAlgorithm]
    record PasswordAlgorithm(int algorithm) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x001D;

        /// Creates the attribute.
        ///
        /// @param algorithm the algorithm number
        /// @throws IllegalArgumentException if `algorithm` does not fit in 16 bits
        public PasswordAlgorithm {
            if (algorithm < 0 || algorithm > 0xFFFF) {
                throw new IllegalArgumentException("algorithm out of range: " + algorithm);
            }
        }

        /// {@return the attribute naming `algorithm`}
        ///
        /// @param algorithm the algorithm
        public static PasswordAlgorithm of(StunPasswordAlgorithm algorithm) {
            return new PasswordAlgorithm(algorithm.code());
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `USERHASH`, the hashed username of a server that offers username anonymity.
    ///
    /// @param hash the 32-byte hash, copied in and out; see [StunKey#userHash(String,String)]
    record UserHash(byte[] hash) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x001E;

        /// Creates the attribute.
        ///
        /// @param hash the 32-byte hash, copied
        /// @throws IllegalArgumentException if `hash` is not 32 bytes long
        public UserHash {
            hash = Objects.requireNonNull(hash, "hash cannot be null").clone();
            if (hash.length != 32) {
                throw new IllegalArgumentException("USERHASH has 32 bytes, not " + hash.length);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }

        /// {@return a copy of the hash}
        @Override
        public byte[] hash() {
            return hash.clone();
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof UserHash that && Arrays.equals(hash, that.hash);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(hash);
        }

        @Override
        public String toString() {
            return "UserHash[" + HexFormat.of().formatHex(hash) + "]";
        }
    }

    /// `XOR-MAPPED-ADDRESS`, the reflexive transport address of the request a response answers.
    ///
    /// @param address the address, resolved
    record XorMappedAddress(InetSocketAddress address) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0020;

        /// Creates the attribute.
        ///
        /// @param address the address, resolved
        /// @throws IllegalArgumentException if `address` is unresolved
        public XorMappedAddress {
            requireResolved(address);
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `RESERVATION-TOKEN` (TURN), the token of a port reserved by `EVEN-PORT`.
    ///
    /// @param token the 64-bit token
    record ReservationToken(long token) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0022;

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `PRIORITY` (ICE), the priority the peer-reflexive candidate learned from a check would get.
    ///
    /// @param priority the unsigned 32-bit priority
    record Priority(long priority) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0024;

        /// Creates the attribute.
        ///
        /// @param priority the priority
        /// @throws IllegalArgumentException if `priority` is not an unsigned 32-bit value
        public Priority {
            if (priority < 0 || priority > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("priority out of range: " + priority);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `USE-CANDIDATE` (ICE), with which the controlling agent nominates the pair a check runs on.
    record UseCandidate() implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x0025;

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `ADDITIONAL-ADDRESS-FAMILY` (TURN), which asks for a second relayed address of another family.
    ///
    /// @param family the family, [StunAddressFamily#IPV6] in practice
    record AdditionalAddressFamily(StunAddressFamily family) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8000;

        /// Creates the attribute.
        ///
        /// @param family the family
        public AdditionalAddressFamily {
            Objects.requireNonNull(family, "family cannot be null");
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `ADDRESS-ERROR-CODE` (TURN), why the relayed address of one family could not be allocated.
    ///
    /// @param family the family that failed
    /// @param code   the error code, `300..699`
    /// @param reason the reason phrase
    record AddressErrorCode(StunAddressFamily family, int code, String reason) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8001;

        /// Creates the attribute.
        ///
        /// @param family the family
        /// @param code   the error code
        /// @param reason the reason phrase
        /// @throws IllegalArgumentException if `code` is outside `300..699`
        public AddressErrorCode {
            Objects.requireNonNull(family, "family cannot be null");
            Objects.requireNonNull(reason, "reason cannot be null");
            if (code < 300 || code > 699) {
                throw new IllegalArgumentException("error code out of range: " + code);
            }
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `PASSWORD-ALGORITHMS`, the password algorithms a server offers, in its order of preference.
    ///
    /// @param algorithms the unmodifiable 16-bit algorithm numbers, including ones Parley does not support
    record PasswordAlgorithms(List<Integer> algorithms) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8002;

        /// Creates the attribute.
        ///
        /// @param algorithms the algorithm numbers, copied
        public PasswordAlgorithms {
            algorithms = List.copyOf(algorithms);
        }

        @Override
        public int type() {
            return TYPE;
        }

        /// {@return the first algorithm of the list Parley supports, or an empty optional when it supports none}
        public Optional<StunPasswordAlgorithm> firstSupported() {
            return algorithms.stream()
                    .map(StunPasswordAlgorithm::ofCode)
                    .flatMap(Optional::stream)
                    .findFirst();
        }
    }

    /// `ALTERNATE-DOMAIN`, the TLS domain of the server named by `ALTERNATE-SERVER`.
    ///
    /// @param value the domain name
    record AlternateDomain(String value) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8003;

        /// Creates the attribute.
        ///
        /// @param value the domain name
        public AlternateDomain {
            Objects.requireNonNull(value, "value cannot be null");
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `ICMP` (TURN), an ICMP error the relay received from a peer, carried in a Data indication.
    ///
    /// @param icmpType  the ICMP type
    /// @param icmpCode  the ICMP code
    /// @param errorData the 32-bit error data, such as the next-hop MTU of a "fragmentation needed" error
    record Icmp(int icmpType, int icmpCode, long errorData) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8004;

        /// Creates the attribute.
        ///
        /// @param icmpType  the ICMP type
        /// @param icmpCode  the ICMP code
        /// @param errorData the error data
        /// @throws IllegalArgumentException if a field does not fit its wire width
        public Icmp {
            if (icmpType < 0 || icmpType > 0x7F || icmpCode < 0 || icmpCode > 0xFF
                    || errorData < 0 || errorData > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("ICMP fields out of range");
            }
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `SOFTWARE`, a description of the software that sent the message.
    ///
    /// @param value the description, UTF-8 on the wire, less than 763 bytes
    record Software(String value) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8022;

        /// Creates the attribute.
        ///
        /// @param value the description
        public Software {
            Objects.requireNonNull(value, "value cannot be null");
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `ALTERNATE-SERVER`, the server a 300 Try Alternate response redirects to.
    ///
    /// @param address the address, resolved
    record AlternateServer(InetSocketAddress address) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8023;

        /// Creates the attribute.
        ///
        /// @param address the address, resolved
        /// @throws IllegalArgumentException if `address` is unresolved
        public AlternateServer {
            requireResolved(address);
        }

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `FINGERPRINT`, the CRC-32 of the message up to this attribute XORed with `0x5354554E`.
    ///
    /// @param crc the unsigned 32-bit value as sent
    record Fingerprint(long crc) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8028;

        /// The value XORed into the CRC-32, the ASCII bytes of `STUN`.
        public static final long XOR = 0x5354554EL;

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `ICE-CONTROLLED` (ICE), sent by the controlled agent with its tie-breaker.
    ///
    /// @param tieBreaker the 64-bit tie-breaker, compared as unsigned
    record IceControlled(long tieBreaker) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x8029;

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// `ICE-CONTROLLING` (ICE), sent by the controlling agent with its tie-breaker.
    ///
    /// @param tieBreaker the 64-bit tie-breaker, compared as unsigned
    record IceControlling(long tieBreaker) implements StunAttribute {
        /// The attribute type.
        public static final int TYPE = 0x802A;

        @Override
        public int type() {
            return TYPE;
        }
    }

    /// Any attribute Parley does not model, or one whose value is malformed, kept as raw bytes.
    ///
    /// A decoded attribute is a read-only view of the decoded buffer, valid only as long as that buffer is.
    ///
    /// @param type  the 16-bit attribute type
    /// @param value the value, without padding
    record Unknown(int type, ByteBuffer value) implements StunAttribute {
        /// Creates the attribute.
        ///
        /// @param type  the attribute type
        /// @param value the value; a read-only view of its remaining bytes is kept
        /// @throws IllegalArgumentException if `type` does not fit in 16 bits or `value` is longer than 65535 bytes
        public Unknown {
            Objects.requireNonNull(value, "value cannot be null");
            if (type < 0 || type > 0xFFFF || value.remaining() > 0xFFFF) {
                throw new IllegalArgumentException("attribute out of range");
            }
            value = value.slice().asReadOnlyBuffer();
        }

        /// {@return a read-only view of the value, with its own position and limit}
        @Override
        public ByteBuffer value() {
            return value.duplicate();
        }

        @Override
        public String toString() {
            return "Unknown[type=0x" + Integer.toHexString(type) + ", " + value.remaining() + " bytes]";
        }
    }

    /// Checks that an address attribute holds a resolved address.
    private static void requireResolved(InetSocketAddress address) {
        Objects.requireNonNull(address, "address cannot be null");
        if (address.isUnresolved()) {
            throw new IllegalArgumentException("address must be resolved: " + address);
        }
    }
}
