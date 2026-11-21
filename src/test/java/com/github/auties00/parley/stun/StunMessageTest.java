package com.github.auties00.parley.stun;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the STUN codec: every attribute round-trips, integrity and fingerprint placement, the decoding rules of
/// RFC 8489, and fuzzing with random and mutated packets (seeded, so failures reproduce).
@DisplayName("StunMessage")
class StunMessageTest {
    private static final InetSocketAddress V4 = new InetSocketAddress(InetAddress.ofLiteral("192.0.2.1"), 32853);
    private static final InetSocketAddress V6 = new InetSocketAddress(InetAddress.ofLiteral("2001:db8::77"), 4000);

    /// One instance of every attribute record.
    static List<StunAttribute> everyAttribute() {
        return List.of(
                new StunAttribute.MappedAddress(V4),
                new StunAttribute.Username("user:name"),
                new StunAttribute.ErrorCode(438, "Stale Nonce"),
                new StunAttribute.UnknownAttributes(List.of(0x7777, 0x0001)),
                new StunAttribute.ChannelNumber(0x4001),
                new StunAttribute.Lifetime(Duration.ofSeconds(600)),
                new StunAttribute.XorPeerAddress(V6),
                new StunAttribute.Data(ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5})),
                new StunAttribute.Realm("realm.example"),
                new StunAttribute.Nonce("obMatJos2gAAAnonce"),
                new StunAttribute.XorRelayedAddress(V4),
                new StunAttribute.RequestedAddressFamily(StunAddressFamily.IPV6),
                new StunAttribute.EvenPort(true),
                new StunAttribute.RequestedTransport(17),
                new StunAttribute.DontFragment(),
                new StunAttribute.PasswordAlgorithm(2),
                new StunAttribute.UserHash(new byte[32]),
                new StunAttribute.XorMappedAddress(V6),
                new StunAttribute.ReservationToken(0x0102030405060708L),
                new StunAttribute.Priority(0x6e0001ffL),
                new StunAttribute.UseCandidate(),
                new StunAttribute.AdditionalAddressFamily(StunAddressFamily.IPV6),
                new StunAttribute.AddressErrorCode(StunAddressFamily.IPV6, 440, "Address Family not Supported"),
                new StunAttribute.PasswordAlgorithms(List.of(2, 1, 0x7000)),
                new StunAttribute.AlternateDomain("alt.example"),
                new StunAttribute.Icmp(3, 4, 1400),
                new StunAttribute.Software("parley"),
                new StunAttribute.AlternateServer(V6),
                new StunAttribute.IceControlled(-1L),
                new StunAttribute.IceControlling(42L),
                new StunAttribute.Unknown(0xC001, ByteBuffer.wrap(new byte[]{9, 8, 7})));
    }

    @Test
    @DisplayName("round-trips every attribute type with integrity and fingerprint")
    void roundTripsEveryAttribute() throws StunFormatException {
        var key = StunKey.shortTerm("password");
        var message = StunMessage.request(StunMethod.ALLOCATE, everyAttribute());
        var decoded = StunMessage.decode(message.encode(key, StunIntegrity.HMAC_SHA1, true));
        assertEquals(StunClass.REQUEST, decoded.messageClass());
        assertEquals(StunMethod.ALLOCATE, decoded.method());
        assertEquals(message.transactionId(), decoded.transactionId());
        var withoutTrailer = decoded.attributes().stream()
                .filter(attribute -> !(attribute instanceof StunAttribute.MessageIntegrity) && !(attribute instanceof StunAttribute.Fingerprint))
                .toList();
        assertEquals(everyAttribute(), withoutTrailer);
        assertTrue(decoded.verifyIntegrity(key));
        assertTrue(decoded.attributes().getLast() instanceof StunAttribute.Fingerprint);
    }

    @ParameterizedTest
    @ValueSource(strings = {"REQUEST", "INDICATION", "SUCCESS_RESPONSE", "ERROR_RESPONSE"})
    @DisplayName("encodes the class and method bits of every combination")
    void classAndMethodBits(String className) throws StunFormatException {
        for (var method : StunMethod.values()) {
            var messageClass = StunClass.valueOf(className);
            var message = StunMessage.of(messageClass, method, StunTransactionId.random(), List.of());
            var decoded = StunMessage.decode(message.encode(false));
            assertEquals(messageClass, decoded.messageClass());
            assertEquals(method, decoded.method());
        }
    }

    @Test
    @DisplayName("writes the type 0x0111 for a Binding error response, as RFC 8489 numbers it")
    void bindingErrorType() {
        var encoded = StunMessage.of(StunClass.ERROR_RESPONSE, StunMethod.BINDING, StunTransactionId.random(), List.of()).encode(false);
        assertEquals(0x0111, encoded.getShort(0) & 0xFFFF);
        var allocateSuccess = StunMessage.of(StunClass.SUCCESS_RESPONSE, StunMethod.ALLOCATE, StunTransactionId.random(), List.of()).encode(false);
        assertEquals(0x0103, allocateSuccess.getShort(0) & 0xFFFF);
    }

    @Test
    @DisplayName("ignores attributes after MESSAGE-INTEGRITY except MESSAGE-INTEGRITY-SHA256 and FINGERPRINT")
    void attributesAfterIntegrity() throws StunFormatException {
        var key = StunKey.shortTerm("password");
        var encoded = StunMessage.request(StunMethod.BINDING, List.of(new StunAttribute.Username("a:b"))).encode(key, StunIntegrity.HMAC_SHA1, false);
        var extended = ByteBuffer.allocate(encoded.remaining() + 12).put(encoded);
        extended.putShort((short) StunAttribute.Software.TYPE).putShort((short) 8).put("trailing".getBytes());
        extended.putShort(2, (short) (extended.position() - StunMessage.HEADER_LENGTH)).flip();
        var decoded = StunMessage.decode(extended);
        assertFalse(decoded.has(StunAttribute.Software.class));
        assertTrue(decoded.verifyIntegrity(key));
    }

    @Test
    @DisplayName("lists unknown comprehension-required attributes and ignores optional ones")
    void unknownAttributes() throws StunFormatException {
        var message = StunMessage.request(StunMethod.BINDING, List.of(
                new StunAttribute.Unknown(0x0777, ByteBuffer.allocate(4)),
                new StunAttribute.Unknown(0x8777, ByteBuffer.allocate(4))));
        var decoded = StunMessage.decode(message.encode(true));
        assertEquals(List.of(0x0777), decoded.unknownComprehensionRequired());
    }

    @Test
    @DisplayName("keeps a malformed comprehension-optional attribute as Unknown and rejects a required one")
    void malformedAttributes() throws StunFormatException {
        var optional = StunMessage.request(StunMethod.BINDING, List.of(new StunAttribute.Unknown(StunAttribute.IceControlled.TYPE, ByteBuffer.allocate(3))));
        var decoded = StunMessage.decode(optional.encode(false));
        assertTrue(decoded.attributes().getFirst() instanceof StunAttribute.Unknown);
        var required = StunMessage.request(StunMethod.BINDING, List.of(new StunAttribute.Unknown(StunAttribute.Priority.TYPE, ByteBuffer.allocate(3))));
        assertThrows(StunFormatException.class, () -> StunMessage.decode(required.encode(false)));
    }

    @Test
    @DisplayName("detects STUN by first byte, cookie and length, and reports the frame length")
    void detection() {
        var encoded = StunMessage.request(StunMethod.BINDING, List.of()).encode(true);
        assertTrue(StunMessage.isStun(encoded));
        assertEquals(encoded.remaining(), StunMessage.frameLength(encoded));
        var rtp = ByteBuffer.wrap(new byte[]{(byte) 0x80, 0, 0, 1, 0x21, 0x12, (byte) 0xA4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        assertFalse(StunMessage.isStun(rtp));
        var truncated = encoded.duplicate().limit(encoded.limit() - 4);
        assertFalse(StunMessage.isStun(truncated));
        assertEquals(-1, StunMessage.frameLength(ByteBuffer.allocate(3)));
    }

    @Test
    @DisplayName("decodes at the buffer's position without moving it and copies into an owned message")
    void zeroCopyDecode() throws StunFormatException {
        var payload = ByteBuffer.wrap(new byte[]{10, 20, 30});
        var message = StunMessage.indication(StunMethod.DATA, List.of(new StunAttribute.XorPeerAddress(V4), new StunAttribute.Data(payload)));
        var encoded = message.encode(false);
        var buffer = ByteBuffer.allocate(encoded.remaining() + 7);
        buffer.position(7).put(encoded).position(7);
        var decoded = StunMessage.decode(buffer);
        assertEquals(7, buffer.position());
        var copy = decoded.copy();
        buffer.put(buffer.limit() - 4, (byte) 99);
        assertEquals(ByteBuffer.wrap(new byte[]{10, 20, 30}), copy.attribute(StunAttribute.Data.class).orElseThrow().value());
        assertNotEquals(ByteBuffer.wrap(new byte[]{10, 20, 30}), decoded.attribute(StunAttribute.Data.class).orElseThrow().value());
    }

    @Test
    @DisplayName("builds responses with the request's transaction id")
    void responses() {
        var request = StunMessage.request(StunMethod.BINDING, List.of());
        var error = request.errorResponse(487, "Role Conflict", List.of());
        assertEquals(request.transactionId(), error.transactionId());
        assertEquals(StunClass.ERROR_RESPONSE, error.messageClass());
        assertEquals(487, error.errorCode().orElseThrow().code());
        assertEquals(StunClass.SUCCESS_RESPONSE, request.successResponse(List.of()).messageClass());
    }

    @Test
    @DisplayName("refuses invalid attribute values at construction")
    void invalidAttributes() {
        assertThrows(IllegalArgumentException.class, () -> new StunAttribute.ErrorCode(200, "x"));
        assertThrows(IllegalArgumentException.class, () -> new StunAttribute.MessageIntegrity(new byte[19]));
        assertThrows(IllegalArgumentException.class, () -> new StunAttribute.MessageIntegritySha256(new byte[15]));
        assertThrows(IllegalArgumentException.class, () -> new StunAttribute.XorMappedAddress(InetSocketAddress.createUnresolved("a", 1)));
        assertThrows(IllegalArgumentException.class, () -> new StunAttribute.Priority(-1));
        assertThrows(IllegalArgumentException.class, () -> new StunAttribute.Lifetime(Duration.ofSeconds(-1)));
    }

    @Test
    @DisplayName("reads the security feature bits of the nonce cookie")
    void nonceCookie() {
        assertTrue(new StunAttribute.Nonce("obMatJos2gAAAxyz").passwordAlgorithmsFeature());
        assertFalse(new StunAttribute.Nonce("obMatJos2gAAAxyz").usernameAnonymityFeature());
        assertTrue(new StunAttribute.Nonce("obMatJos2QAAAxyz").usernameAnonymityFeature());
        assertEquals(Optional.empty(), new StunAttribute.Nonce("plain").securityFeatures());
    }

    @Test
    @DisplayName("maps non-ASCII spaces and normalizes to NFC in OpaqueString")
    void opaqueString() {
        assertEquals("a b", StunKey.opaqueString("a\u00A0b"));
        assertEquals("\u00E9", StunKey.opaqueString("e\u0301"));
    }

    @Nested
    @DisplayName("under fuzzing")
    class Fuzzing {
        @Test
        @DisplayName("throws only StunFormatException for random bytes behind a valid header")
        void randomBodies() {
            var random = new Random(0x5EED);
            for (var i = 0; i < 40_000; i++) {
                var length = random.nextInt(64) * 4;
                var buffer = ByteBuffer.allocate(20 + length);
                buffer.putShort((short) (random.nextInt(0x4000))).putShort((short) length).putInt(StunMessage.MAGIC_COOKIE);
                var rest = new byte[12 + length];
                random.nextBytes(rest);
                buffer.put(rest).flip();
                decodeQuietly(buffer);
            }
        }

        @Test
        @DisplayName("throws only StunFormatException for every single-byte mutation of a valid message")
        void mutations() {
            var random = new Random(42);
            var original = StunMessage.request(StunMethod.ALLOCATE, everyAttribute()).encode(StunKey.shortTerm("k"), StunIntegrity.HMAC_SHA256, true);
            for (var position = 0; position < original.remaining(); position++) {
                for (var trial = 0; trial < 4; trial++) {
                    var copy = ByteBuffer.allocate(original.remaining()).put(original.duplicate()).flip();
                    copy.put(position, (byte) random.nextInt(256));
                    decodeQuietly(copy);
                }
            }
        }

        @Test
        @DisplayName("round-trips random attribute subsets")
        void randomRoundTrips() throws StunFormatException {
            var random = new Random(7);
            var all = everyAttribute();
            for (var i = 0; i < 500; i++) {
                var chosen = new ArrayList<StunAttribute>();
                for (var attribute : all) {
                    if (random.nextBoolean()) {
                        chosen.add(attribute);
                    }
                }
                var message = StunMessage.request(StunMethod.BINDING, chosen);
                var decoded = StunMessage.decode(message.encode(random.nextBoolean()));
                assertEquals(chosen, decoded.attributes().stream().filter(attribute -> !(attribute instanceof StunAttribute.Fingerprint)).toList());
            }
        }

        private static void decodeQuietly(ByteBuffer buffer) {
            try {
                var message = StunMessage.decode(buffer);
                message.verifyIntegrity(StunKey.shortTerm("k"));
                message.unknownComprehensionRequired();
                message.copy();
            } catch (StunFormatException expected) {
                // Malformed input must fail this way and no other.
            }
        }
    }
}
