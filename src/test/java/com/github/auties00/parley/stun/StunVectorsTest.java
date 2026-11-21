package com.github.auties00.parley.stun;

import com.github.auties00.parley.stun.StunAttribute.Fingerprint;
import com.github.auties00.parley.stun.StunAttribute.IceControlled;
import com.github.auties00.parley.stun.StunAttribute.MessageIntegrity;
import com.github.auties00.parley.stun.StunAttribute.MessageIntegritySha256;
import com.github.auties00.parley.stun.StunAttribute.Nonce;
import com.github.auties00.parley.stun.StunAttribute.Priority;
import com.github.auties00.parley.stun.StunAttribute.Realm;
import com.github.auties00.parley.stun.StunAttribute.Software;
import com.github.auties00.parley.stun.StunAttribute.UserHash;
import com.github.auties00.parley.stun.StunAttribute.Username;
import com.github.auties00.parley.stun.StunAttribute.XorMappedAddress;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// The test vectors of RFC 5769 and RFC 8489 appendix B, byte for byte.
@DisplayName("STUN test vectors")
class StunVectorsTest {
    // RFC 5769 section 2.1: padding uses spaces, so only decoding and verification are checked.
    private static final String SAMPLE_REQUEST = """
            000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74\
            002400046e0001ff80290008932ff9b151263b36000600096576746a3a6836765920202000080014\
            9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf""";

    // RFC 5769 section 2.2.
    private static final String SAMPLE_IPV4_RESPONSE = """
            0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f722000200008\
            0001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96""";

    // RFC 5769 section 2.3.
    private static final String SAMPLE_IPV6_RESPONSE = """
            010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f722000200014\
            0002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275\
            bfe3ed4180280004c8fb0b4c""";

    // RFC 5769 section 2.4: nul padding, so the encoder reproduces it exactly.
    private static final String SAMPLE_LONG_TERM_REQUEST = """
            000100602112a44278ad3433c6ad72c029da412e00060012e3839ee38388e383aae38383e382afe3            82b900000015001c662f2f3439396b39353464364f4c33346f4c3946535476793634734100140            00b6578616d706c652e6f726700000800 14f67024656dd64a3e02b8e0712e85c9a28ca89666""";

    // RFC 8489 appendix B.1, every attribute before MESSAGE-INTEGRITY-SHA256. The header length 0x9c also counts
    // 20 bytes of PASSWORD-ALGORITHM and PASSWORD-ALGORITHMS that the printed message omits (a known erratum), and
    // the HMAC was computed with that length.
    private static final String SAMPLE_SHA256_PREFIX = """
            0001009c2112a44278ad3433c6ad72c029da412e001e00204a3cf38fef6992bda952c6780417da0f            24819415569e60b205c46e41407f1704001500296f624d61744a6f733241414143662f2f3439396b            39353464364f4c33346f4c39465354767936347341000000 0014000b6578616d706c652e6f726700""";

    // RFC 8489 appendix B.1, the MESSAGE-INTEGRITY-SHA256 attribute.
    private static final String SAMPLE_SHA256_INTEGRITY = """
            001c0020e4686c8f0edeb59013e07090010a93efccbccc544c0a45d9f830aa6d6f735a01""";

    /// The 2.4 username, six katakana characters.
    private static final String MATRIX_USERNAME = "\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9";

    private static ByteBuffer hex(String text) {
        return ByteBuffer.wrap(HexFormat.of().parseHex(text.replaceAll("\\s", "")));
    }

    @Test
    @DisplayName("decodes and verifies the RFC 5769 sample request")
    void sampleRequest() throws StunFormatException {
        var message = StunMessage.decode(hex(SAMPLE_REQUEST));
        assertEquals(StunClass.REQUEST, message.messageClass());
        assertEquals(StunMethod.BINDING, message.method());
        assertEquals("STUN test client", message.attribute(Software.class).orElseThrow().value());
        assertEquals(0x6e0001ffL, message.attribute(Priority.class).orElseThrow().priority());
        assertEquals(0x932ff9b151263b36L, message.attribute(IceControlled.class).orElseThrow().tieBreaker());
        assertEquals("evtj:h6vY", message.attribute(Username.class).orElseThrow().value());
        assertTrue(message.has(Fingerprint.class));
        assertTrue(message.verifyIntegrity(StunKey.shortTerm("VOkJxbRl1RmTxUk/WvJxBt")));
        assertFalse(message.verifyIntegrity(StunKey.shortTerm("wrong")));
    }

    @Test
    @DisplayName("decodes the RFC 5769 IPv4 response with its XOR-MAPPED-ADDRESS")
    void sampleIpv4Response() throws Exception {
        var message = StunMessage.decode(hex(SAMPLE_IPV4_RESPONSE));
        assertEquals(StunClass.SUCCESS_RESPONSE, message.messageClass());
        assertEquals("test vector", message.attribute(Software.class).orElseThrow().value());
        assertEquals(new InetSocketAddress(InetAddress.ofLiteral("192.0.2.1"), 32853),
                message.attribute(XorMappedAddress.class).orElseThrow().address());
        assertTrue(message.verifyIntegrity(StunKey.shortTerm("VOkJxbRl1RmTxUk/WvJxBt")));
    }

    @Test
    @DisplayName("decodes the RFC 5769 IPv6 response with its XOR-MAPPED-ADDRESS")
    void sampleIpv6Response() throws Exception {
        var message = StunMessage.decode(hex(SAMPLE_IPV6_RESPONSE));
        assertEquals(new InetSocketAddress(InetAddress.ofLiteral("2001:db8:1234:5678:11:2233:4455:6677"), 32853),
                message.attribute(XorMappedAddress.class).orElseThrow().address());
        assertTrue(message.verifyIntegrity(StunKey.shortTerm("VOkJxbRl1RmTxUk/WvJxBt")));
    }

    @Test
    @DisplayName("re-encodes the IPv4 response so it verifies and keeps its attributes")
    void reencodesResponse() throws Exception {
        var key = StunKey.shortTerm("VOkJxbRl1RmTxUk/WvJxBt");
        var original = StunMessage.decode(hex(SAMPLE_IPV4_RESPONSE));
        var encoded = original.encode(key, StunIntegrity.HMAC_SHA1, true);
        var decoded = StunMessage.decode(encoded);
        // The vector pads with spaces and the encoder with zeros, so only the attributes before the trailer match.
        assertEquals(original.attributes().subList(0, 2), decoded.attributes().subList(0, 2));
        assertTrue(decoded.verifyIntegrity(key));
    }

    @Test
    @DisplayName("reproduces the RFC 5769 long-term request byte for byte")
    void sampleLongTermRequest() throws StunFormatException {
        var expected = hex(SAMPLE_LONG_TERM_REQUEST);
        var message = StunMessage.decode(expected.duplicate());
        assertEquals(MATRIX_USERNAME, message.attribute(Username.class).orElseThrow().value());
        assertEquals("f//499k954d6OL34oL9FSTvy64sA", message.attribute(Nonce.class).orElseThrow().value());
        assertEquals("example.org", message.attribute(Realm.class).orElseThrow().value());
        // "TheMatrIX" is the password after SASLprep, which RFC 5769 used before OpaqueString replaced it.
        var key = StunKey.longTerm(MATRIX_USERNAME, "example.org", "TheMatrIX", StunPasswordAlgorithm.MD5);
        assertTrue(message.verifyIntegrity(key));
        var rebuilt = StunMessage.of(StunClass.REQUEST, StunMethod.BINDING, message.transactionId(), List.of(
                new Username(MATRIX_USERNAME), new Nonce("f//499k954d6OL34oL9FSTvy64sA"), new Realm("example.org")));
        assertEquals(expected, rebuilt.encode(key, StunIntegrity.HMAC_SHA1, false));
    }

    @Test
    @DisplayName("matches the RFC 8489 MESSAGE-INTEGRITY-SHA256 request with USERHASH")
    void sampleSha256Request() throws Exception {
        var prefix = hex(SAMPLE_SHA256_PREFIX);
        var integrity = hex(SAMPLE_SHA256_INTEGRITY);
        var whole = ByteBuffer.allocate(prefix.remaining() + integrity.remaining()).put(prefix.duplicate()).put(integrity.duplicate()).flip();
        whole.putShort(2, (short) (whole.remaining() - StunMessage.HEADER_LENGTH));
        var message = StunMessage.decode(whole);
        assertArrayEquals(StunKey.userHash(MATRIX_USERNAME, "example.org"),
                message.attribute(UserHash.class).orElseThrow().hash());
        assertEquals(Optional.of(StunIntegrity.HMAC_SHA256), message.integrity());
        assertEquals(Optional.of(0x000002), message.attribute(Nonce.class).orElseThrow().securityFeatures());
        assertTrue(message.has(MessageIntegritySha256.class));
        assertFalse(message.has(MessageIntegrity.class));
        var key = StunKey.longTerm(MATRIX_USERNAME, "example.org", "TheMatrIX", StunPasswordAlgorithm.SHA_256);
        var mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(key.key(), "HmacSHA256"));
        var expected = new byte[32];
        integrity.get(4, expected);
        assertArrayEquals(expected, mac.doFinal(HexFormat.of().parseHex(SAMPLE_SHA256_PREFIX.replaceAll("\s", ""))));
    }

    @Test
    @DisplayName("signs and verifies MESSAGE-INTEGRITY-SHA256 with a SHA-256 long-term key")
    void sha256RoundTrip() throws Exception {
        var key = StunKey.longTerm(MATRIX_USERNAME, "example.org", "TheMatrIX", StunPasswordAlgorithm.SHA_256);
        var request = StunMessage.request(StunMethod.ALLOCATE, List.of(new UserHash(StunKey.userHash(MATRIX_USERNAME, "example.org")),
                new Nonce("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"), new Realm("example.org")));
        var decoded = StunMessage.decode(request.encode(key, StunIntegrity.HMAC_SHA256, true));
        assertTrue(decoded.verifyIntegrity(key));
        assertFalse(decoded.verifyIntegrity(StunKey.longTerm(MATRIX_USERNAME, "example.org", "TheMatrIX", StunPasswordAlgorithm.MD5)));
    }

    @Test
    @DisplayName("derives the RFC 8489 section 9.2.2 example key")
    void longTermKeyExample() {
        var key = StunKey.longTerm("user", "realm", "pass", StunPasswordAlgorithm.MD5);
        assertArrayEquals(HexFormat.of().parseHex("8493fbc53ba582fb4c044c456bdc40eb"), key.key());
    }

    @Test
    @DisplayName("rejects a sample whose FINGERPRINT was damaged")
    void damagedFingerprint() {
        var bytes = hex(SAMPLE_IPV4_RESPONSE);
        bytes.put(bytes.limit() - 1, (byte) (bytes.get(bytes.limit() - 1) ^ 1));
        assertThrows(StunFormatException.class, () -> StunMessage.decode(bytes));
    }

    @Test
    @DisplayName("fails integrity when a byte covered by it changes")
    void damagedIntegrity() throws StunFormatException {
        var bytes = hex(SAMPLE_LONG_TERM_REQUEST);
        bytes.put(30, (byte) (bytes.get(30) ^ 1));
        var message = StunMessage.decode(bytes);
        var key = StunKey.longTerm(MATRIX_USERNAME, "example.org", "TheMatrIX", StunPasswordAlgorithm.MD5);
        assertFalse(message.verifyIntegrity(key));
    }
}
