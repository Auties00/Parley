package com.github.auties00.parley.dtls;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/// Checks the cryptographic building blocks against published test vectors: the TLS 1.3 key schedule of RFC 8448
/// (with the `tls13 ` prefix, which shares every step with the `dtls13` schedule but the label), the TLS 1.2 PRF,
/// X25519 from RFC 7748 and the ChaCha20 block function of RFC 8439 that masks DTLS 1.3 record numbers.
@DisplayName("cryptographic test vectors")
class CryptoVectorsTest {
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] hex(String value) {
        return HEX.parseHex(value.replace(" ", ""));
    }

    @Test
    @DisplayName("derives the RFC 8448 simple 1-RTT key schedule")
    void rfc8448KeySchedule() {
        var hash = HashAlgorithm.SHA256;
        var early = Hkdf.extract(hash, new byte[0], new byte[0]);
        assertArrayEquals(hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"), early);
        var emptyHash = hash.hash(new byte[0]);
        var derived = Hkdf.expandLabel(hash, "tls13 ", early, "derived", emptyHash, 32);
        assertArrayEquals(hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"), derived);
        var handshake = Hkdf.extract(hash, derived,
                hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"));
        assertArrayEquals(hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), handshake);
        var transcript = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        var clientTraffic = Hkdf.expandLabel(hash, "tls13 ", handshake, "c hs traffic", transcript, 32);
        assertArrayEquals(hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), clientTraffic);
        var serverTraffic = Hkdf.expandLabel(hash, "tls13 ", handshake, "s hs traffic", transcript, 32);
        assertArrayEquals(hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), serverTraffic);
        var masterDerived = Hkdf.expandLabel(hash, "tls13 ", handshake, "derived", emptyHash, 32);
        assertArrayEquals(hex("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"), masterDerived);
        var master = Hkdf.extract(hash, masterDerived, new byte[0]);
        assertArrayEquals(hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), master);
        assertArrayEquals(hex("3fce516009c21727d0f2e4e86ee403bc"),
                Hkdf.expandLabel(hash, "tls13 ", serverTraffic, "key", new byte[0], 16));
        assertArrayEquals(hex("5d313eb2671276ee13000b30"),
                Hkdf.expandLabel(hash, "tls13 ", serverTraffic, "iv", new byte[0], 12));
    }

    @Test
    @DisplayName("prefixes DTLS 1.3 labels with dtls13 and no space")
    void dtls13Prefix() {
        var secret = new byte[32];
        var dtls = Hkdf.expandLabel(HashAlgorithm.SHA256, secret, "key", new byte[0], 16);
        var explicit = Hkdf.expandLabel(HashAlgorithm.SHA256, "dtls13", secret, "key", new byte[0], 16);
        assertArrayEquals(explicit, dtls);
        var info = new TlsWriter().u16(16).vector8("dtls13key".getBytes(StandardCharsets.US_ASCII)).vector8(new byte[0])
                .toByteArray();
        assertArrayEquals(Hkdf.expand(HashAlgorithm.SHA256, secret, info, 16), dtls);
    }

    @Test
    @DisplayName("computes the TLS 1.2 PRF test vector with SHA-256")
    void tls12Prf() {
        var output = TlsPrf.compute(HashAlgorithm.SHA256, hex("9bbe436ba940f017b17652849a71db35"), "test label",
                hex("a0ba9f936cda311827a6f796ffd5198c"), 100);
        assertArrayEquals(hex("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4"
                + "e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110ff"
                + "f70187347b66"), output);
    }

    @Test
    @DisplayName("agrees on the RFC 7748 X25519 shared secret and round-trips the key encoding")
    void x25519() throws Exception {
        var group = NamedGroup.X25519;
        var bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        var alicePrivateBytes = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var alicePrivate = KeyFactory.getInstance("XDH")
                .generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, alicePrivateBytes));
        var decoded = group.decode(bobPublic);
        assertArrayEquals(bobPublic, group.encode(decoded));
        var shared = group.agree(new KeyPair(decoded, alicePrivate), decoded);
        assertArrayEquals(hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"), shared);
    }

    @Test
    @DisplayName("rejects malformed key shares")
    void malformedShares() {
        assertThrows(DtlsException.class, () -> NamedGroup.X25519.decode(new byte[31]));
        assertThrows(DtlsException.class, () -> NamedGroup.SECP256R1.decode(new byte[65]));
        assertThrows(DtlsException.class, () -> NamedGroup.SECP384R1.decode(new byte[]{4, 1, 2}));
        var notOnCurve = new byte[65];
        notOnCurve[0] = 4;
        notOnCurve[64] = 1;
        assertThrows(DtlsException.class, () -> NamedGroup.SECP256R1.decode(notOnCurve));
    }

    @Test
    @DisplayName("round-trips every group's key encoding and agrees on the same secret")
    void everyGroup() throws Exception {
        for (var group : NamedGroup.values()) {
            var first = group.generate();
            var second = group.generate();
            var firstPublic = group.decode(group.encode(first.getPublic()));
            var secondPublic = group.decode(group.encode(second.getPublic()));
            assertArrayEquals(group.agree(first, secondPublic), group.agree(second, firstPublic), group.name());
        }
    }

    @Test
    @DisplayName("masks ChaCha20 record numbers with the RFC 8439 block function")
    void chachaMask() throws Exception {
        var key = new byte[32];
        for (var index = 0; index < key.length; index++) {
            key[index] = (byte) index;
        }
        var cipher = new Dtls13RecordCipher(Aead.CHACHA20_POLY1305, new byte[32], new byte[12], key);
        var sample = new byte[16];
        sample[0] = 1;
        System.arraycopy(hex("000000090000004a00000000"), 0, sample, 4, 12);
        assertArrayEquals(hex("10f1e7e4d13b5915500fdd1fa32071c4"), cipher.mask(sample, 0));
    }

    @Test
    @DisplayName("masks AES record numbers with AES-ECB of the sample")
    void aesMask() throws Exception {
        var key = hex("000102030405060708090a0b0c0d0e0f");
        var cipher = new Dtls13RecordCipher(Aead.AES_128_GCM, new byte[16], new byte[12], key);
        var sample = hex("00112233445566778899aabbccddeeff");
        assertArrayEquals(hex("69c4e0d86a7b0430d8cdb78070b4c55a"), cipher.mask(sample, 0));
    }

    @Test
    @DisplayName("round-trips DTLS 1.2 records of every AEAD and rejects a changed header")
    void dtls12Records() throws Exception {
        for (var aead : Aead.values()) {
            var key = new byte[aead.keyLength()];
            var iv = new byte[Dtls12RecordCipher.fixedIvLength(aead)];
            key[0] = 1;
            iv[0] = 2;
            var sealer = new Dtls12RecordCipher(aead, key, iv);
            var opener = new Dtls12RecordCipher(aead, key, iv);
            var plaintext = "hello".getBytes(StandardCharsets.US_ASCII);
            var sealed = sealer.seal(1L << 48 | 5, 23, 0xFEFD, plaintext);
            assertEquals(plaintext.length + sealer.overhead(), sealed.length);
            assertArrayEquals(plaintext, opener.open(1L << 48 | 5, 23, 0xFEFD, sealed, 0, sealed.length));
            assertThrows(DtlsException.class, () -> opener.open(1L << 48 | 6, 23, 0xFEFD, sealed, 0, sealed.length));
            assertThrows(DtlsException.class, () -> opener.open(1L << 48 | 5, 22, 0xFEFD, sealed, 0, sealed.length));
        }
    }

    @Test
    @DisplayName("derives the DTLS 1.3 record keys of a secret")
    void dtls13RecordKeys() throws Exception {
        var secret = new BigInteger("1234567890").toByteArray();
        var sealer = Dtls13RecordCipher.fromSecret(CipherSuite.TLS_AES_256_GCM_SHA384, secret);
        var opener = Dtls13RecordCipher.fromSecret(CipherSuite.TLS_AES_256_GCM_SHA384, secret);
        var aad = new byte[]{0x2E, 0, 7, 0, 22};
        var sealed = sealer.seal(7, aad, new byte[]{1, 2, 3, 4, 5, 23});
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5, 23}, opener.open(7, aad, sealed, 0, sealed.length));
        assertThrows(DtlsException.class, () -> opener.open(8, aad, sealed, 0, sealed.length));
    }
}
