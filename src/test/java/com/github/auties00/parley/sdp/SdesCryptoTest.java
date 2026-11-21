package com.github.auties00.parley.sdp;

import com.github.auties00.srtp.SrtpCryptoSuite;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Typed `a=crypto` attributes: the RFC 4568 examples, the suite-derived key lengths, `tryParse` for negotiation, and a
/// fuzz of the parser that only ever yields an attribute or an [IllegalArgumentException].
@DisplayName("SdesCrypto")
class SdesCryptoTest {
    /// RFC 4568 section 4, the example of the attribute syntax.
    private static final String RFC_EXAMPLE =
            "1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32";

    @Test
    @DisplayName("parses the RFC 4568 example into a typed suite, key and salt")
    void rfcExample() {
        var crypto = SdesCrypto.parse(RFC_EXAMPLE);
        assertEquals(1, crypto.tag());
        assertEquals(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, crypto.suite());
        var material = Base64.getDecoder().decode("PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR");
        assertArrayEquals(java.util.Arrays.copyOf(material, 16), crypto.masterKey());
        assertArrayEquals(java.util.Arrays.copyOfRange(material, 16, 30), crypto.masterSalt());
        assertEquals(List.of(), crypto.sessionParameters());
        assertEquals("1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR", crypto.value());
    }

    @Test
    @DisplayName("keeps session parameters verbatim")
    void sessionParameters() {
        var crypto = SdesCrypto.parse("2 AES_CM_128_HMAC_SHA1_32 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR "
                + "UNENCRYPTED_SRTCP KDR=1");
        assertEquals(List.of("UNENCRYPTED_SRTCP", "KDR=1"), crypto.sessionParameters());
        assertEquals(crypto, SdesCrypto.parse(crypto.value()));
    }

    @ParameterizedTest
    @EnumSource(SrtpCryptoSuite.class)
    @DisplayName("generates key material of the suite's lengths that survives formatting and parsing")
    void generate(SrtpCryptoSuite suite) {
        var crypto = SdesCrypto.generate(7, suite);
        assertEquals(suite.masterKeyLength(), crypto.masterKey().length);
        assertEquals(suite.masterSaltLength(), crypto.masterSalt().length);
        var parsed = SdesCrypto.parse(crypto.value());
        assertEquals(crypto, parsed);
        assertFalse(crypto.toString().contains(Base64.getEncoder().encodeToString(crypto.keySalt())));
    }

    @Test
    @DisplayName("rejects unknown suites in parse and skips them in tryParse")
    void unknownSuite() {
        var line = "1 AES_192_CM_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR";
        var exception = assertThrows(IllegalArgumentException.class, () -> SdesCrypto.parse(line));
        assertTrue(exception.getMessage().contains("AES_192_CM_HMAC_SHA1_80"));
        assertEquals(Optional.empty(), SdesCrypto.tryParse(line));
        assertTrue(SdesCrypto.tryParse(RFC_EXAMPLE).isPresent());
    }

    @Test
    @DisplayName("rejects key material of the wrong length, a negative tag and a broken key")
    void invalid() {
        assertThrows(IllegalArgumentException.class,
                () -> new SdesCrypto(1, SrtpCryptoSuite.AEAD_AES_128_GCM, new byte[30]));
        assertThrows(IllegalArgumentException.class,
                () -> new SdesCrypto(-1, SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, new byte[30]));
        assertThrows(IllegalArgumentException.class,
                () -> SdesCrypto.parse("1 AES_CM_128_HMAC_SHA1_80 inline:!!!"));
        assertThrows(IllegalArgumentException.class, () -> SdesCrypto.parse("x AES_CM_128_HMAC_SHA1_80 inline:AA=="));
        assertThrows(IllegalArgumentException.class, () -> SdesCrypto.parse("1 AES_CM_128_HMAC_SHA1_80"));
    }

    @Test
    @DisplayName("never throws anything but IllegalArgumentException on mutated input")
    void fuzz() {
        var random = new Random(4568);
        var alphabet = "0123456789 _|:^inlAESCMHSG=+/aZ".toCharArray();
        for (var round = 0; round < 20_000; round++) {
            var chars = RFC_EXAMPLE.toCharArray();
            var mutations = 1 + random.nextInt(4);
            for (var mutation = 0; mutation < mutations; mutation++) {
                chars[random.nextInt(chars.length)] = alphabet[random.nextInt(alphabet.length)];
            }
            var text = new String(chars, 0, random.nextInt(chars.length + 1));
            try {
                var parsed = SdesCrypto.parse(text);
                assertEquals(parsed, SdesCrypto.parse(parsed.value()));
            } catch (IllegalArgumentException expected) {
                assertEquals(Optional.empty(), SdesCrypto.tryParse(text));
            }
        }
    }
}
