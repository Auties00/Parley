package com.github.auties00.parley.dtls;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the value types of the package: fingerprints, certificates, `a=setup`, `a=tls-id`, the restart rule of
/// [DtlsParameters], the configuration and the profile and version tables.
@DisplayName("DTLS value types")
class DtlsValuesTest {
    private static final DtlsCertificate CERTIFICATE = DtlsCertificate.generateEcdsa();

    @Nested
    @DisplayName("DtlsFingerprint")
    class Fingerprints {
        @Test
        @DisplayName("round-trips the a=fingerprint form, case-insensitively")
        void roundTrip() {
            var fingerprint = CERTIFICATE.fingerprints().getFirst();
            var sdp = fingerprint.toSdp();
            assertTrue(sdp.startsWith("sha-256 "));
            assertEquals(fingerprint, DtlsFingerprint.parse(sdp));
            assertEquals(fingerprint, DtlsFingerprint.parse("  SHA-256   " + sdp.substring(8).toLowerCase() + " "));
            assertEquals(fingerprint.hashCode(), DtlsFingerprint.parse(sdp).hashCode());
            assertTrue(fingerprint.matches(CERTIFICATE.certificate()));
            assertFalse(fingerprint.matches(DtlsCertificate.generateEcdsa().certificate()));
        }

        @Test
        @DisplayName("copies the digest in and out")
        void defensiveCopies() {
            var digest = new byte[32];
            var fingerprint = new DtlsFingerprint("sha-256", digest);
            digest[0] = 1;
            assertEquals(0, fingerprint.value()[0]);
            fingerprint.value()[0] = 2;
            assertEquals(0, fingerprint.value()[0]);
        }

        @ParameterizedTest(name = "{0}")
        @CsvSource({"md5 00:11", "sha-256 00:11", "sha-256", "sha-256 zz:zz", "foo 00"})
        @DisplayName("rejects malformed values")
        void malformed(String value) {
            assertThrows(IllegalArgumentException.class, () -> DtlsFingerprint.parse(value));
        }

        @Test
        @DisplayName("selects the strongest hash function among several")
        void select() {
            var certificate = CERTIFICATE.certificate();
            var sha1 = DtlsFingerprint.of("sha-1", certificate);
            var sha256 = DtlsFingerprint.of("sha-256", certificate);
            var sha512 = DtlsFingerprint.of("SHA-512", certificate);
            assertEquals(List.of(sha512), DtlsFingerprint.select(List.of(sha1, sha256, sha512)));
            assertEquals(List.of(sha256), DtlsFingerprint.select(List.of(sha1, sha256)));
        }

        @Test
        @DisplayName("parses random strings without unexpected exceptions")
        void fuzz() {
            var random = new Random(4);
            var alphabet = "sha-0123456789ABCDEFabcdef: \t";
            for (var round = 0; round < 20_000; round++) {
                var builder = new StringBuilder();
                for (var index = random.nextInt(40); index > 0; index--) {
                    builder.append(alphabet.charAt(random.nextInt(alphabet.length())));
                }
                try {
                    DtlsFingerprint.parse(builder.toString());
                } catch (IllegalArgumentException expected) {
                    // malformed input is reported this way only
                }
            }
        }
    }

    @Nested
    @DisplayName("DtlsCertificate")
    class Certificates {
        @Test
        @DisplayName("generates ECDSA and RSA certificates with three fingerprints and a thirty-day expiry")
        void generate() {
            for (var certificate : List.of(DtlsCertificate.generateEcdsa(), DtlsCertificate.generateRsa())) {
                assertEquals(List.of("sha-256", "sha-384", "sha-512"),
                        certificate.fingerprints().stream().map(DtlsFingerprint::algorithm).toList());
                var days = Duration.between(Instant.now(), certificate.expires()).toDays();
                assertTrue(days >= 29 && days <= 30, "expires in " + days + " days");
                assertFalse(certificate.isExpired(Instant.now()));
                assertTrue(certificate.isExpired(certificate.expires()));
            }
            assertEquals("RSA", DtlsCertificate.generateRsa().certificate().getPublicKey().getAlgorithm());
        }

        @Test
        @DisplayName("imports an existing key and certificate, refusing a key of another certificate")
        void importExisting() {
            var imported = DtlsCertificate.of(CERTIFICATE.privateKey(), CERTIFICATE.certificate());
            assertEquals(CERTIFICATE.fingerprints(), imported.fingerprints());
            var other = DtlsCertificate.generateEcdsa();
            assertThrows(IllegalArgumentException.class, () -> DtlsCertificate.of(other.privateKey(), CERTIFICATE.certificate()));
            var rsa = DtlsCertificate.generateRsa();
            assertThrows(IllegalArgumentException.class, () -> DtlsCertificate.of(rsa.privateKey(), CERTIFICATE.certificate()));
        }

        @Test
        @DisplayName("generates with a custom validity, refusing a non-positive one")
        void validity() {
            var certificate = DtlsCertificate.generateEcdsa(Duration.ofDays(365 * 30));
            assertTrue(certificate.expires().isAfter(Instant.now().plus(Duration.ofDays(365 * 29))));
            assertThrows(IllegalArgumentException.class, () -> DtlsCertificate.generateEcdsa(Duration.ZERO));
        }
    }

    @Nested
    @DisplayName("a=setup and a=tls-id")
    class Signalling {
        @Test
        @DisplayName("parses, answers and maps setup values to roles")
        void setup() {
            assertEquals(DtlsSetup.ACTPASS, DtlsSetup.parse(" ActPass "));
            assertEquals("holdconn", DtlsSetup.HOLDCONN.toSdp());
            assertEquals(DtlsSetup.ACTIVE, DtlsSetup.answerTo(DtlsSetup.ACTPASS));
            assertEquals(DtlsSetup.PASSIVE, DtlsSetup.answerTo(DtlsSetup.ACTIVE));
            assertEquals(DtlsSetup.ACTIVE, DtlsSetup.answerTo(DtlsSetup.PASSIVE));
            assertEquals(Optional.of(DtlsRole.CLIENT), DtlsSetup.ACTIVE.role());
            assertEquals(DtlsRole.SERVER, DtlsSetup.localRole(DtlsSetup.ACTPASS, DtlsSetup.ACTIVE));
            assertEquals(DtlsRole.CLIENT, DtlsSetup.localRole(DtlsSetup.ACTIVE, DtlsSetup.ACTPASS));
            assertThrows(IllegalArgumentException.class, () -> DtlsSetup.localRole(DtlsSetup.ACTIVE, DtlsSetup.ACTIVE));
            assertThrows(IllegalArgumentException.class, () -> DtlsSetup.localRole(DtlsSetup.ACTPASS, DtlsSetup.ACTPASS));
            assertThrows(IllegalArgumentException.class, () -> DtlsSetup.parse("both"));
        }

        @Test
        @DisplayName("generates and validates tls-id values")
        void tlsId() {
            var generated = DtlsTlsId.generate();
            assertEquals(32, generated.value().length());
            assertEquals(generated, DtlsTlsId.parse(" " + generated.toSdp() + " "));
            assertNotEquals(generated, DtlsTlsId.generate());
            assertThrows(IllegalArgumentException.class, () -> new DtlsTlsId("short"));
            assertThrows(IllegalArgumentException.class, () -> new DtlsTlsId("abcdefghijklmnopqrstu!"));
        }

        @Test
        @DisplayName("requires a new association when the tls-id, the fingerprints or the role change")
        void restartRule() {
            var fingerprints = CERTIFICATE.fingerprints();
            var id = DtlsTlsId.generate();
            var current = new DtlsParameters(DtlsSetup.ACTIVE, fingerprints, Optional.of(id));
            assertFalse(new DtlsParameters(DtlsSetup.ACTIVE, fingerprints, Optional.of(id)).requiresNewAssociation(current));
            assertTrue(new DtlsParameters(DtlsSetup.ACTIVE, fingerprints, Optional.of(DtlsTlsId.generate()))
                    .requiresNewAssociation(current));
            var withoutId = new DtlsParameters(DtlsSetup.ACTIVE, fingerprints, Optional.empty());
            assertFalse(withoutId.requiresNewAssociation(new DtlsParameters(DtlsSetup.ACTIVE, fingerprints, Optional.empty())));
            assertTrue(new DtlsParameters(DtlsSetup.ACTIVE, DtlsCertificate.generateEcdsa().fingerprints(), Optional.empty())
                    .requiresNewAssociation(withoutId));
            assertTrue(new DtlsParameters(DtlsSetup.PASSIVE, fingerprints, Optional.empty()).requiresNewAssociation(withoutId));
            assertThrows(IllegalArgumentException.class, () -> new DtlsParameters(DtlsSetup.ACTIVE, List.of(), Optional.empty()));
        }
    }

    @Nested
    @DisplayName("tables and configuration")
    class Tables {
        @Test
        @DisplayName("maps SRTP profiles, versions and alerts by their wire values")
        void lookups() {
            assertEquals(Optional.of(SrtpProfile.AEAD_AES_256_GCM), SrtpProfile.ofId(0x0008));
            assertEquals(32, SrtpProfile.AEAD_AES_256_GCM.keyLength());
            assertEquals(Optional.empty(), SrtpProfile.ofId(0x0003));
            assertEquals(Optional.of(DtlsVersion.DTLS_1_3), DtlsVersion.ofWireValue(0xFEFC));
            assertEquals(Optional.of(DtlsAlert.NO_RENEGOTIATION), DtlsAlert.ofCode(100));
            assertEquals(Optional.empty(), DtlsAlert.ofCode(255));
        }

        @Test
        @DisplayName("validates the configuration and copies its collections")
        void config() {
            var config = DtlsConfig.of(CERTIFICATE);
            assertEquals(Set.of(DtlsVersion.values()), config.versions());
            assertEquals(DtlsConfig.DEFAULT_INITIAL_RETRANSMIT, config.initialRetransmit());
            assertTrue(config.cookieExchange());
            assertFalse(config.withCookieExchange(false).cookieExchange());
            assertThrows(IllegalArgumentException.class, () -> config.withVersions(Set.of()));
            assertThrows(IllegalArgumentException.class, () -> config.withCertificates(List.of()));
            assertThrows(IllegalArgumentException.class, () -> config.withInitialRetransmit(Duration.ZERO));
            assertThrows(UnsupportedOperationException.class, () -> config.srtpProfiles().clear());
        }

        @Test
        @DisplayName("redacts key material from DtlsSrtpKeys and copies it")
        void keys() {
            var key = new byte[16];
            var keys = new DtlsSrtpKeys(SrtpProfile.AES128_CM_HMAC_SHA1_80, key, new byte[14], new byte[16], new byte[14]);
            key[0] = 5;
            assertEquals(0, keys.localKey()[0]);
            assertFalse(keys.toString().contains("0, 0"));
        }
    }
}
