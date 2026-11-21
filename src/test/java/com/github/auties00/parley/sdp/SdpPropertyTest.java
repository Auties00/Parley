package com.github.auties00.parley.sdp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/// Property and fuzz tests of the SDP layer: every generated attribute survives a write and parse unchanged, every
/// browser description survives a parse and encode unchanged, and no input, however mangled, makes the parsers throw
/// anything but the documented [IllegalArgumentException]. Seeds are fixed so a failure reproduces.
@DisplayName("SDP properties")
class SdpPropertyTest {
    private static final int ITERATIONS = 20_000;
    private static final String TOKEN_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.+/";
    private static final String RID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

    static Stream<String> fixtures() {
        return Stream.of(BrowserFixtures.CHROME_OFFER, BrowserFixtures.CHROME_SIMULCAST_OFFER,
                BrowserFixtures.FIREFOX_OFFER, BrowserFixtures.SAFARI_OFFER, BrowserFixtures.LITE_SFU_OFFER);
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    @DisplayName("parses a browser description and encodes it back byte for byte")
    void browserRoundTrip(String sdp) {
        var parsed = SessionDescription.parse(sdp);
        assertEquals(sdp, parsed.encode());
        for (var section : parsed.media()) {
            for (var attribute : section.typedAttributes()) {
                if (attribute instanceof SdpAttribute.Invalid invalid) {
                    fail("a browser attribute did not parse: " + invalid);
                }
            }
        }
    }

    @Test
    @DisplayName("writes and parses back every generated typed attribute unchanged")
    void attributeRoundTrip() {
        var random = new Random(0x5DB);
        for (var iteration = 0; iteration < ITERATIONS; iteration++) {
            var attribute = generate(random);
            var line = attribute.toLine();
            var parsed = SdpAttribute.parse(line);
            assertEquals(attribute, parsed, () -> "round trip of " + line);
            assertEquals(line, parsed.toLine());
        }
    }

    @Test
    @DisplayName("never throws from SdpAttribute.parse, whatever the text")
    void attributeFuzz() {
        var random = new Random(0xF00D);
        var names = List.of("rtpmap", "fmtp", "rtcp-fb", "extmap", "ssrc", "ssrc-group", "msid", "mid", "group",
                "rid", "simulcast", "ice-ufrag", "ice-pwd", "ice-options", "candidate", "fingerprint", "setup",
                "tls-id", "rtcp", "sctp-port", "max-message-size", "crypto", "ptime", "maxptime", "sendrecv",
                "ice-lite", "extmap-allow-mixed", "bundle-only", "x-unknown");
        for (var iteration = 0; iteration < ITERATIONS; iteration++) {
            var name = names.get(random.nextInt(names.size()));
            var text = random.nextBoolean() ? name : name + ":" + noise(random, random.nextInt(40))
                    .replace('\r', ' ').replace('\n', ' ');
            assertDoesNotThrow(() -> SdpAttribute.parse(text), text);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    @DisplayName("parses mangled browser descriptions into a fixed point or rejects them with IllegalArgumentException")
    void descriptionFuzz(String sdp) {
        var random = new Random(sdp.hashCode());
        for (var iteration = 0; iteration < ITERATIONS / 10; iteration++) {
            var mangled = mangle(random, sdp);
            SessionDescription parsed;
            try {
                parsed = SessionDescription.parse(mangled);
            } catch (IllegalArgumentException expected) {
                continue;
            } catch (RuntimeException unexpected) {
                throw new AssertionError("unexpected exception for:\n" + mangled, unexpected);
            }
            var again = SessionDescription.parse(parsed.encode());
            assertEquals(parsed, again, "encode then parse is a fixed point");
            parsed.typedAttributes();
            parsed.origin();
            parsed.bundleGroups();
            for (var section : parsed.media()) {
                section.typedAttributes();
                section.mid();
                section.bandwidths();
                RtpCodec.of(section);
                parsed.direction(section);
            }
        }
    }

    @Test
    @DisplayName("rejects random text with IllegalArgumentException only")
    void randomTextFuzz() {
        var random = new Random(42);
        for (var iteration = 0; iteration < ITERATIONS; iteration++) {
            var text = noise(random, random.nextInt(200));
            try {
                SessionDescription.parse(text).encode();
            } catch (IllegalArgumentException expected) {
                // the documented rejection
            }
        }
    }

    /// Applies a few random edits: deleting, duplicating or replacing characters, and swapping lines.
    private static String mangle(Random random, String sdp) {
        var builder = new StringBuilder(sdp);
        var edits = 1 + random.nextInt(4);
        for (var edit = 0; edit < edits && !builder.isEmpty(); edit++) {
            var at = random.nextInt(builder.length());
            switch (random.nextInt(4)) {
                case 0 -> builder.deleteCharAt(at);
                case 1 -> builder.insert(at, builder.charAt(at));
                case 2 -> builder.setCharAt(at, (char) (32 + random.nextInt(95)));
                default -> {
                    var lines = new ArrayList<>(List.of(builder.toString().split("\r\n")));
                    if (lines.size() > 2) {
                        var a = random.nextInt(lines.size());
                        var b = random.nextInt(lines.size());
                        var swap = lines.get(a);
                        lines.set(a, lines.get(b));
                        lines.set(b, swap);
                    }
                    builder = new StringBuilder(String.join("\r\n", lines));
                }
            }
        }
        return builder.toString();
    }

    /// {@return random printable characters with occasional line breaks}
    private static String noise(Random random, int length) {
        var builder = new StringBuilder();
        for (var index = 0; index < length; index++) {
            var roll = random.nextInt(40);
            builder.append(roll == 0 ? '\n' : roll == 1 ? '\r' : (char) (32 + random.nextInt(95)));
        }
        return builder.toString();
    }

    /// {@return a random typed attribute}
    private static SdpAttribute generate(Random random) {
        return switch (random.nextInt(24)) {
            case 0 -> new SdpAttribute.Rtpmap(random.nextInt(128), token(random, RID_CHARS, 8),
                    1 + random.nextInt(200_000), random.nextBoolean() ? OptionalInt.of(1 + random.nextInt(8))
                    : OptionalInt.empty());
            case 1 -> new SdpAttribute.Fmtp(random.nextInt(128), token(random, RID_CHARS, 6) + "="
                    + token(random, RID_CHARS, 6) + ";" + token(random, RID_CHARS, 4) + "=1");
            case 2 -> new SdpAttribute.RtcpFb(random.nextBoolean() ? OptionalInt.of(random.nextInt(128))
                    : OptionalInt.empty(), token(random, RID_CHARS, 8),
                    random.nextBoolean() ? Optional.of(token(random, RID_CHARS, 5)) : Optional.empty());
            case 3 -> new SdpAttribute.Extmap(1 + random.nextInt(255),
                    random.nextBoolean() ? Optional.of(MediaDirection.values()[random.nextInt(4)]) : Optional.empty(),
                    URI.create("urn:ietf:params:rtp-hdrext:" + token(random, RID_CHARS, 10)),
                    random.nextBoolean() ? Optional.of(token(random, RID_CHARS, 5)) : Optional.empty());
            case 4 -> new SdpAttribute.Ssrc(random.nextLong(0x1_0000_0000L), token(random, RID_CHARS, 6),
                    random.nextBoolean() ? Optional.of(token(random, TOKEN_CHARS, 10)) : Optional.empty());
            case 5 -> new SdpAttribute.SsrcGroup(List.of("FID", "SIM", "FEC-FR").get(random.nextInt(3)),
                    List.of(random.nextLong(0x1_0000_0000L), random.nextLong(0x1_0000_0000L)));
            case 6 -> new SdpAttribute.Msid(token(random, TOKEN_CHARS, 20),
                    random.nextBoolean() ? Optional.of(token(random, TOKEN_CHARS, 20)) : Optional.empty());
            case 7 -> new SdpAttribute.Mid(token(random, TOKEN_CHARS, 16));
            case 8 -> new SdpAttribute.Group("BUNDLE", List.of(token(random, TOKEN_CHARS, 3),
                    token(random, TOKEN_CHARS, 3)));
            case 9 -> {
                var restrictions = new LinkedHashMap<String, String>();
                restrictions.put("max-width", Integer.toString(random.nextInt(4000)));
                if (random.nextBoolean()) {
                    restrictions.put("max-fps", Integer.toString(random.nextInt(60)));
                }
                yield new SdpAttribute.Rid(token(random, RID_CHARS, 8),
                        random.nextBoolean() ? SdpAttribute.Rid.Direction.SEND : SdpAttribute.Rid.Direction.RECV,
                        random.nextBoolean() ? List.of(random.nextInt(128)) : List.of(), restrictions);
            }
            case 10 -> new SdpAttribute.Simulcast(
                    List.of(List.of(new SdpAttribute.Simulcast.Stream(token(random, RID_CHARS, 3), random.nextBoolean())),
                            List.of(new SdpAttribute.Simulcast.Stream(token(random, RID_CHARS, 3), false),
                                    new SdpAttribute.Simulcast.Stream(token(random, RID_CHARS, 3), true))),
                    random.nextBoolean() ? List.of(List.of(new SdpAttribute.Simulcast.Stream(
                            token(random, RID_CHARS, 3), false))) : List.of());
            case 11 -> new SdpAttribute.IceUfrag(token(random, TOKEN_CHARS, 8));
            case 12 -> new SdpAttribute.IcePwd(token(random, TOKEN_CHARS, 24));
            case 13 -> new SdpAttribute.IceOptions(List.of("trickle", token(random, RID_CHARS, 5)));
            case 14 -> new SdpAttribute.Candidate(random.nextInt(9999) + " 1 udp " + random.nextInt() + " 192.0.2.1 "
                    + random.nextInt(65536) + " typ host");
            case 15 -> {
                var digest = new byte[32];
                random.nextBytes(digest);
                yield SdpAttribute.Fingerprint.of(random.nextBoolean() ? "sha-256" : "sha-384", digest);
            }
            case 16 -> new SdpAttribute.Setup(SetupRole.values()[random.nextInt(4)]);
            case 17 -> new SdpAttribute.TlsId(token(random, TOKEN_CHARS, 24));
            case 18 -> new SdpAttribute.Rtcp(random.nextInt(65536),
                    random.nextBoolean() ? Optional.of("IN IP4 0.0.0.0") : Optional.empty());
            case 19 -> new SdpAttribute.SctpPort(1 + random.nextInt(65535));
            case 20 -> new SdpAttribute.MaxMessageSize(random.nextLong(Long.MAX_VALUE));
            case 21 -> new SdpAttribute.Direction(MediaDirection.values()[random.nextInt(4)]);
            case 22 -> new SdpAttribute.Ptime(1 + random.nextInt(200));
            default -> List.<SdpAttribute>of(new SdpAttribute.RtcpMux(), new SdpAttribute.RtcpRsize(),
                    new SdpAttribute.RtcpMuxOnly(), new SdpAttribute.IceLite(), new SdpAttribute.EndOfCandidates(),
                    new SdpAttribute.ExtmapAllowMixed(), new SdpAttribute.BundleOnly(), new SdpAttribute.Cryptex())
                    .get(random.nextInt(8));
        };
    }

    /// {@return a random token of 1 to `maxLength` characters from `alphabet`}
    private static String token(Random random, String alphabet, int maxLength) {
        var length = 1 + random.nextInt(maxLength);
        var builder = new StringBuilder(length);
        for (var index = 0; index < length; index++) {
            builder.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return builder.toString();
    }
}
