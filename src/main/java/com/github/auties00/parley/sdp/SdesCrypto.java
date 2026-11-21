package com.github.auties00.parley.sdp;

import com.github.auties00.srtp.SrtpCryptoSuite;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/// One SDES `a=crypto` attribute: the tag, the SRTP crypto suite and the inline master key and salt that the sender
/// protects its media with.
///
/// ```text
/// a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4
/// ```
///
/// The base64 text after `inline:` is the master key followed by the master salt, whose lengths the suite fixes. A
/// lifetime and an MKI after it (`|2^20|1:4`) are accepted and ignored on parse, and [#value()] writes neither, so an
/// offer that requires an MKI cannot be answered with this class. Session parameters after the key parameters (such as
/// `UNENCRYPTED_SRTCP`) are kept verbatim.
///
/// A line pairs with a media direction: this side's own line keys what it sends, the peer's line what it receives.
/// Both are typed the same, so a transport takes them as two named arguments rather than four byte arrays:
///
/// {@snippet lang = java :
/// var local = SdesCrypto.generate(1, SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80);
/// // signal "a=crypto:" + local.value(), read the peer's line from its answer
/// var remote = SdesCrypto.parse(remoteAttributeValue);
/// transport.establishSdes(remoteAddress, local, remote);
/// }
///
/// The key material is secret: the record copies it in and out, and [#toString()] leaves it out.
///
/// @param tag               the decimal tag that pairs an answer line with the offer line it accepts, at least `0`
/// @param suite             the crypto suite
/// @param keySalt           the master key followed by the master salt, exactly
///                          [SrtpCryptoSuite#masterKeyLength()] plus [SrtpCryptoSuite#masterSaltLength()] bytes
/// @param sessionParameters the session parameters after the key parameters, unmodifiable, in order
/// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
/// @spec https://www.rfc-editor.org/rfc/rfc6188.html RFC 6188: The Use of AES-192 and AES-256 in Secure RTP
/// @spec https://www.rfc-editor.org/rfc/rfc7714.html RFC 7714: AES-GCM Authenticated Encryption in the Secure Real-time Transport Protocol (SRTP)
public record SdesCrypto(int tag, SrtpCryptoSuite suite, byte[] keySalt, List<String> sessionParameters) {
    /// The source of fresh SDES keys.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// Creates an attribute, copying the key material and the session parameters.
    ///
    /// @param tag               the tag
    /// @param suite             the crypto suite
    /// @param keySalt           the master key followed by the master salt
    /// @param sessionParameters the session parameters
    /// @throws IllegalArgumentException if `tag` is negative, the key material does not have the suite's length, or a
    ///                                  session parameter is blank or holds white space
    public SdesCrypto {
        Objects.requireNonNull(suite, "suite cannot be null");
        keySalt = Objects.requireNonNull(keySalt, "keySalt cannot be null").clone();
        sessionParameters = List.copyOf(sessionParameters);
        if (tag < 0) {
            throw new IllegalArgumentException("tag cannot be negative");
        }
        var expected = suite.masterKeyLength() + suite.masterSaltLength();
        if (keySalt.length != expected) {
            throw new IllegalArgumentException(suite + " needs " + expected + " bytes of key and salt, got "
                    + keySalt.length);
        }
        for (var parameter : sessionParameters) {
            if (parameter.isBlank() || parameter.chars().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException("malformed session parameter: " + parameter);
            }
        }
    }

    /// Creates an attribute without session parameters, copying the key material.
    ///
    /// @param tag     the tag
    /// @param suite   the crypto suite
    /// @param keySalt the master key followed by the master salt
    /// @throws IllegalArgumentException if `tag` is negative or the key material does not have the suite's length
    public SdesCrypto(int tag, SrtpCryptoSuite suite, byte[] keySalt) {
        this(tag, suite, keySalt, List.of());
    }

    /// Parses the value of an `a=crypto` attribute.
    ///
    /// @param value the text after `a=crypto:`
    /// @return the attribute
    /// @throws IllegalArgumentException if the value has no tag, suite or `inline:` key, the tag is not a
    ///                                  non-negative number, the suite is not one [SrtpCryptoSuite] names, or the key
    ///                                  is not base64 of the suite's length
    public static SdesCrypto parse(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        var tokens = value.trim().split("\\s+");
        if (tokens.length < 3 || !tokens[2].startsWith("inline:")) {
            throw new IllegalArgumentException("malformed crypto attribute: " + value);
        }
        int tag;
        try {
            tag = Integer.parseInt(tokens[0]);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("malformed crypto tag: " + value, exception);
        }
        SrtpCryptoSuite suite;
        try {
            suite = SrtpCryptoSuite.valueOf(tokens[1].toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("unsupported crypto suite " + tokens[1], exception);
        }
        var keyParams = tokens[2].substring("inline:".length());
        var bar = keyParams.indexOf('|');
        var encoded = bar < 0 ? keyParams : keyParams.substring(0, bar);
        byte[] material;
        try {
            material = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("malformed crypto key: not base64", exception);
        }
        return new SdesCrypto(tag, suite, material, Arrays.asList(tokens).subList(3, tokens.length));
    }

    /// {@return the attribute an `a=crypto` value carries, or an empty optional when it is malformed or names a suite
    /// this library does not support}
    ///
    /// Negotiation uses it to skip the lines it cannot use: an offer lists several suites in preference order and the
    /// answerer picks the first one it supports.
    ///
    /// @param value the text after `a=crypto:`
    public static Optional<SdesCrypto> tryParse(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        try {
            return Optional.of(parse(value));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    /// {@return an attribute with fresh key material from a [SecureRandom], of the lengths the suite defines}
    ///
    /// @param tag   the tag
    /// @param suite the suite
    /// @throws IllegalArgumentException if `tag` is negative
    public static SdesCrypto generate(int tag, SrtpCryptoSuite suite) {
        Objects.requireNonNull(suite, "suite cannot be null");
        var material = new byte[suite.masterKeyLength() + suite.masterSaltLength()];
        RANDOM.nextBytes(material);
        return new SdesCrypto(tag, suite, material);
    }

    /// {@return a copy of the key material, the master key followed by the master salt}
    @Override
    public byte[] keySalt() {
        return keySalt.clone();
    }

    /// {@return a copy of the master key, the first [SrtpCryptoSuite#masterKeyLength()] bytes of the key material}
    public byte[] masterKey() {
        return Arrays.copyOfRange(keySalt, 0, suite.masterKeyLength());
    }

    /// {@return a copy of the master salt, the [SrtpCryptoSuite#masterSaltLength()] bytes after the key}
    public byte[] masterSalt() {
        return Arrays.copyOfRange(keySalt, suite.masterKeyLength(), keySalt.length);
    }

    /// {@return the attribute value, `<tag> <suite> inline:<base64>` followed by the session parameters, with neither
    /// lifetime nor MKI}
    public String value() {
        var builder = new StringBuilder().append(tag).append(' ').append(suite.name()).append(" inline:")
                .append(Base64.getEncoder().encodeToString(keySalt));
        for (var parameter : sessionParameters) {
            builder.append(' ').append(parameter);
        }
        return builder.toString();
    }

    /// {@return whether `other` is an attribute with the same tag, suite, key material and session parameters}
    ///
    /// @param other the object to compare with
    @Override
    public boolean equals(Object other) {
        return other instanceof SdesCrypto that && tag == that.tag && suite == that.suite
                && MessageDigest.isEqual(keySalt, that.keySalt) && sessionParameters.equals(that.sessionParameters);
    }

    /// {@return a hash code over the tag, the suite, the key material and the session parameters}
    @Override
    public int hashCode() {
        return Objects.hash(tag, suite, Arrays.hashCode(keySalt), sessionParameters);
    }

    /// {@return the tag, the suite and the session parameters, without the key material}
    @Override
    public String toString() {
        return "SdesCrypto[tag=" + tag + ", suite=" + suite + ", sessionParameters=" + sessionParameters + "]";
    }
}
