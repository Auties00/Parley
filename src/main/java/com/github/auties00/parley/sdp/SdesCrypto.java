package com.github.auties00.parley.sdp;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/// One SDES `a=crypto` attribute: the tag, the SRTP crypto suite and the inline master key and salt that the sender
/// protects its media with.
///
/// ```text
/// a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4
/// ```
///
/// The base64 text after `inline:` is the master key followed by the master salt. A lifetime and an MKI after it
/// (`|2^20|1:4`) are accepted and ignored on parse, and [#value()] writes neither, so an offer that requires an MKI
/// cannot be answered with this class. Session parameters after the key are ignored too.
///
/// The key material is secret: the record copies it in and out, and [#toString()] leaves it out.
///
/// @param tag     the decimal tag that pairs an answer line with the offer line it accepts, at least `0`
/// @param suite   the crypto suite name, such as `AES_CM_128_HMAC_SHA1_80`
/// @param keySalt the master key followed by the master salt
/// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
public record SdesCrypto(int tag, String suite, byte[] keySalt) {
    /// The source of fresh SDES keys.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// Creates an attribute, copying the key material.
    ///
    /// @param tag     the tag
    /// @param suite   the crypto suite name
    /// @param keySalt the master key followed by the master salt
    /// @throws IllegalArgumentException if `tag` is negative
    public SdesCrypto {
        Objects.requireNonNull(suite, "suite cannot be null");
        keySalt = Objects.requireNonNull(keySalt, "keySalt cannot be null").clone();
        if (tag < 0) {
            throw new IllegalArgumentException("tag cannot be negative");
        }
    }

    /// Parses the value of an `a=crypto` attribute.
    ///
    /// @param value the text after `a=crypto:`
    /// @return the attribute
    /// @throws IllegalArgumentException if the value has no tag, suite or `inline:` key, the tag is not a
    ///                                  non-negative number, or the key is not base64
    public static SdesCrypto parse(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        var tokens = value.trim().split(" +");
        if (tokens.length < 3 || !tokens[2].startsWith("inline:")) {
            throw new IllegalArgumentException("malformed crypto attribute: " + value);
        }
        int tag;
        try {
            tag = Integer.parseInt(tokens[0]);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("malformed crypto tag: " + value, exception);
        }
        var keyParams = tokens[2].substring("inline:".length());
        var bar = keyParams.indexOf('|');
        var encoded = bar < 0 ? keyParams : keyParams.substring(0, bar);
        return new SdesCrypto(tag, tokens[1], Base64.getDecoder().decode(encoded));
    }

    /// {@return an attribute with fresh key material from a [SecureRandom]}
    ///
    /// The lengths are those the suite defines; for `AES_CM_128_HMAC_SHA1_80` they are 16 and 14 bytes.
    ///
    /// @param tag        the tag
    /// @param suite      the suite name
    /// @param keyLength  the master key length in bytes
    /// @param saltLength the master salt length in bytes
    /// @throws IllegalArgumentException if `tag` is negative
    /// @throws NegativeArraySizeException if the lengths add up to a negative number
    public static SdesCrypto generate(int tag, String suite, int keyLength, int saltLength) {
        var material = new byte[keyLength + saltLength];
        RANDOM.nextBytes(material);
        return new SdesCrypto(tag, suite, material);
    }

    /// {@return a copy of the key material, the master key followed by the master salt}
    @Override
    public byte[] keySalt() {
        return keySalt.clone();
    }

    /// {@return a copy of the master key, the first `keyLength` bytes of the key material}
    ///
    /// @param keyLength the master key length the suite defines, in bytes
    /// @throws IllegalArgumentException if the material is shorter than `keyLength`
    public byte[] masterKey(int keyLength) {
        if (keySalt.length < keyLength) {
            throw new IllegalArgumentException("crypto key material too short for the suite");
        }
        var key = new byte[keyLength];
        System.arraycopy(keySalt, 0, key, 0, keyLength);
        return key;
    }

    /// {@return a copy of the master salt, the `saltLength` bytes after the key}
    ///
    /// @param keyLength  the master key length the suite defines, in bytes
    /// @param saltLength the master salt length the suite defines, in bytes
    /// @throws IllegalArgumentException if the material is shorter than `keyLength + saltLength`
    public byte[] masterSalt(int keyLength, int saltLength) {
        if (keySalt.length < keyLength + saltLength) {
            throw new IllegalArgumentException("crypto key material too short for the suite");
        }
        var salt = new byte[saltLength];
        System.arraycopy(keySalt, keyLength, salt, 0, saltLength);
        return salt;
    }

    /// {@return the attribute value, `<tag> <suite> inline:<base64>`, with neither lifetime nor MKI}
    public String value() {
        return tag + " " + suite + " inline:" + Base64.getEncoder().encodeToString(keySalt);
    }

    /// {@return the tag and the suite, without the key material}
    @Override
    public String toString() {
        return "SdesCrypto[tag=" + tag + ", suite=" + suite + "]";
    }
}
