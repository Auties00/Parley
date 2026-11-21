package com.github.auties00.parley.stun;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Objects;

/// The key that signs and verifies STUN message integrity.
///
/// A short-term credential (ICE connectivity checks) keys the HMAC with the password itself; a long-term credential
/// (TURN) keys it with a hash of the username, realm and password. Passwords and realms go through the OpaqueString
/// profile of RFC 8265 (Unicode normalization form C, non-ASCII spaces mapped to U+0020) before use.
///
/// The record holds a copy of the key and hands out copies; [#toString()] never shows it.
///
/// @param key the HMAC key bytes
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc8265.html RFC 8265: Preparation, Enforcement, and Comparison of Internationalized Strings Representing Usernames and Passwords
public record StunKey(byte[] key) {
    /// Creates a key from raw bytes.
    ///
    /// @param key the HMAC key bytes, copied
    /// @throws IllegalArgumentException if `key` is empty
    public StunKey {
        key = Objects.requireNonNull(key, "key cannot be null").clone();
        if (key.length == 0) {
            throw new IllegalArgumentException("a STUN key cannot be empty");
        }
    }

    /// {@return the short-term credential key of `password`: the UTF-8 bytes of its OpaqueString form}
    ///
    /// @param password the password, such as an ICE password
    public static StunKey shortTerm(String password) {
        return new StunKey(opaqueString(password).getBytes(StandardCharsets.UTF_8));
    }

    /// {@return the long-term credential key `H(username ":" OpaqueString(realm) ":" OpaqueString(password))`}
    ///
    /// The username is used as given: RFC 8489 applies OpaqueString to it before it goes into `USERNAME`, so the
    /// caller passes the form it sends.
    ///
    /// @param username  the username, as sent in `USERNAME`
    /// @param realm     the realm from the server's challenge
    /// @param password  the password
    /// @param algorithm the hash, [StunPasswordAlgorithm#MD5] unless the server negotiated another
    /// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
    public static StunKey longTerm(String username, String realm, String password, StunPasswordAlgorithm algorithm) {
        Objects.requireNonNull(username, "username cannot be null");
        Objects.requireNonNull(algorithm, "algorithm cannot be null");
        var input = username + ":" + opaqueString(realm) + ":" + opaqueString(password);
        return new StunKey(digest(algorithm.digestName(), input));
    }

    /// {@return the 32-byte `USERHASH` of a username and realm, `SHA-256(OpaqueString(username) ":"
    /// OpaqueString(realm))`}
    ///
    /// @param username the username
    /// @param realm    the realm
    /// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
    public static byte[] userHash(String username, String realm) {
        return digest("SHA-256", opaqueString(username) + ":" + opaqueString(realm));
    }

    /// {@return `value` prepared with the OpaqueString profile: non-ASCII spaces mapped to U+0020, then Unicode
    /// normalization form C}
    ///
    /// @param value the string
    /// @spec https://www.rfc-editor.org/rfc/rfc8265.html RFC 8265: Preparation, Enforcement, and Comparison of Internationalized Strings Representing Usernames and Passwords
    public static String opaqueString(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        var mapped = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            if (codePoint != ' ' && Character.getType(codePoint) == Character.SPACE_SEPARATOR) {
                mapped.append(' ');
            } else {
                mapped.appendCodePoint(codePoint);
            }
        });
        return Normalizer.normalize(mapped, Normalizer.Form.NFC);
    }

    /// {@return a copy of the key bytes}
    @Override
    public byte[] key() {
        return key.clone();
    }

    /// {@return the key bytes without a copy, for the codec}
    byte[] bytes() {
        return key;
    }

    /// {@return whether `other` is a key with the same bytes}
    @Override
    public boolean equals(Object other) {
        return other instanceof StunKey(var otherKey) && MessageDigest.isEqual(key, otherKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }

    /// {@return the key length, never the key}
    @Override
    public String toString() {
        return "StunKey[" + key.length + " bytes]";
    }

    /// {@return the digest of the UTF-8 bytes of `input`}
    private static byte[] digest(String algorithm, String input) {
        try {
            return MessageDigest.getInstance(algorithm).digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(algorithm + " unavailable", exception);
        }
    }
}
