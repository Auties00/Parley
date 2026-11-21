package com.github.auties00.parley.dtls;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/// The hash functions of the cipher suites, which drive the DTLS 1.2 PRF, the DTLS 1.3 key schedule and the
/// handshake transcript.
enum HashAlgorithm {
    /// SHA-256.
    SHA256("SHA-256", "HmacSHA256", 32),

    /// SHA-384.
    SHA384("SHA-384", "HmacSHA384", 48);

    /// The JDK digest name.
    private final String digestName;

    /// The JDK MAC name.
    private final String macName;

    /// The output length in bytes.
    private final int length;

    /// Creates a hash constant.
    HashAlgorithm(String digestName, String macName, int length) {
        this.digestName = digestName;
        this.macName = macName;
        this.length = length;
    }

    /// {@return the output length in bytes}
    int length() {
        return length;
    }

    /// {@return a new digest}
    ///
    /// @throws IllegalStateException if the JDK lacks the algorithm
    MessageDigest digest() {
        try {
            return MessageDigest.getInstance(digestName);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(digestName + " unavailable", exception);
        }
    }

    /// {@return the hash of `data`}
    ///
    /// @param data the data
    byte[] hash(byte[] data) {
        return digest().digest(data);
    }

    /// {@return an HMAC keyed with `key`}
    ///
    /// @param key the key; an empty key is treated as `length()` zero bytes would be, as HMAC pads it
    /// @throws IllegalStateException if the JDK lacks the algorithm
    Mac mac(byte[] key) {
        try {
            var mac = Mac.getInstance(macName);
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[length] : key, macName));
            return mac;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(macName + " unavailable", exception);
        }
    }

    /// {@return the HMAC of `data` under `key`}
    ///
    /// @param key  the key
    /// @param data the data
    byte[] hmac(byte[] key, byte[] data) {
        return mac(key).doFinal(data);
    }
}
