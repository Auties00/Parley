package com.github.auties00.parley.dtls;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/// Computes the TLS 1.2 pseudo-random function with HMAC-SHA256, the PRF of every cipher suite [DtlsEndpoint]
/// negotiates.
///
/// `PRF(secret, label, seed) = P_SHA256(secret, label + seed)`, where `P_SHA256` chains
/// `A(i) = HMAC(secret, A(i-1))` and outputs `HMAC(secret, A(i) + label + seed)` blocks until the requested length is
/// reached.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
final class TlsPrf {
    private TlsPrf() {
        throw new AssertionError("TlsPrf cannot be instantiated");
    }

    /// {@return `length` bytes of `PRF(secret, label, seed)`}
    ///
    /// @param label the ASCII label, such as `master secret`
    /// @throws IllegalStateException if the JDK provides no HmacSHA256
    static byte[] compute(byte[] secret, String label, byte[] seed, int length) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            var labelBytes = label.getBytes(StandardCharsets.US_ASCII);
            var labelSeed = new byte[labelBytes.length + seed.length];
            System.arraycopy(labelBytes, 0, labelSeed, 0, labelBytes.length);
            System.arraycopy(seed, 0, labelSeed, labelBytes.length, seed.length);
            var output = new byte[length];
            var a = labelSeed;
            var written = 0;
            while (written < length) {
                a = mac.doFinal(a);
                mac.update(a);
                var block = mac.doFinal(labelSeed);
                var count = Math.min(block.length, length - written);
                System.arraycopy(block, 0, output, written, count);
                written += count;
            }
            return output;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HmacSHA256 unavailable", exception);
        }
    }

    /// {@return a new array holding `first` followed by `second`}
    static byte[] concat(byte[] first, byte[] second) {
        var result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
