package com.github.auties00.parley.dtls;

import java.nio.charset.StandardCharsets;

/// Computes the TLS 1.2 pseudo-random function, `P_hash` over the HMAC of a cipher suite's hash.
///
/// `PRF(secret, label, seed) = P_hash(secret, label + seed)`, where `P_hash` chains `A(i) = HMAC(secret, A(i-1))` and
/// outputs `HMAC(secret, A(i) + label + seed)` blocks until the requested length is reached.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
final class TlsPrf {
    private TlsPrf() {
        throw new AssertionError("TlsPrf cannot be instantiated");
    }

    /// {@return `length` bytes of `PRF(secret, label, seed)` under `hash`}
    ///
    /// @param hash   the suite's hash
    /// @param secret the secret
    /// @param label  the ASCII label, such as `master secret`
    /// @param seed   the seed
    /// @param length the number of bytes
    static byte[] compute(HashAlgorithm hash, byte[] secret, String label, byte[] seed, int length) {
        var mac = hash.mac(secret);
        var labelSeed = concat(label.getBytes(StandardCharsets.US_ASCII), seed);
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
    }

    /// {@return a new array holding the arrays in order}
    ///
    /// @param parts the arrays
    static byte[] concat(byte[]... parts) {
        var total = 0;
        for (var part : parts) {
            total += part.length;
        }
        var result = new byte[total];
        var offset = 0;
        for (var part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }
}
