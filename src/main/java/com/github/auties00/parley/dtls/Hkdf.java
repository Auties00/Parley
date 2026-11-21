package com.github.auties00.parley.dtls;

import java.nio.charset.StandardCharsets;

/// Computes HKDF and the `HKDF-Expand-Label` construction of the TLS 1.3 key schedule, with the label prefix DTLS 1.3
/// uses.
///
/// DTLS 1.3 prefixes every label with `dtls13` (no trailing space) where TLS 1.3 uses `tls13 `, so the two protocols
/// never derive the same keys; [#expandLabel(HashAlgorithm,String,byte\[\],String,byte\[\],int)] takes the prefix so
/// the TLS 1.3 test vectors of RFC 8448 can check it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5869.html RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
final class Hkdf {
    /// The label prefix of DTLS 1.3.
    static final String DTLS13 = "dtls13";

    private Hkdf() {
        throw new AssertionError("Hkdf cannot be instantiated");
    }

    /// {@return `HKDF-Extract(salt, ikm)`}
    ///
    /// @param hash the hash
    /// @param salt the salt; empty means `length()` zero bytes
    /// @param ikm  the input keying material; empty means `length()` zero bytes, as the key schedule specifies
    static byte[] extract(HashAlgorithm hash, byte[] salt, byte[] ikm) {
        return hash.hmac(salt, ikm.length == 0 ? new byte[hash.length()] : ikm);
    }

    /// {@return `HKDF-Expand(prk, info, length)`}
    ///
    /// @param hash   the hash
    /// @param prk    the pseudo-random key
    /// @param info   the context information
    /// @param length the output length, at most 255 times the hash length
    static byte[] expand(HashAlgorithm hash, byte[] prk, byte[] info, int length) {
        var mac = hash.mac(prk);
        var output = new byte[length];
        var previous = new byte[0];
        var written = 0;
        for (var counter = 1; written < length; counter++) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            var count = Math.min(previous.length, length - written);
            System.arraycopy(previous, 0, output, written, count);
            written += count;
        }
        return output;
    }

    /// {@return `HKDF-Expand-Label(secret, label, context, length)` with the DTLS 1.3 prefix}
    ///
    /// @param hash    the hash
    /// @param secret  the secret
    /// @param label   the label without prefix, such as `key`
    /// @param context the context, often empty or a transcript hash
    /// @param length  the output length
    static byte[] expandLabel(HashAlgorithm hash, byte[] secret, String label, byte[] context, int length) {
        return expandLabel(hash, DTLS13, secret, label, context, length);
    }

    /// {@return `HKDF-Expand-Label(secret, label, context, length)` with an explicit label prefix}
    ///
    /// @param hash    the hash
    /// @param prefix  the label prefix, `dtls13` or `tls13 `
    /// @param secret  the secret
    /// @param label   the label without prefix
    /// @param context the context
    /// @param length  the output length
    static byte[] expandLabel(HashAlgorithm hash, String prefix, byte[] secret, String label, byte[] context, int length) {
        var fullLabel = (prefix + label).getBytes(StandardCharsets.US_ASCII);
        var info = new TlsWriter(4 + fullLabel.length + context.length)
                .u16(length)
                .vector8(fullLabel)
                .vector8(context)
                .toByteArray();
        return expand(hash, secret, info, length);
    }

    /// {@return `Derive-Secret(secret, label, messages)`: the label expanded over a transcript hash, DTLS 1.3 prefix}
    ///
    /// @param hash           the hash
    /// @param secret         the secret
    /// @param label          the label without prefix
    /// @param transcriptHash the hash of the messages
    static byte[] deriveSecret(HashAlgorithm hash, byte[] secret, String label, byte[] transcriptHash) {
        return expandLabel(hash, secret, label, transcriptHash, hash.length());
    }
}
