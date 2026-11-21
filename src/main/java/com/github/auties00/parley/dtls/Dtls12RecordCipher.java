package com.github.auties00.parley.dtls;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

/// Protects the records of one direction of a DTLS 1.2 epoch with the AEAD of the negotiated cipher suite.
///
/// The additional data is the epoch and sequence number, the content type, the version and the plaintext length. The
/// AES-GCM suites send an 8-byte explicit nonce, set here to the epoch and sequence number, after a 4-byte implicit
/// salt; the ChaCha20-Poly1305 suites send none and XOR the epoch and sequence number into a 12-byte implicit IV:
///
/// ```text
/// aad            = epoch(2) || seq(6) || type(1) || version(2) || plaintext_length(2)
/// AES-GCM        : fragment = explicit_nonce(8) || ciphertext || tag(16), nonce = salt(4) || explicit_nonce
/// ChaCha20-Poly  : fragment = ciphertext || tag(16),                     nonce = iv(12) XOR (0(4) || epoch_seq(8))
/// ```
///
/// Instances are not thread-safe; the record layer uses each under its lock.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5288.html RFC 5288: AES Galois Counter Mode (GCM) Cipher Suites for TLS
/// @spec https://www.rfc-editor.org/rfc/rfc7905.html RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
final class Dtls12RecordCipher {
    /// The explicit nonce length of the AES-GCM suites.
    static final int EXPLICIT_NONCE_LENGTH = 8;

    /// The algorithm.
    private final Aead aead;

    /// The write key.
    private final SecretKeySpec key;

    /// The implicit IV: 4 bytes for AES-GCM, 12 for ChaCha20-Poly1305.
    private final byte[] iv;

    /// The cipher, re-initialized per record.
    private final Cipher cipher;

    /// The additional data of the record being protected or opened, rewritten for each; the cipher, which the record
    /// layer uses from one thread at a time, consumes it before the next record.
    private final byte[] aad = new byte[13];

    /// Creates the protection of one direction.
    ///
    /// @param aead the algorithm
    /// @param key  the write key, copied
    /// @param iv   the write IV of the key block, copied
    /// @throws IllegalStateException if the JDK lacks the algorithm
    Dtls12RecordCipher(Aead aead, byte[] key, byte[] iv) {
        this.aead = aead;
        this.key = new SecretKeySpec(key, aead.keyAlgorithm());
        this.iv = iv.clone();
        try {
            this.cipher = Cipher.getInstance(aead.transformation());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(aead + " unavailable", exception);
        }
    }

    /// {@return the bytes protection adds to a plaintext}
    int overhead() {
        return explicitNonceLength() + Aead.TAG_LENGTH;
    }

    /// {@return the length of the fixed IV this algorithm takes from a DTLS 1.2 key block}
    ///
    /// @param aead the algorithm
    static int fixedIvLength(Aead aead) {
        return aead.isAes() ? 4 : Aead.NONCE_LENGTH;
    }

    /// Protects a record fragment.
    ///
    /// @param epochAndSequence the epoch in the top 16 bits and the sequence number in the low 48
    /// @param type             the content type
    /// @param version          the record version
    /// @param plaintext        the plaintext
    /// @return the protected fragment
    /// @throws DtlsException if the cipher fails
    byte[] seal(long epochAndSequence, int type, int version, byte[] plaintext) throws DtlsException {
        var output = new byte[overhead() + plaintext.length];
        sealInto(epochAndSequence, type, version, plaintext, output, 0);
        return output;
    }

    /// Protects one record's plaintext into `output` at `offset`, where the caller reserved [#overhead()] bytes
    /// more than the plaintext: the explicit nonce, if any, then the ciphertext and the tag.
    ///
    /// @param epochAndSequence the epoch in the top 16 bits and the sequence number in the low 48
    /// @param type             the content type
    /// @param version          the record version
    /// @param plaintext        the plaintext
    /// @param output           the array the protected fragment is written into
    /// @param offset           the index of its first byte
    /// @throws DtlsException if the cipher fails
    void sealInto(long epochAndSequence, int type, int version, byte[] plaintext, byte[] output, int offset)
            throws DtlsException {
        var explicit = explicitNonceLength();
        if (explicit > 0) {
            writeLong(output, offset, epochAndSequence);
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, parameters(epochAndSequence));
            cipher.updateAAD(aad(epochAndSequence, type, version, plaintext.length));
            cipher.doFinal(plaintext, 0, plaintext.length, output, offset + explicit);
        } catch (GeneralSecurityException exception) {
            throw new DtlsException(DtlsAlert.INTERNAL_ERROR, false, "record encryption failed", exception);
        }
    }

    /// Unprotects a record fragment.
    ///
    /// @param epochAndSequence the epoch and sequence number of the record header
    /// @param type             the content type of the record header
    /// @param version          the version of the record header
    /// @param fragment         the source array
    /// @param offset           the first byte of the fragment
    /// @param length           the fragment length
    /// @return the plaintext
    /// @throws DtlsException if the fragment is too short or does not authenticate
    byte[] open(long epochAndSequence, int type, int version, byte[] fragment, int offset, int length)
            throws DtlsException {
        var explicit = explicitNonceLength();
        if (length < explicit + Aead.TAG_LENGTH) {
            throw new DtlsException(DtlsAlert.BAD_RECORD_MAC, "protected record too short");
        }
        var nonceSequence = explicit > 0 ? readLong(fragment, offset) : epochAndSequence;
        var plaintextLength = length - explicit - Aead.TAG_LENGTH;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, parameters(nonceSequence));
            cipher.updateAAD(aad(epochAndSequence, type, version, plaintextLength));
            return cipher.doFinal(fragment, offset + explicit, length - explicit);
        } catch (GeneralSecurityException exception) {
            throw new DtlsException(DtlsAlert.BAD_RECORD_MAC, "record authentication failed");
        }
    }

    /// {@return the explicit nonce length of the algorithm}
    private int explicitNonceLength() {
        return aead.isAes() ? EXPLICIT_NONCE_LENGTH : 0;
    }

    /// {@return the cipher parameters for a nonce sequence value}
    private AlgorithmParameterSpec parameters(long sequence) {
        var nonce = new byte[Aead.NONCE_LENGTH];
        if (aead.isAes()) {
            System.arraycopy(iv, 0, nonce, 0, 4);
            writeLong(nonce, 4, sequence);
            return new GCMParameterSpec(Aead.TAG_LENGTH * 8, nonce);
        }
        System.arraycopy(iv, 0, nonce, 0, Aead.NONCE_LENGTH);
        for (var index = 0; index < 8; index++) {
            nonce[4 + index] ^= (byte) (sequence >>> (56 - 8 * index));
        }
        return new IvParameterSpec(nonce);
    }

    /// {@return the 13-byte additional data of a record}
    private byte[] aad(long epochAndSequence, int type, int version, int length) {
        var aad = this.aad;
        writeLong(aad, 0, epochAndSequence);
        aad[8] = (byte) type;
        aad[9] = (byte) (version >>> 8);
        aad[10] = (byte) version;
        aad[11] = (byte) (length >>> 8);
        aad[12] = (byte) length;
        return aad;
    }

    /// Writes a big-endian 64-bit value.
    private static void writeLong(byte[] target, int offset, long value) {
        for (var index = 0; index < 8; index++) {
            target[offset + index] = (byte) (value >>> (56 - 8 * index));
        }
    }

    /// Reads a big-endian 64-bit value.
    private static long readLong(byte[] source, int offset) {
        var value = 0L;
        for (var index = 0; index < 8; index++) {
            value = value << 8 | (source[offset + index] & 0xFF);
        }
        return value;
    }
}
