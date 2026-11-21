package com.github.auties00.parley.dtls;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

/// Protects the records of one direction of a DTLS 1.3 epoch, and computes the mask that encrypts their record
/// numbers.
///
/// The per-record nonce is the write IV XORed with the 64-bit record sequence number, without the epoch; the
/// additional data is the unified header exactly as sent but with the sequence number in the clear. The record number
/// mask comes from the first 16 bytes of the ciphertext: AES-ECB under the `sn` key for the AES suites, or the ChaCha20
/// block whose counter is the first four bytes (little-endian) and whose nonce is the next twelve:
///
/// ```text
/// nonce = iv XOR (0(4) || sequence(8))
/// mask  = AES-ECB(sn_key, ciphertext[0..15])                        AES suites
/// mask  = ChaCha20(sn_key, ciphertext[0..3], ciphertext[4..15])     ChaCha20 suite
/// ```
///
/// Instances are not thread-safe; the record layer uses each under its lock.
///
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
final class Dtls13RecordCipher {
    /// The number of ciphertext bytes the record number mask is computed from.
    static final int MASK_SAMPLE = 16;

    /// The algorithm.
    private final Aead aead;

    /// The write key.
    private final SecretKeySpec key;

    /// The 12-byte write IV.
    private final byte[] iv;

    /// The record number key.
    private final SecretKeySpec snKey;

    /// The record cipher, re-initialized per record.
    private final Cipher cipher;

    /// The AES-ECB cipher of the record number mask, or `null` for ChaCha20.
    private final Cipher maskCipher;

    /// Creates the protection of one direction of an epoch.
    ///
    /// @param aead  the algorithm
    /// @param key   the write key, copied
    /// @param iv    the 12-byte write IV, copied
    /// @param snKey the record number key, copied
    /// @throws IllegalStateException if the JDK lacks the algorithm
    Dtls13RecordCipher(Aead aead, byte[] key, byte[] iv, byte[] snKey) {
        this.aead = aead;
        this.key = new SecretKeySpec(key, aead.keyAlgorithm());
        this.iv = iv.clone();
        this.snKey = new SecretKeySpec(snKey, aead.keyAlgorithm());
        try {
            this.cipher = Cipher.getInstance(aead.transformation());
            if (aead.isAes()) {
                this.maskCipher = Cipher.getInstance("AES/ECB/NoPadding");
                this.maskCipher.init(Cipher.ENCRYPT_MODE, this.snKey);
            } else {
                this.maskCipher = null;
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(aead + " unavailable", exception);
        }
    }

    /// {@return the cipher of an epoch's traffic secret: its key, IV and record number key}
    ///
    /// @param suite  the negotiated suite
    /// @param secret the traffic secret
    static Dtls13RecordCipher fromSecret(CipherSuite suite, byte[] secret) {
        var hash = suite.hash();
        var aead = suite.aead();
        var key = Hkdf.expandLabel(hash, secret, "key", new byte[0], aead.keyLength());
        var iv = Hkdf.expandLabel(hash, secret, "iv", new byte[0], Aead.NONCE_LENGTH);
        var sn = Hkdf.expandLabel(hash, secret, "sn", new byte[0], aead.keyLength());
        return new Dtls13RecordCipher(aead, key, iv, sn);
    }

    /// Encrypts a `DTLSInnerPlaintext`.
    ///
    /// @param sequence the 64-bit record sequence number
    /// @param aad      the unified header with the plaintext sequence number
    /// @param inner    the content followed by the content type
    /// @return the ciphertext with its tag
    /// @throws DtlsException if the cipher fails
    byte[] seal(long sequence, byte[] aad, byte[] inner) throws DtlsException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, parameters(sequence));
            cipher.updateAAD(aad);
            return cipher.doFinal(inner);
        } catch (GeneralSecurityException exception) {
            throw new DtlsException(DtlsAlert.INTERNAL_ERROR, false, "record encryption failed", exception);
        }
    }

    /// Decrypts a record into its `DTLSInnerPlaintext`.
    ///
    /// @param sequence the reconstructed 64-bit record sequence number
    /// @param aad      the unified header with the plaintext sequence number
    /// @param source   the source array
    /// @param offset   the first ciphertext byte
    /// @param length   the ciphertext length, tag included
    /// @return the inner plaintext
    /// @throws DtlsException if the record does not authenticate
    byte[] open(long sequence, byte[] aad, byte[] source, int offset, int length) throws DtlsException {
        if (length < Aead.TAG_LENGTH) {
            throw new DtlsException(DtlsAlert.BAD_RECORD_MAC, "protected record too short");
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, parameters(sequence));
            cipher.updateAAD(aad);
            return cipher.doFinal(source, offset, length);
        } catch (GeneralSecurityException exception) {
            throw new DtlsException(DtlsAlert.BAD_RECORD_MAC, "record authentication failed");
        }
    }

    /// Computes the record number mask from a ciphertext sample.
    ///
    /// @param source the array holding the ciphertext
    /// @param offset the first ciphertext byte; [#MASK_SAMPLE] bytes must follow it
    /// @return the 16-byte mask
    /// @throws DtlsException if the cipher fails
    byte[] mask(byte[] source, int offset) throws DtlsException {
        try {
            if (maskCipher != null) {
                return maskCipher.doFinal(source, offset, MASK_SAMPLE);
            }
            var counter = (source[offset] & 0xFF) | (source[offset + 1] & 0xFF) << 8
                    | (source[offset + 2] & 0xFF) << 16 | (source[offset + 3] & 0xFF) << 24;
            var nonce = new byte[Aead.NONCE_LENGTH];
            System.arraycopy(source, offset + 4, nonce, 0, Aead.NONCE_LENGTH);
            var chacha = Cipher.getInstance("ChaCha20");
            chacha.init(Cipher.ENCRYPT_MODE, snKey, new ChaCha20ParameterSpec(nonce, counter));
            return chacha.doFinal(new byte[MASK_SAMPLE]);
        } catch (GeneralSecurityException exception) {
            throw new DtlsException(DtlsAlert.INTERNAL_ERROR, false, "record number mask failed", exception);
        }
    }

    /// {@return the nonce parameters of a record}
    private AlgorithmParameterSpec parameters(long sequence) {
        var nonce = iv.clone();
        for (var index = 0; index < 8; index++) {
            nonce[4 + index] ^= (byte) (sequence >>> (56 - 8 * index));
        }
        return aead.isAes() ? new GCMParameterSpec(Aead.TAG_LENGTH * 8, nonce) : new IvParameterSpec(nonce);
    }
}
