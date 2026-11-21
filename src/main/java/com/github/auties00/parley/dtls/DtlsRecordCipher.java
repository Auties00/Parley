package com.github.auties00.parley.dtls;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/// Protects the records of one direction of epoch 1 with AES-128-GCM, the record protection of the
/// `TLS_ECDHE_*_WITH_AES_128_GCM_SHA256` suites applied to DTLS 1.2.
///
/// The nonce is the 4-byte implicit salt of the key block followed by an 8-byte explicit part, which this
/// implementation sets to the record's epoch and sequence number and sends in front of the ciphertext. The additional
/// data is the epoch, the sequence number, the content type, the version and the plaintext length:
///
/// ```text
/// fragment = explicit_nonce(8) || AES-GCM(key, salt || explicit_nonce, aad, plaintext) || tag(16)
/// aad      = epoch(2) || seq(6) || type(1) || version(2) || plaintext_length(2)
/// ```
///
/// @spec https://www.rfc-editor.org/rfc/rfc5288.html RFC 5288: AES Galois Counter Mode (GCM) Cipher Suites for TLS
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
final class DtlsRecordCipher {
    /// The size of the explicit nonce.
    static final int EXPLICIT_NONCE_LENGTH = 8;

    /// The size of the authentication tag.
    static final int TAG_LENGTH = 16;

    /// The AES write key.
    private final SecretKeySpec key;

    /// The 4-byte implicit nonce salt, the write IV of the key block.
    private final byte[] salt;

    /// Creates the cipher of one direction.
    ///
    /// @param key  the 16-byte write key
    /// @param salt the 4-byte write IV, copied
    DtlsRecordCipher(byte[] key, byte[] salt) {
        this.key = new SecretKeySpec(key, "AES");
        this.salt = salt.clone();
    }

    /// Encrypts a record fragment.
    ///
    /// @param epochAndSequence the epoch in the top 16 bits and the sequence number in the low 48 bits
    /// @return the protected fragment, explicit nonce first
    /// @throws DtlsException if the cipher fails
    byte[] encrypt(long epochAndSequence, int type, int version, byte[] plaintext) throws DtlsException {
        var explicit = ByteBuffer.allocate(EXPLICIT_NONCE_LENGTH).putLong(epochAndSequence).array();
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * 8, nonce(explicit)));
            cipher.updateAAD(aad(epochAndSequence, type, version, plaintext.length));
            var sealed = cipher.doFinal(plaintext);
            return TlsPrf.concat(explicit, sealed);
        } catch (GeneralSecurityException exception) {
            throw new DtlsException("record encryption failed", exception);
        }
    }

    /// Decrypts a record fragment, taking the epoch, sequence number, type and version from the record header.
    ///
    /// @return the plaintext fragment
    /// @throws DtlsException if the fragment is too short or does not authenticate
    byte[] decrypt(long epochAndSequence, int type, int version, byte[] fragment) throws DtlsException {
        if (fragment.length < EXPLICIT_NONCE_LENGTH + TAG_LENGTH) {
            throw new DtlsException("protected record too short");
        }
        var explicit = new byte[EXPLICIT_NONCE_LENGTH];
        System.arraycopy(fragment, 0, explicit, 0, EXPLICIT_NONCE_LENGTH);
        var plaintextLength = fragment.length - EXPLICIT_NONCE_LENGTH - TAG_LENGTH;
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * 8, nonce(explicit)));
            cipher.updateAAD(aad(epochAndSequence, type, version, plaintextLength));
            return cipher.doFinal(fragment, EXPLICIT_NONCE_LENGTH, fragment.length - EXPLICIT_NONCE_LENGTH);
        } catch (GeneralSecurityException exception) {
            throw new DtlsException("record authentication failed", exception);
        }
    }

    /// {@return the full GCM nonce, the salt followed by the explicit nonce}
    private byte[] nonce(byte[] explicit) {
        return TlsPrf.concat(salt, explicit);
    }

    /// {@return the 13-byte additional authenticated data of a record}
    private static byte[] aad(long epochAndSequence, int type, int version, int length) {
        return ByteBuffer.allocate(13)
                .putLong(epochAndSequence)
                .put((byte) type)
                .putShort((short) version)
                .putShort((short) length)
                .array();
    }
}
