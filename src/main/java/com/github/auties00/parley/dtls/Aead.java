package com.github.auties00.parley.dtls;

/// The AEAD algorithms that protect DTLS records, with their key and nonce sizes.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5116.html RFC 5116: An Interface and Algorithms for Authenticated Encryption
/// @spec https://www.rfc-editor.org/rfc/rfc8439.html RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
enum Aead {
    /// AES-128 in Galois/Counter mode.
    AES_128_GCM(16, "AES/GCM/NoPadding", "AES"),

    /// AES-256 in Galois/Counter mode.
    AES_256_GCM(32, "AES/GCM/NoPadding", "AES"),

    /// ChaCha20 with a Poly1305 authenticator.
    CHACHA20_POLY1305(32, "ChaCha20-Poly1305", "ChaCha20");

    /// The authentication tag length every algorithm here appends.
    static final int TAG_LENGTH = 16;

    /// The full nonce length every algorithm here takes.
    static final int NONCE_LENGTH = 12;

    /// The key length in bytes.
    private final int keyLength;

    /// The JDK cipher transformation.
    private final String transformation;

    /// The JDK key algorithm.
    private final String keyAlgorithm;

    /// Creates an algorithm constant.
    Aead(int keyLength, String transformation, String keyAlgorithm) {
        this.keyLength = keyLength;
        this.transformation = transformation;
        this.keyAlgorithm = keyAlgorithm;
    }

    /// {@return the key length in bytes}
    int keyLength() {
        return keyLength;
    }

    /// {@return the JDK cipher transformation}
    String transformation() {
        return transformation;
    }

    /// {@return the JDK key algorithm}
    String keyAlgorithm() {
        return keyAlgorithm;
    }

    /// {@return whether the algorithm is AES-based, which decides how DTLS 1.3 masks record numbers}
    boolean isAes() {
        return this != CHACHA20_POLY1305;
    }
}
