package com.github.auties00.parley.stun;

import java.util.Optional;

/// A password algorithm of the long-term credential mechanism, the hash that turns a username, realm and password
/// into the `MESSAGE-INTEGRITY` key.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public enum StunPasswordAlgorithm {
    /// MD5, number `0x0001`, a 16-byte key; the algorithm when none is negotiated.
    MD5(0x0001, "MD5"),

    /// SHA-256, number `0x0002`, a 32-byte key.
    SHA_256(0x0002, "SHA-256");

    /// The algorithm number.
    private final int code;

    /// The JCA name of the digest.
    private final String digestName;

    /// Creates an algorithm.
    StunPasswordAlgorithm(int code, String digestName) {
        this.code = code;
        this.digestName = digestName;
    }

    /// {@return the 16-bit algorithm number}
    public int code() {
        return code;
    }

    /// {@return the JCA name of the digest, such as `SHA-256`}
    public String digestName() {
        return digestName;
    }

    /// {@return the algorithm numbered `code`, or an empty optional for an algorithm Parley does not support}
    ///
    /// @param code the 16-bit algorithm number
    public static Optional<StunPasswordAlgorithm> ofCode(int code) {
        return switch (code) {
            case 0x0001 -> Optional.of(MD5);
            case 0x0002 -> Optional.of(SHA_256);
            default -> Optional.empty();
        };
    }
}
