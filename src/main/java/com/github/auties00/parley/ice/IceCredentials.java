package com.github.auties00.parley.ice;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Objects;

/// The ICE username fragment and password of one agent, as `a=ice-ufrag` and `a=ice-pwd` carry them.
///
/// RFC 8839 section 5.4 requires at least 24 bits of randomness in the fragment and 128 bits in the password, both
/// drawn from the `ice-char` alphabet; [#generate()] draws 8 and 24 characters of 64 symbols, 48 and 144 bits.
/// [#toString()] leaves the password out.
///
/// @param ufrag    the username fragment
/// @param password the password, whose UTF-8 bytes key `MESSAGE-INTEGRITY`
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
public record IceCredentials(String ufrag, String password) {
    /// The `ice-char` alphabet: letters, digits, `+` and `/`.
    private static final String ICE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// The source of random credentials.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// Creates credentials.
    ///
    /// @param ufrag    the username fragment
    /// @param password the password
    public IceCredentials {
        Objects.requireNonNull(ufrag, "ufrag cannot be null");
        Objects.requireNonNull(password, "password cannot be null");
    }

    /// {@return fresh random credentials drawn from a [SecureRandom]}
    public static IceCredentials generate() {
        return new IceCredentials(random(8), random(24));
    }

    /// {@return the short-term credential key of `MESSAGE-INTEGRITY`, a new array holding the UTF-8 bytes of the
    /// password}
    public byte[] key() {
        return password.getBytes(StandardCharsets.UTF_8);
    }

    /// {@return a random `ice-char` string of `length` characters}
    private static String random(int length) {
        var builder = new StringBuilder(length);
        for (var i = 0; i < length; i++) {
            builder.append(ICE_CHARS.charAt(RANDOM.nextInt(ICE_CHARS.length())));
        }
        return builder.toString();
    }

    /// {@return the username fragment, without the password}
    @Override
    public String toString() {
        return "IceCredentials[ufrag=" + ufrag + "]";
    }
}
