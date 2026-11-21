package com.github.auties00.parley.ice;

import com.github.auties00.parley.stun.StunKey;

import java.security.SecureRandom;
import java.util.Objects;

/// The ICE parameters of one agent, as `a=ice-ufrag`, `a=ice-pwd` and `a=ice-lite` carry them.
///
/// RFC 8839 section 5.4 requires at least 24 bits of randomness in the fragment and 128 bits in the password, both
/// drawn from the `ice-char` alphabet; [#generate()] draws 4 and 24 characters of 64 symbols, 24 and 144 bits.
/// [#toString()] leaves the password out.
///
/// @param usernameFragment the username fragment, 4 to 256 `ice-char` characters
/// @param password         the password, 22 to 256 `ice-char` characters, whose UTF-8 bytes key `MESSAGE-INTEGRITY`
/// @param lite             whether the agent is a lite implementation (`a=ice-lite`)
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
public record IceParameters(String usernameFragment, String password, boolean lite) {
    /// The `ice-char` alphabet: letters, digits, `+` and `/`.
    private static final String ICE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// The source of random parameters.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// Creates parameters.
    ///
    /// The lengths are not enforced, since peers in the field send shorter values than RFC 8839 allows; only empty
    /// values and characters outside `ice-char` are refused.
    ///
    /// @param usernameFragment the username fragment
    /// @param password         the password
    /// @param lite             whether the agent is lite
    /// @throws IllegalArgumentException if a value is empty or holds a character outside `ice-char`
    public IceParameters {
        Objects.requireNonNull(usernameFragment, "usernameFragment cannot be null");
        Objects.requireNonNull(password, "password cannot be null");
        requireIceChars(usernameFragment, "username fragment");
        requireIceChars(password, "password");
    }

    /// {@return fresh random parameters of a full agent, drawn from a [SecureRandom]}
    public static IceParameters generate() {
        return generate(false);
    }

    /// {@return fresh random parameters, drawn from a [SecureRandom]}
    ///
    /// @param lite whether the agent is lite
    public static IceParameters generate(boolean lite) {
        return new IceParameters(random(4), random(24), lite);
    }

    /// {@return the short-term `MESSAGE-INTEGRITY` key of the password}
    public StunKey key() {
        return StunKey.shortTerm(password);
    }

    /// {@return whether `other` has the same username fragment and password, so it continues the same ICE session}
    ///
    /// @param other the other parameters
    public boolean sameCredentials(IceParameters other) {
        return usernameFragment.equals(other.usernameFragment) && password.equals(other.password);
    }

    /// {@return a random `ice-char` string of `length` characters}
    private static String random(int length) {
        var builder = new StringBuilder(length);
        for (var i = 0; i < length; i++) {
            builder.append(ICE_CHARS.charAt(RANDOM.nextInt(ICE_CHARS.length())));
        }
        return builder.toString();
    }

    /// Fails unless `value` is a non-empty `ice-char` string.
    private static void requireIceChars(String value, String what) {
        if (value.isEmpty()) {
            throw new IllegalArgumentException("empty " + what);
        }
        for (var i = 0; i < value.length(); i++) {
            if (ICE_CHARS.indexOf(value.charAt(i)) < 0) {
                throw new IllegalArgumentException("invalid character in " + what);
            }
        }
    }

    /// {@return the username fragment and the lite flag, without the password}
    @Override
    public String toString() {
        return "IceParameters[usernameFragment=" + usernameFragment + ", lite=" + lite + "]";
    }
}
