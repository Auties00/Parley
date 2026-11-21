package com.github.auties00.parley.sdp;

import java.util.regex.Pattern;

/// The patterns the SDP parsers split and check lines with, compiled once: `String.split` compiles a pattern of more
/// than one character on every call.
final class SdpPatterns {
    /// A line break, CRLF or a bare LF.
    static final Pattern LINE_BREAK = Pattern.compile("\r?\n");

    /// A run of spaces.
    static final Pattern SPACES = Pattern.compile(" +");

    /// A run of spaces and tabs.
    static final Pattern BLANKS = Pattern.compile("[ \t]+");

    /// A run of whitespace.
    static final Pattern WHITESPACE = Pattern.compile("\\s+");

    /// A fingerprint: uppercase hexadecimal bytes separated by colons.
    static final Pattern FINGERPRINT = Pattern.compile("[0-9A-F]{2}(:[0-9A-F]{2})*");

    private SdpPatterns() {
        throw new AssertionError("SdpPatterns cannot be instantiated");
    }
}
