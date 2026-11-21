package com.github.auties00.parley.transport;

/// The SRTP settings of an [SrtpTransport] beyond its keys.
///
/// @param cryptex          whether RTP header extensions and CSRC lists are encrypted, as negotiated with
///                         `a=cryptex`; both sides must agree, and only the AES counter-mode and GCM suites support it
/// @param replayProtection whether received packets are checked against a 64-packet replay window per SSRC; turning it
///                         off is only for test tools and recorders that must see retransmitted duplicates
/// @spec https://www.rfc-editor.org/rfc/rfc9335.html RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources
/// @spec https://www.rfc-editor.org/rfc/rfc3711.html#section-3.3.2 RFC 3711: The Secure Real-time Transport Protocol (SRTP)
public record SrtpOptions(boolean cryptex, boolean replayProtection) {
    /// The defaults: no cryptex, replay protection on.
    public static final SrtpOptions DEFAULT = new SrtpOptions(false, true);

    /// {@return a copy with cryptex on or off}
    ///
    /// @param cryptex whether to encrypt header extensions and CSRCs
    public SrtpOptions withCryptex(boolean cryptex) {
        return new SrtpOptions(cryptex, replayProtection);
    }

    /// {@return a copy with replay protection on or off}
    ///
    /// @param replayProtection whether to reject replayed packets
    public SrtpOptions withReplayProtection(boolean replayProtection) {
        return new SrtpOptions(cryptex, replayProtection);
    }
}
