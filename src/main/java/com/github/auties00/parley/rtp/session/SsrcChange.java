package com.github.auties00.parley.rtp.session;

/// A local SSRC the session moved: after an SSRC collision with another source (RFC 3550 section 8.2), or a call to
/// [RtpSendStream#changeSsrc(long)].
///
/// The old SSRC was announced in a BYE; the signaling layer should list the new one in its next offer's `a=ssrc` and
/// `a=ssrc-group` lines.
///
/// @param oldSsrc the SSRC given up, an unsigned 32-bit value
/// @param newSsrc the SSRC used from now on, an unsigned 32-bit value
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public record SsrcChange(long oldSsrc, long newSsrc) {
    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if an SSRC is out of range or both are equal
    public SsrcChange {
        SessionChecks.ssrc(oldSsrc, "oldSsrc");
        SessionChecks.ssrc(newSsrc, "newSsrc");
        if (oldSsrc == newSsrc) {
            throw new IllegalArgumentException("the SSRC did not change: " + oldSsrc);
        }
    }
}
