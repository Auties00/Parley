package com.github.auties00.parley.rtp.fec;

/// The forward error correction formats Parley encodes and decodes.
///
/// All three protect packets by XOR parity over the same fields (the padding, extension and CSRC count bits, the
/// marker and payload type, the timestamp, the length after the fixed header, and every byte after the fixed
/// header); they differ in the FEC header and in how the packets an FEC packet protects are listed.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-payload-flexible-fec-scheme-03 draft-ietf-payload-flexible-fec-scheme-03: RTP Payload Format for Flexible Forward Error Correction (FEC)
public enum FecFormat {
    /// ULPFEC (RFC 5109) with one protection level: a 10-byte FEC header and a level header with a 16-bit or 48-bit
    /// mask, sent inside RED on the media SSRC.
    ULPFEC(48),
    /// FlexFEC as RFC 8627 specifies it with a flexible mask (`F = 0`): no SSRC list, the protected SSRC is the one
    /// signaled with `a=ssrc-group:FEC-FR`; sent on its own SSRC.
    FLEXFEC(109),
    /// FlexFEC as draft 03 specifies it, which browsers send for `flexfec-03`: like [#FLEXFEC] with an SSRC count and
    /// the protected SSRC in the header.
    FLEXFEC_03(109);

    private final int maxProtected;

    FecFormat(int maxProtected) {
        this.maxProtected = maxProtected;
    }

    /// {@return the largest span of sequence numbers one FEC packet can protect}
    public int maxProtected() {
        return maxProtected;
    }
}
