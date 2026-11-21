package com.github.auties00.parley.rtp.session;

/// Forward error correction for a video stream: ULPFEC carried in RED on the media SSRC, as browsers send it, or
/// FlexFEC on its own SSRC.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
public sealed interface FecConfig {
    /// {@return the FEC packets generated per media packet, in percent, `0..100`}
    int protectionPercent();

    /// ULPFEC with RED: every media packet is sent inside RED, and the FEC packets are RED packets whose block
    /// carries the `ulpfec` payload type.
    ///
    /// @param redPayloadType    the payload type negotiated for `red`, `0..127`
    /// @param ulpfecPayloadType the payload type negotiated for `ulpfec`, `0..127`
    /// @param protectionPercent the FEC packets per media packet in percent, `0..100`; a receive stream ignores it
    record Ulpfec(int redPayloadType, int ulpfecPayloadType, int protectionPercent) implements FecConfig {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field is out of range
        public Ulpfec {
            SessionChecks.payloadType(redPayloadType, "redPayloadType");
            SessionChecks.payloadType(ulpfecPayloadType, "ulpfecPayloadType");
            SessionChecks.percent(protectionPercent);
        }
    }

    /// FlexFEC on its own SSRC, associated with the media SSRC by `a=ssrc-group:FEC-FR`.
    ///
    /// @param payloadType       the payload type negotiated for `flexfec` or `flexfec-03`, `0..127`
    /// @param ssrc              the FlexFEC SSRC, an unsigned 32-bit value
    /// @param draft03           whether the negotiated format is `flexfec-03`, the header layout browsers send,
    ///                          rather than RFC 8627
    /// @param protectionPercent the FEC packets per media packet in percent, `0..100`; a receive stream ignores it
    record Flexfec(int payloadType, long ssrc, boolean draft03, int protectionPercent) implements FecConfig {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field is out of range
        public Flexfec {
            SessionChecks.payloadType(payloadType, "payloadType");
            SessionChecks.ssrc(ssrc, "ssrc");
            SessionChecks.percent(protectionPercent);
        }
    }
}
