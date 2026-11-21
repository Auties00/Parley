package com.github.auties00.parley.rtp;

import java.util.List;
import java.util.Objects;

/// The fixed header fields of an RTP packet, detached from its bytes.
///
/// @param payloadType      the payload type, `0..127`
/// @param marker           the marker bit, whose meaning the payload format defines (the last packet of a video
///                         frame, the first packet of a talkspurt)
/// @param sequence         the sequence number, `0..65535`
/// @param timestamp        the RTP timestamp, an unsigned 32-bit value in units of the payload clock rate
/// @param ssrc             the synchronization source, an unsigned 32-bit value
/// @param csrcs            the contributing sources, at most 15 unsigned 32-bit values
/// @param extensionProfile the 16-bit "defined by profile" field of the header extension: `0xBEDE` for one-byte
///                         elements, `0x1000..0x100F` for two-byte elements, or `0` when the packet has no
///                         extension
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public record RtpHeader(int payloadType, boolean marker, int sequence, long timestamp, long ssrc,
                        List<Long> csrcs, int extensionProfile) {
    /// Validates the ranges and copies `csrcs`.
    ///
    /// @throws IllegalArgumentException if a field is out of its range or there are more than 15 contributing
    ///                                  sources
    public RtpHeader {
        if (payloadType < 0 || payloadType > 127) {
            throw new IllegalArgumentException("payloadType must be in 0..127: " + payloadType);
        }
        if (sequence < 0 || sequence > 0xFFFF) {
            throw new IllegalArgumentException("sequence must be in 0..65535: " + sequence);
        }
        RtpPacket.checkUint32(timestamp, "timestamp");
        RtpPacket.checkUint32(ssrc, "ssrc");
        csrcs = List.copyOf(Objects.requireNonNull(csrcs, "csrcs cannot be null"));
        if (csrcs.size() > 15) {
            throw new IllegalArgumentException("at most 15 CSRCs: " + csrcs.size());
        }
        for (var csrc : csrcs) {
            RtpPacket.checkUint32(csrc, "csrc");
        }
        if (extensionProfile < 0 || extensionProfile > 0xFFFF) {
            throw new IllegalArgumentException("extensionProfile must be in 0..65535: " + extensionProfile);
        }
    }
}
