package com.github.auties00.parley.rtp.session;

/// Redundant audio (RED) for a send stream: every packet repeats the previous `distance` frames, so a receiver
/// recovers isolated losses without a retransmission round trip.
///
/// @param payloadType the payload type negotiated for `red`, `0..127`
/// @param distance    how many earlier frames each packet repeats, `0..8`; `0` sends RED without redundancy
/// @spec https://www.rfc-editor.org/rfc/rfc2198.html RFC 2198: RTP Payload for Redundant Audio Data
public record RedConfig(int payloadType, int distance) {
    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if a field is out of range
    public RedConfig {
        SessionChecks.payloadType(payloadType, "payloadType");
        if (distance < 0 || distance > 8) {
            throw new IllegalArgumentException("distance must be in 0..8: " + distance);
        }
    }
}
