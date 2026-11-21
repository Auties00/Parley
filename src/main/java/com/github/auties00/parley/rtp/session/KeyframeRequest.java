package com.github.auties00.parley.rtp.session;

import java.util.Objects;

/// A keyframe request a peer sent for one of the local send streams.
///
/// @param method        whether the peer sent a PLI or a FIR
/// @param mediaSsrc     the local SSRC the request targets
/// @param requesterSsrc the SSRC of the peer that sent the request
/// @param arrivalNanos  when the request arrived, in nanoseconds of the session's clock
public record KeyframeRequest(KeyframeMethod method, long mediaSsrc, long requesterSsrc, long arrivalNanos) {
    /// Checks `method` is not `null`.
    public KeyframeRequest {
        Objects.requireNonNull(method, "method cannot be null");
    }
}
