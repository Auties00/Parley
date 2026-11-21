package com.github.auties00.parley.cc;

import java.util.Objects;

/// What one encoding asks of a [BitrateAllocator], derived from its `RTCRtpEncodingParameters`.
///
/// @param key                   the encoding
/// @param active                whether the encoding is sending; an inactive encoding is allocated nothing
/// @param minBitrateBps         the lowest rate the encoding is useful at; below it the encoding is suspended
/// @param maxBitrateBps         the highest rate the encoding can use (`maxBitrate`, or the encoder's own ceiling)
/// @param priority              the relative share of spare bandwidth, positive; the W3C priorities `very-low`,
///                              `low`, `medium` and `high` map to `0.5`, `1`, `2` and `4`
/// @param scaleResolutionDownBy the encoding's downscale factor, at least `1`; among the encodings of one sender,
///                              those with the larger factor (smaller pictures) are filled first
///
/// @spec https://www.w3.org/TR/webrtc/#dom-rtcrtpencodingparameters WebRTC: Real-Time Communication in Browsers, RTCRtpEncodingParameters
public record EncodingDemand(AllocationKey key, boolean active, long minBitrateBps, long maxBitrateBps,
                             double priority, double scaleResolutionDownBy) {
    /// Validates the demand.
    ///
    /// @throws IllegalArgumentException if a rate is negative, `maxBitrateBps` is below `minBitrateBps`, `priority`
    ///                                  is not positive or `scaleResolutionDownBy` is below `1`
    public EncodingDemand {
        Objects.requireNonNull(key, "key");
        if (minBitrateBps < 0 || maxBitrateBps < minBitrateBps) {
            throw new IllegalArgumentException("rates must satisfy 0 <= min <= max: " + minBitrateBps + ", " + maxBitrateBps);
        }
        if (!(priority > 0) || Double.isInfinite(priority)) {
            throw new IllegalArgumentException("priority must be positive and finite: " + priority);
        }
        if (!(scaleResolutionDownBy >= 1) || Double.isInfinite(scaleResolutionDownBy)) {
            throw new IllegalArgumentException("scaleResolutionDownBy must be at least 1: " + scaleResolutionDownBy);
        }
    }
}
