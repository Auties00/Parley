package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsTransportStatistics;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// A snapshot of the counters of a [MediaTransport] and its layers.
///
/// @param rtp            the SRTP counters, absent before the transport was established
/// @param dtls           the DTLS counters, absent unless DTLS-SRTP keys the transport
/// @param lastMediaNanos the clock time the last authenticated RTP or RTCP packet arrived, absent before any
public record MediaTransportStatistics(Optional<RtpTransportStatistics> rtp, Optional<DtlsTransportStatistics> dtls,
                                       OptionalLong lastMediaNanos) {
    /// Creates a snapshot.
    ///
    /// @param rtp            the SRTP counters
    /// @param dtls           the DTLS counters
    /// @param lastMediaNanos the last media arrival
    public MediaTransportStatistics {
        Objects.requireNonNull(rtp, "rtp cannot be null");
        Objects.requireNonNull(dtls, "dtls cannot be null");
        Objects.requireNonNull(lastMediaNanos, "lastMediaNanos cannot be null");
    }
}
