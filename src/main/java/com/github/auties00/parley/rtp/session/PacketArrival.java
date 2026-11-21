package com.github.auties00.parley.rtp.session;

import java.util.Objects;
import java.util.OptionalInt;

/// The arrival of one RTP packet, as a receive-side congestion controller needs it: transport-wide feedback reports
/// arrival times by transport-wide sequence number, and REMB estimates delay from the absolute send time.
///
/// @param ssrc              the packet's SSRC
/// @param sizeBytes         the packet's size, header and padding included
/// @param transportSequence the transport-wide sequence number, when the packet carried one
/// @param absSendTime       the 24-bit absolute send time, when the packet carried one
/// @param arrivalNanos      when the packet arrived, in nanoseconds of the session's clock
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
public record PacketArrival(long ssrc, int sizeBytes, OptionalInt transportSequence, OptionalInt absSendTime,
                            long arrivalNanos) {
    /// Checks the optional fields are not `null`.
    public PacketArrival {
        Objects.requireNonNull(transportSequence, "transportSequence cannot be null");
        Objects.requireNonNull(absSendTime, "absSendTime cannot be null");
    }
}
