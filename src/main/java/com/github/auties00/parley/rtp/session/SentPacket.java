package com.github.auties00.parley.rtp.session;

import java.util.Objects;

/// One RTP packet that left the session, as a [TransportFeedbackObserver] learns of it.
///
/// @param transportSequence the transport-wide sequence number stamped on it, `0..65535`, or `-1` when the packet
///                          carries no transport-wide sequence extension (the extension was not negotiated, or the
///                          stream does not write it); only such a number lets transport-wide feedback name the
///                          packet
/// @param size              the packet's size before SRTP protection, header and padding included, in bytes
/// @param sendNanos         when it was written to the transport, in nanoseconds of the session's clock
/// @param priority          its priority class
/// @param retransmission    whether it repeats a packet already sent (an RTX or plain retransmission, or a padding
///                          packet built from the history)
/// @param ssrc              its SSRC, an unsigned 32-bit value
/// @param sequence          its RTP sequence number, `0..65535`, which RFC 8888 feedback names it by
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
public record SentPacket(int transportSequence, int size, long sendNanos, OutgoingPacketScheduler.Priority priority,
                         boolean retransmission, long ssrc, int sequence) {
    /// Validates the ranges.
    ///
    /// @throws IllegalArgumentException if a number is out of range
    public SentPacket {
        Objects.requireNonNull(priority, "priority cannot be null");
        if (transportSequence < -1 || transportSequence > 0xFFFF) {
            throw new IllegalArgumentException("transportSequence must be -1 or in 0..65535: " + transportSequence);
        }
        if (size < 0) {
            throw new IllegalArgumentException("size cannot be negative: " + size);
        }
        SessionChecks.ssrc(ssrc, "ssrc");
        if (sequence < 0 || sequence > 0xFFFF) {
            throw new IllegalArgumentException("sequence must be in 0..65535: " + sequence);
        }
    }

    /// {@return whether the packet carries a transport-wide sequence number}
    public boolean hasTransportSequence() {
        return transportSequence >= 0;
    }
}
