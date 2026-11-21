package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;

import java.nio.ByteBuffer;
import java.util.Objects;

/// One padding packet a [PaddingSource] produced.
///
/// @param plainRtp the unprotected RTP packet, positioned at its first byte with its limit at its end; ownership
///                 passes to the pacer
/// @param ssrc     the synchronization source of the packet (usually an RTX stream)
/// @param sink     where the pacer sends the packet
public record PaddingPacket(ByteBuffer plainRtp, long ssrc, OutgoingPacketScheduler.PacketSink sink) {
    /// Validates the packet.
    ///
    /// @throws IllegalArgumentException if `plainRtp` is empty or `ssrc` is not an unsigned 32-bit value
    public PaddingPacket {
        Objects.requireNonNull(plainRtp, "plainRtp");
        Objects.requireNonNull(sink, "sink");
        if (!plainRtp.hasRemaining()) {
            throw new IllegalArgumentException("plainRtp must not be empty");
        }
        if (ssrc < 0 || ssrc > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("ssrc must be an unsigned 32-bit value: " + ssrc);
        }
    }
}
