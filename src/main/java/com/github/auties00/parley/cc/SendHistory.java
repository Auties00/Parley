package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;

import java.util.Optional;

/// The record of recently sent packets by transport-wide sequence number, which transport feedback is matched
/// against.
///
/// Sequence numbers are unwrapped to `long`; the history keeps the last [#CAPACITY] packets, about 13 seconds at
/// 2,500 packets per second, beyond which feedback could not be matched anyway since the 16-bit counter has wrapped
/// halfway.
final class SendHistory {
    /// The number of packets kept: half the 16-bit sequence space.
    static final int CAPACITY = 1 << 15;

    /// One sent packet.
    ///
    /// @param sequence  the unwrapped transport-wide sequence number
    /// @param sizeBytes the packet size
    /// @param sendNanos when it was sent
    /// @param priority  its priority class
    /// @param probe     the probe cluster it was part of, if any
    record SentPacket(long sequence, int sizeBytes, long sendNanos, OutgoingPacketScheduler.Priority priority,
                      Optional<ProbeCluster> probe) {
    }

    private final SentPacket[] packets;
    private final SequenceUnwrapper unwrapper;
    private long lastSequence;
    private boolean any;

    /// Creates an empty history.
    SendHistory() {
        this.packets = new SentPacket[CAPACITY];
        this.unwrapper = new SequenceUnwrapper(16);
    }

    /// Records a sent packet.
    ///
    /// @param sequence  the 16-bit transport-wide sequence number
    /// @param sizeBytes the packet size
    /// @param sendNanos when it was sent
    /// @param priority  its priority class
    /// @param probe     its probe cluster, if any
    void add(int sequence, int sizeBytes, long sendNanos, OutgoingPacketScheduler.Priority priority,
             Optional<ProbeCluster> probe) {
        var unwrapped = unwrapper.unwrap(sequence & 0xFFFF);
        packets[(int) (unwrapped & (CAPACITY - 1))] = new SentPacket(unwrapped, sizeBytes, sendNanos, priority, probe);
        if (!any || unwrapped > lastSequence) {
            lastSequence = unwrapped;
        }
        any = true;
    }

    /// {@return the unwrapped form of a 16-bit sequence number from feedback, nearest to the last sent one}
    ///
    /// @param sequence the 16-bit sequence number
    long unwrap(int sequence) {
        return any ? SequenceUnwrapper.nearest(lastSequence, sequence & 0xFFFF, 1 << 16) : sequence & 0xFFFF;
    }

    /// {@return the packet sent with the unwrapped sequence number, if it is still in the history}
    ///
    /// @param unwrappedSequence the unwrapped sequence number
    Optional<SentPacket> get(long unwrappedSequence) {
        if (!any || unwrappedSequence > lastSequence || lastSequence - unwrappedSequence >= CAPACITY) {
            return Optional.empty();
        }
        var packet = packets[(int) (unwrappedSequence & (CAPACITY - 1))];
        return packet != null && packet.sequence() == unwrappedSequence ? Optional.of(packet) : Optional.empty();
    }
}
