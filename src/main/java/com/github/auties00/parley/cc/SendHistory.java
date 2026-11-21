package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/// The record of recently sent packets, which congestion feedback is matched against: by transport-wide sequence
/// number for transport-wide feedback, and by SSRC and RTP sequence number for RFC 8888 feedback.
///
/// Transport-wide sequence numbers are unwrapped to `long`; the history keeps the last [#CAPACITY] of them, about 13
/// seconds at 2,500 packets per second, beyond which feedback could not be matched anyway since the 16-bit counter
/// has wrapped halfway. Per SSRC it keeps the last [#SSRC_CAPACITY] packets of at most [#MAX_SSRCS] SSRCs (local
/// send streams, so the bound is never reached in practice).
///
/// The history also counts the bytes in flight: packets that no feedback has reported yet, received or lost. A
/// packet that leaves the history unreported stops counting.
final class SendHistory {
    /// The packets kept by transport-wide sequence number: half the 16-bit sequence space.
    static final int CAPACITY = 1 << 15;

    /// The packets kept per SSRC for RFC 8888 feedback.
    static final int SSRC_CAPACITY = 1 << 12;

    /// The SSRCs kept for RFC 8888 feedback.
    static final int MAX_SSRCS = 64;

    /// One sent packet.
    ///
    /// @param sequence  the unwrapped transport-wide sequence number, or `-1` without one
    /// @param sizeBytes the packet size
    /// @param sendNanos when it was sent
    /// @param priority  its priority class
    /// @param probe     the probe cluster it was part of, if any
    record SentPacket(long sequence, int sizeBytes, long sendNanos, OutgoingPacketScheduler.Priority priority,
                      Optional<ProbeCluster> probe) {
    }

    /// The last packets of one SSRC, by RTP sequence number.
    private static final class SsrcRing {
        final SentPacket[] packets = new SentPacket[SSRC_CAPACITY];
        final int[] sequences = new int[SSRC_CAPACITY];
        final boolean[] reported = new boolean[SSRC_CAPACITY];
        long lastUse;
    }

    private final SentPacket[] packets;
    private final boolean[] reported;
    private final SequenceUnwrapper unwrapper;
    private final Map<Long, SsrcRing> bySsrc;
    private long lastSequence;
    private boolean any;
    private long bytesInFlight;
    private long uses;

    /// Creates an empty history.
    SendHistory() {
        this.packets = new SentPacket[CAPACITY];
        this.reported = new boolean[CAPACITY];
        this.unwrapper = new SequenceUnwrapper(16);
        this.bySsrc = new HashMap<>();
    }

    /// Records a sent packet.
    ///
    /// @param transportSequence the 16-bit transport-wide sequence number, or `-1` without one
    /// @param ssrc              the packet's SSRC
    /// @param rtpSequence       the packet's RTP sequence number
    /// @param sizeBytes         the packet size
    /// @param sendNanos         when it was sent
    /// @param priority          its priority class
    /// @param probe             its probe cluster, if any
    void add(int transportSequence, long ssrc, int rtpSequence, int sizeBytes, long sendNanos,
             OutgoingPacketScheduler.Priority priority, Optional<ProbeCluster> probe) {
        var unwrapped = transportSequence < 0 ? -1 : unwrapper.unwrap(transportSequence & 0xFFFF);
        var packet = new SentPacket(unwrapped, sizeBytes, sendNanos, priority, probe);
        if (unwrapped >= 0) {
            var slot = (int) (unwrapped & (CAPACITY - 1));
            var evicted = packets[slot];
            if (evicted != null && !reported[slot]) {
                bytesInFlight -= evicted.sizeBytes();
            }
            packets[slot] = packet;
            reported[slot] = false;
            bytesInFlight += sizeBytes;
            if (!any || unwrapped > lastSequence) {
                lastSequence = unwrapped;
            }
            any = true;
        }
        var ring = bySsrc.get(ssrc);
        if (ring == null) {
            if (bySsrc.size() >= MAX_SSRCS) {
                var stalest = bySsrc.entrySet().stream()
                        .min((left, right) -> Long.compare(left.getValue().lastUse, right.getValue().lastUse))
                        .orElseThrow().getKey();
                bySsrc.remove(stalest);
            }
            ring = new SsrcRing();
            bySsrc.put(ssrc, ring);
        }
        ring.lastUse = ++uses;
        var slot = rtpSequence & (SSRC_CAPACITY - 1);
        var evicted = ring.packets[slot];
        if (evicted != null && evicted.sequence() < 0 && !ring.reported[slot]) {
            bytesInFlight -= evicted.sizeBytes();
        }
        if (unwrapped < 0) {
            bytesInFlight += sizeBytes;
        }
        ring.packets[slot] = packet;
        ring.sequences[slot] = rtpSequence;
        ring.reported[slot] = false;
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
        if (!any || unwrappedSequence < 0 || unwrappedSequence > lastSequence
                || lastSequence - unwrappedSequence >= CAPACITY) {
            return Optional.empty();
        }
        var packet = packets[(int) (unwrappedSequence & (CAPACITY - 1))];
        return packet != null && packet.sequence() == unwrappedSequence ? Optional.of(packet) : Optional.empty();
    }

    /// Marks the packet with the unwrapped transport-wide sequence number reported by feedback, so it stops counting
    /// in flight.
    ///
    /// @param unwrappedSequence the unwrapped sequence number
    void markReported(long unwrappedSequence) {
        if (get(unwrappedSequence).isEmpty()) {
            return;
        }
        var slot = (int) (unwrappedSequence & (CAPACITY - 1));
        if (!reported[slot]) {
            reported[slot] = true;
            bytesInFlight -= packets[slot].sizeBytes();
        }
    }

    /// {@return the packet of one SSRC with an RTP sequence number, if it is still in the history and has not been
    /// reported by RFC 8888 feedback yet; reporting marks it so the next feedback repeating it is ignored}
    ///
    /// @param ssrc        the SSRC
    /// @param rtpSequence the RTP sequence number
    Optional<SentPacket> takeBySsrc(long ssrc, int rtpSequence) {
        var ring = bySsrc.get(ssrc);
        if (ring == null) {
            return Optional.empty();
        }
        var slot = rtpSequence & (SSRC_CAPACITY - 1);
        var packet = ring.packets[slot];
        if (packet == null || ring.sequences[slot] != rtpSequence || ring.reported[slot]) {
            return Optional.empty();
        }
        ring.reported[slot] = true;
        if (packet.sequence() >= 0) {
            markReported(packet.sequence());
        } else {
            bytesInFlight -= packet.sizeBytes();
        }
        return Optional.of(packet);
    }

    /// {@return the bytes sent and not yet reported by feedback}
    long bytesInFlight() {
        return bytesInFlight;
    }
}
