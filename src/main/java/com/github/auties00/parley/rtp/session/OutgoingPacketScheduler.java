package com.github.auties00.parley.rtp.session;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;

/// Decides when each outgoing RTP packet of a session leaves: the hook a pacer plugs into.
///
/// The session hands every packet it produces (media, retransmissions, FEC) to [#schedule], together with the
/// [PacketSink] that sends it. The scheduler may send at once, as [#immediate()] does, or queue packets and drain
/// them at a paced rate by priority, as a congestion controller's pacer does. The sink stamps the transport-wide
/// sequence number and the absolute send time at the moment it is called, so a queued packet's congestion feedback
/// reflects when it actually left.
///
/// # Threading
///
/// [#schedule] is called on the thread that sends media (the application's) or the session's own threads
/// (retransmissions, FEC), possibly concurrently; it must not block for long. A sink may be called on any thread, at
/// most once per scheduled packet.
///
/// @implSpec An implementation must call [PacketSink#send(ByteBuffer)] (or [PacketSink#send(ByteBuffer, boolean)])
/// exactly once for every packet it does not drop, with the buffer it received, keeping the packets of one SSRC in
/// the order they were scheduled.
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
public interface OutgoingPacketScheduler {
    /// The priority classes of outgoing packets, highest first.
    enum Priority {
        /// Audio media.
        AUDIO,
        /// Retransmissions, RTX or plain.
        RETRANSMISSION,
        /// Video media.
        VIDEO,
        /// Forward error correction.
        FEC,
        /// Padding and probes.
        PADDING
    }

    /// Sends one scheduled packet: stamps its transport-wide sequence number and absolute send time, protects it and
    /// writes it to the transport.
    @FunctionalInterface
    interface PacketSink {
        /// Sends the packet as ordinary traffic.
        ///
        /// @param plainRtp the packet the scheduler received, positioned at its first byte with its limit after its
        ///                 last; it is protected in place, so the caller must not reuse it
        /// @throws IOException if the transport fails
        void send(ByteBuffer plainRtp) throws IOException;

        /// Sends the packet, telling the session whether it is part of a bandwidth probe.
        ///
        /// @implSpec The default implementation ignores `probe` and calls [#send(ByteBuffer)].
        ///
        /// @param plainRtp the packet
        /// @param probe    whether the packet belongs to a probe cluster
        /// @throws IOException if the transport fails
        default void send(ByteBuffer plainRtp, boolean probe) throws IOException {
            send(plainRtp);
        }
    }

    /// Produces padding when the scheduler needs bytes on the wire, such as to probe for bandwidth.
    @FunctionalInterface
    interface PaddingSource {
        /// Sends up to `targetBytes` of padding through the session's normal send path, preferring retransmissions
        /// of recent packets (useful padding) over padding-only packets.
        ///
        /// @param targetBytes the bytes wanted
        /// @param probe       whether the padding belongs to a probe cluster
        /// @return the bytes actually sent, possibly more than `targetBytes` by at most one packet, or `0` when the
        ///         session has no stream to pad on
        /// @throws IOException if the transport fails
        int sendPadding(int targetBytes, boolean probe) throws IOException;
    }

    /// Takes ownership of one packet and sends it through `sink`, now or later.
    ///
    /// @param plainRtp the unprotected packet with tailroom for SRTP after its limit; ownership passes to the
    ///                 scheduler
    /// @param priority the packet's priority class
    /// @param ssrc     the packet's SSRC
    /// @param sink     the sink that sends it
    void schedule(ByteBuffer plainRtp, Priority priority, long ssrc, PacketSink sink);

    /// Gives the scheduler the session's padding source, once, when the session is built.
    ///
    /// @implSpec The default implementation ignores it.
    ///
    /// @param source the padding source
    default void setPaddingSource(PaddingSource source) {
        Objects.requireNonNull(source, "source cannot be null");
    }

    /// {@return a scheduler that sends every packet at once on the scheduling thread}
    ///
    /// A transport failure is logged and the packet dropped, as a lost datagram would be.
    static OutgoingPacketScheduler immediate() {
        return ImmediateScheduler.INSTANCE;
    }
}
