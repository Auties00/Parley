package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler;
import com.github.auties00.parley.rtp.session.SentPacket;
import com.github.auties00.parley.rtp.session.TransportFeedbackObserver;

import java.time.Duration;
import java.util.function.Consumer;

/// A send-side bandwidth estimator: observes every packet the RTP session sends and every piece of congestion
/// feedback it receives (transport-wide feedback, RFC 8888 congestion control feedback, REMB, receiver reports), and
/// turns them into a [TargetBitrate] for the encoders and a pacing rate for its [Pacer].
///
/// {@snippet lang = java :
/// var controller = CongestionController.gcc(CongestionConfig.defaults()
///         .withTargetListener(target -> allocator.allocate(target.bitsPerSecond(), demands)));
/// // give controller.pacer() to the RTP session as its OutgoingPacketScheduler,
/// // and the controller itself as its TransportFeedbackObserver
/// }
///
/// # Threading
///
/// Every method may be called from any thread. The target listener of the [CongestionConfig] is called on the thread
/// whose call changed the target, never while the controller holds a lock, and never concurrently with itself;
/// targets are delivered in the order they were computed.
///
/// @implSpec The RTP session must call [#onPacketSent(SentPacket)] synchronously from inside the
/// [OutgoingPacketScheduler.PacketSink#send(java.nio.ByteBuffer)] call the pacer made, which is how a packet sent as
/// part of a probe is attributed to its probe cluster.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
public sealed interface CongestionController extends TransportFeedbackObserver, AutoCloseable
        permits GoogleCongestionController {
    /// The queuing time the congestion window allows on top of one round trip at the target rate: 100 ms.
    Duration WINDOW_QUEUE_ALLOWANCE = Duration.ofMillis(100);

    /// Creates a Google Congestion Control estimator and starts its pacer.
    ///
    /// @param config the configuration, listeners included
    /// @return the controller
    static CongestionController gcc(CongestionConfig config) {
        return new GoogleCongestionController(config, true);
    }

    /// {@return the pacer every outgoing RTP packet should be scheduled on}
    Pacer pacer();

    /// {@return the current target}
    TargetBitrate currentTarget();

    /// {@return the bytes sent and not yet reported received or lost by feedback, the quantity the congestion window
    /// bounds}
    long bytesInFlight();

    /// Changes the highest target, as when the remote description's bandwidth line or the senders' `maxBitrate`
    /// change; raising it while the estimate sits at the old ceiling probes the new one.
    ///
    /// @param maxBitrateBps the new ceiling, at least the configured minimum
    /// @throws IllegalArgumentException if `maxBitrateBps` is below the configured minimum
    void setMaxBitrate(long maxBitrateBps);

    /// Stops the pacer and drops its queue. Idempotent.
    @Override
    void close();
}
