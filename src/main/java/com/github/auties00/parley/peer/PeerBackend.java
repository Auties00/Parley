package com.github.auties00.parley.peer;

import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelInit;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceTransportState;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.stats.RtcStats;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/// The transport side of a peer connection: everything below the offer/answer exchange.
///
/// The JSEP engine decides what to run from the descriptions alone and tells the backend through these calls; the
/// backend reports transport events back through the [Listener] it was created with. Every call is made with the peer
/// connection's operation lock held and must not block on the network.
interface PeerBackend extends AutoCloseable {
    /// Creates backends.
    @FunctionalInterface
    interface Factory {
        /// {@return a backend for a peer connection with `configuration` that reports to `listener`}
        PeerBackend create(Configuration configuration, Listener listener);
    }

    /// Receives the transport events of a backend; each method may be called from any thread.
    interface Listener {
        /// A local candidate was gathered on a transport; `candidate` is the attribute value without `candidate:`.
        void onLocalCandidate(String transportId, String candidate);

        /// The candidate gathering state of a transport changed.
        void onGatheringState(String transportId, IceGatheringState state);

        /// A STUN or TURN server could not be used.
        void onCandidateError(String transportId, URI server, int errorCode, String reason);

        /// The ICE state of a transport changed.
        void onIceState(String transportId, IceTransportState state);

        /// The DTLS state of a transport changed.
        void onDtlsState(String transportId, DtlsState state);

        /// The peer opened a data channel.
        void onDataChannel(DataChannel channel);
    }

    /// {@return the fingerprints of the local certificates, which every offer and answer carries}
    List<SdpAttribute.Fingerprint> fingerprints();

    /// Starts gathering candidates for a transport the local description introduces, with its local credentials.
    ///
    /// Called again with the same id after an ICE restart, with the new credentials.
    void startGathering(String transportId, Negotiated.IceCredentials credentials);

    /// Runs the outcome of an offer/answer exchange: creates, updates and closes transports and streams.
    ///
    /// @param negotiated the outcome
    /// @param finalAnswer whether the exchange ended with a final answer rather than a provisional one
    void apply(Negotiated negotiated, boolean finalAnswer);

    /// Hands a trickled remote candidate to a transport.
    ///
    /// @param transportId the transport
    /// @param candidate   the attribute value without `candidate:`
    void addRemoteCandidate(String transportId, String candidate);

    /// Tells a transport that the peer gathers no further candidates.
    void endOfRemoteCandidates(String transportId);

    /// {@return a data channel the application opens}
    ///
    /// The channel opens once the data section is negotiated and SCTP is established.
    DataChannel createDataChannel(String label, DataChannelInit init);

    /// {@return the statistics of the transports, streams and channels the backend runs, measured at `now`}
    List<RtcStats> statistics(Instant now);

    /// Applies new encoding parameters to the streams of a sender.
    void updateEncodings(RtpSender sender, List<Encoding> encodings);

    /// Applies a new jitter buffer target to a receiver.
    void updateJitterBufferTarget(RtpReceiver receiver, Optional<java.time.Duration> target);

    /// Closes every transport; called once, by [PeerConnection#close()].
    @Override
    void close();
}
