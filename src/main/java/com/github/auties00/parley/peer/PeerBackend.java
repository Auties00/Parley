package com.github.auties00.parley.peer;

import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelInit;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceProtocol;
import com.github.auties00.parley.ice.IceTransportState;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.stats.RtcStats;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/// The transport side of a peer connection: everything below the offer/answer exchange.
///
/// The JSEP engine decides what to run from the descriptions alone and tells the backend through these calls; the
/// backend reports transport events back through the [Listener] it was created with. [#apply(Negotiated, boolean)]
/// and [#close()] are called one at a time, without the connection's state lock held; the other calls may hold it.
/// No call blocks on the network.
interface PeerBackend extends AutoCloseable {
    /// Creates backends.
    @FunctionalInterface
    interface Factory {
        /// {@return a backend for a peer connection with `configuration` that reports to `listener`}
        PeerBackend create(Configuration configuration, Listener listener);
    }

    /// Receives the transport events of a backend; each method may be called from any thread.
    interface Listener {
        /// A local candidate was gathered on a transport.
        ///
        /// @param candidate     the attribute value without `candidate:`
        /// @param url           the STUN or TURN server it was gathered from, or an empty optional
        /// @param relayProtocol the protocol to the TURN server of a relayed candidate, or an empty optional
        void onLocalCandidate(String transportId, String candidate, Optional<URI> url,
                              Optional<IceProtocol> relayProtocol);

        /// The candidate gathering state of a transport changed.
        void onGatheringState(String transportId, IceGatheringState state);

        /// A STUN or TURN server could not be used.
        ///
        /// @param address the local address the request was sent from, or an empty optional
        /// @param port    the local port the request was sent from, or an empty optional
        void onCandidateError(String transportId, Optional<String> address, OptionalInt port, URI server,
                              int errorCode, String reason);

        /// The ICE state of a transport changed.
        void onIceState(String transportId, IceTransportState state);

        /// The DTLS state of a transport changed.
        void onDtlsState(String transportId, DtlsState state);

        /// The peer opened a data channel.
        void onDataChannel(DataChannel channel);

        /// A data channel, opened locally or by the peer, became open.
        void onDataChannelOpened();

        /// A data channel that was open closed.
        void onDataChannelClosed();

        /// The RTP session of a transport moved one of a sender's sources to another SSRC after a collision; the
        /// next offer must announce it.
        ///
        /// @param sender  the sender
        /// @param oldSsrc the SSRC given up
        /// @param newSsrc the SSRC used from now on
        void onSsrcChanged(RtpSender sender, long oldSsrc, long newSsrc);

        /// A transport failed for a reason neither ICE nor DTLS reports, such as its pacer stopping, so the
        /// connection is failed.
        ///
        /// @param transportId the transport
        void onTransportFailed(String transportId);
    }

    /// {@return the fingerprints of the local certificates, which every offer and answer carries}
    List<SdpAttribute.Fingerprint> fingerprints();

    /// Starts gathering candidates for a transport the local description introduces, with its local credentials.
    ///
    /// Called again with the same id after an ICE restart, with the new credentials.
    void startGathering(String transportId, Negotiated.IceCredentials credentials);

    /// Runs the outcome of an offer/answer exchange: creates, updates and closes transports and streams.
    ///
    /// @param negotiated  the outcome
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
    void updateJitterBufferTarget(RtpReceiver receiver, Optional<Duration> target);

    /// Asks the peer for a key frame on the streams of a receiver, or on its layer `rid`; does nothing before they
    /// exist.
    void requestKeyFrame(RtpReceiver receiver, Optional<String> rid);

    /// {@return the view of a transport's DTLS layer, or an empty optional when the transport does not run}
    Optional<PeerDtlsTransport> dtlsTransport(String transportId);

    /// {@return the view of the SCTP association, or an empty optional before a data section is negotiated}
    Optional<PeerSctpTransport> sctpTransport();

    /// Closes every transport; called once, by [PeerConnection#close()]. Never throws: each resource is closed on
    /// its own.
    @Override
    void close();
}
