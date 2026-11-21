package com.github.auties00.parley.ice;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;

/// An event of an [IceAgent], delivered to the listener of its builder.
///
/// Events are delivered serially, in the order they happen, on one thread the agent starts; a listener that blocks
/// delays the events behind it but never the agent itself.
///
/// {@snippet lang = java :
/// IceAgent.builder().eventListener(event -> {
///     switch (event) {
///         case IceEvent.CandidateGathered(var candidate, var server) -> signaling.send(candidate.toSdp());
///         case IceEvent.GatheringStateChanged(var state) when state == IceGatheringState.COMPLETE -> signaling.endOfCandidates();
///         case IceEvent.StateChanged(var state) -> log(state);
///         default -> { }
///     }
/// });
/// }
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public sealed interface IceEvent {
    /// A local candidate was gathered and should be signalled to the peer (trickle ICE).
    ///
    /// @param candidate the candidate, with the local username fragment; a relayed one carries its
    ///                  [relay protocol][IceCandidate#relayProtocol()]
    /// @param server    the URL of the STUN or TURN server the candidate came from (W3C `RTCPeerConnectionIceEvent.url`),
    ///                  empty for a host candidate
    record CandidateGathered(IceCandidate candidate, Optional<URI> server) implements IceEvent {
        /// Creates the event.
        ///
        /// @param candidate the candidate
        /// @param server    the server URL
        public CandidateGathered {
            Objects.requireNonNull(candidate, "candidate cannot be null");
            Objects.requireNonNull(server, "server cannot be null");
        }
    }

    /// The gathering state changed; [IceGatheringState#COMPLETE] is the end-of-candidates indication to signal.
    ///
    /// @param state the new state
    record GatheringStateChanged(IceGatheringState state) implements IceEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public GatheringStateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// A STUN or TURN server failed to provide a candidate, as the W3C `icecandidateerror` event reports it.
    ///
    /// When the multicast DNS responder cannot be opened under [HostCandidatePolicy#MDNS], each host candidate is
    /// withheld rather than signalled under a name nobody answers for, and reported here with the server
    /// `mdns:224.0.0.251:5353` and the code `701`.
    ///
    /// @param server       the URL of the server
    /// @param localAddress the local address the request was sent from (W3C `address` and `port`), empty when it is
    ///                     not known, as for a TURN server reached over a connection that failed
    /// @param errorCode    the STUN error code of the server's response, or `701` when the server could not be reached
    /// @param reason       a description of the failure
    record CandidateError(URI server, Optional<InetSocketAddress> localAddress, int errorCode, String reason)
            implements IceEvent {
        /// The code of a server that could not be reached, from the W3C specification.
        public static final int UNREACHABLE = 701;

        /// Creates the event.
        ///
        /// @param server       the URL of the server
        /// @param localAddress the local address
        /// @param errorCode    the error code
        /// @param reason       a description
        public CandidateError {
            Objects.requireNonNull(server, "server cannot be null");
            Objects.requireNonNull(localAddress, "localAddress cannot be null");
            Objects.requireNonNull(reason, "reason cannot be null");
        }
    }

    /// The transport state changed.
    ///
    /// @param state the new state
    record StateChanged(IceTransportState state) implements IceEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public StateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// The pair the transport sends on changed.
    ///
    /// @param pair the new selected pair
    record SelectedPairChanged(IceCandidatePair pair) implements IceEvent {
        /// Creates the event.
        ///
        /// @param pair the new selected pair
        public SelectedPairChanged {
            Objects.requireNonNull(pair, "pair cannot be null");
        }
    }
}
