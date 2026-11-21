package com.github.auties00.parley.peer;

import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceTransportState;

import java.net.URI;
import java.util.List;
import java.util.Objects;

/// An event of a [PeerConnection], the W3C `RTCPeerConnection` event handlers as one sealed hierarchy.
///
/// The events arrive through [PeerConnection#events()] or [PeerConnection#addListener(java.util.function.Consumer)],
/// in the order the connection raised them.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public sealed interface PeerConnectionEvent {
    /// The application should start an offer/answer exchange, the W3C `negotiationneeded` event: tracks, transceivers,
    /// directions or data channels changed since the last one, or an ICE restart was requested.
    record NegotiationNeeded() implements PeerConnectionEvent {
    }

    /// A local candidate was gathered and should be sent to the peer, the W3C `icecandidate` event.
    ///
    /// @param candidate the candidate, with the media section it belongs to
    record IceCandidate(IceCandidateInit candidate) implements PeerConnectionEvent {
        /// Creates the event.
        ///
        /// @param candidate the candidate
        public IceCandidate {
            Objects.requireNonNull(candidate, "candidate cannot be null");
        }
    }

    /// Every transport finished gathering, the W3C `icecandidate` event with a `null` candidate; a peer that does not
    /// trickle can now be sent [PeerConnection#localDescription()], which holds every candidate.
    record EndOfCandidates() implements PeerConnectionEvent {
    }

    /// A STUN or TURN server could not be used, the W3C `icecandidateerror` event.
    ///
    /// @param url       the server URL
    /// @param errorCode the STUN error code, or a value of 700 and above for a failure to reach the server
    /// @param errorText the reason
    record IceCandidateError(URI url, int errorCode, String errorText) implements PeerConnectionEvent {
        /// Creates the event.
        ///
        /// @param url       the server URL
        /// @param errorCode the error code
        /// @param errorText the reason
        public IceCandidateError {
            Objects.requireNonNull(url, "url cannot be null");
            Objects.requireNonNull(errorText, "errorText cannot be null");
        }
    }

    /// The aggregate candidate gathering state changed, the W3C `icegatheringstatechange` event.
    ///
    /// @param state the new state
    record IceGatheringStateChanged(IceGatheringState state) implements PeerConnectionEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public IceGatheringStateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// The aggregate ICE state changed, the W3C `iceconnectionstatechange` event.
    ///
    /// @param state the new state
    record IceConnectionStateChanged(IceTransportState state) implements PeerConnectionEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public IceConnectionStateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// The aggregate ICE and DTLS state changed, the W3C `connectionstatechange` event.
    ///
    /// @param state the new state
    record ConnectionStateChanged(PeerConnectionState state) implements PeerConnectionEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public ConnectionStateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// The signaling state changed, the W3C `signalingstatechange` event.
    ///
    /// @param state the new state
    record SignalingStateChanged(SignalingState state) implements PeerConnectionEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public SignalingStateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// The peer started sending on a media section, the W3C `track` event.
    ///
    /// @param receiver    the receiver whose track now carries media
    /// @param streams     the ids of the media streams the peer put the track in
    /// @param transceiver the transceiver of the receiver
    record Track(RtpReceiver receiver, List<String> streams, RtpTransceiver transceiver) implements PeerConnectionEvent {
        /// Creates the event, copying the list.
        ///
        /// @param receiver    the receiver
        /// @param streams     the stream ids
        /// @param transceiver the transceiver
        public Track {
            Objects.requireNonNull(receiver, "receiver cannot be null");
            streams = List.copyOf(streams);
            Objects.requireNonNull(transceiver, "transceiver cannot be null");
        }
    }

    /// The peer opened a data channel, the W3C `datachannel` event.
    ///
    /// @param channel the channel
    record DataChannel(com.github.auties00.parley.datachannel.DataChannel channel) implements PeerConnectionEvent {
        /// Creates the event.
        ///
        /// @param channel the channel
        public DataChannel {
            Objects.requireNonNull(channel, "channel cannot be null");
        }
    }
}
