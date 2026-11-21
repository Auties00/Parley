package com.github.auties00.parley.peer;

import com.github.auties00.parley.ice.IceCandidatePair;
import com.github.auties00.parley.ice.IceGatheringState;
import com.github.auties00.parley.ice.IceTransportState;

import java.util.Objects;

/// An event of a [PeerIceTransport], the W3C `RTCIceTransport` event handlers as one sealed hierarchy.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public sealed interface PeerIceTransportEvent {
    /// The ICE state changed, the W3C `statechange` event.
    ///
    /// @param state the new state
    record StateChanged(IceTransportState state) implements PeerIceTransportEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public StateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// The candidate gathering state changed, the W3C `gatheringstatechange` event.
    ///
    /// @param state the new state
    record GatheringStateChanged(IceGatheringState state) implements PeerIceTransportEvent {
        /// Creates the event.
        ///
        /// @param state the new state
        public GatheringStateChanged {
            Objects.requireNonNull(state, "state cannot be null");
        }
    }

    /// Another candidate pair was selected to carry the transport's traffic, the W3C `selectedcandidatepairchange`
    /// event.
    ///
    /// @param pair the selected pair
    record SelectedPairChanged(IceCandidatePair pair) implements PeerIceTransportEvent {
        /// Creates the event.
        ///
        /// @param pair the selected pair
        public SelectedPairChanged {
            Objects.requireNonNull(pair, "pair cannot be null");
        }
    }
}
