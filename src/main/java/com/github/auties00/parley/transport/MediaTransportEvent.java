package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.ice.IceEvent;

import java.util.Optional;

/// What a [MediaTransport] reports to its event listener, serially and in order.
public sealed interface MediaTransportEvent {
    /// An event of the ICE agent: a gathered candidate, a state change, a new selected pair.
    ///
    /// @param event the ICE event
    record Ice(IceEvent event) implements MediaTransportEvent {
    }

    /// A state change of the DTLS association.
    ///
    /// @param state the new state
    record DtlsStateChanged(DtlsState state) implements MediaTransportEvent {
    }

    /// The media path is keyed and carries SRTP.
    ///
    /// @param profile the SRTP profile a DTLS-SRTP handshake negotiated; empty for SDES keying
    record Established(Optional<SrtpProfile> profile) implements MediaTransportEvent {
    }

    /// The transport failed after it was established and has closed itself; the last event.
    ///
    /// @param failure why
    record Failed(MediaTransportFailure failure) implements MediaTransportEvent {
    }
}
