package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsAlert;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/// Why an established [MediaTransport] failed; reported once, in a [MediaTransportEvent.Failed], after the transport
/// closed itself.
public sealed interface MediaTransportFailure {
    /// {@return a description for logs}
    String message();

    /// The peer stopped answering consent checks, or ICE lost every candidate pair: the ICE transport moved to
    /// `failed` after the media path was established.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
    record ConsentExpired() implements MediaTransportFailure {
        @Override
        public String message() {
            return "the peer withdrew consent or stopped answering consent checks";
        }
    }

    /// No packet authenticated for the configured media timeout: the peer stopped sending, or its keys no longer match
    /// this side's. Packets that fail authentication never fail the transport by themselves, since anyone who can
    /// reach the port can send them; they only show up in `authenticationFailures`.
    ///
    /// @param silence                how long no packet authenticated, at least the configured media timeout
    /// @param authenticationFailures the packets that failed authentication during that time
    record MediaTimeout(Duration silence, long authenticationFailures) implements MediaTransportFailure {
        /// Creates the failure.
        ///
        /// @param silence                how long no packet authenticated
        /// @param authenticationFailures the packets that failed authentication meanwhile
        public MediaTimeout {
            Objects.requireNonNull(silence, "silence cannot be null");
        }

        @Override
        public String message() {
            return "no media authenticated for " + silence.toMillis() + " ms (" + authenticationFailures
                    + " packets failed SRTP authentication meanwhile)";
        }
    }

    /// The peer closed the DTLS association with `close_notify`.
    record DtlsClosedByPeer() implements MediaTransportFailure {
        @Override
        public String message() {
            return "the peer closed the DTLS association";
        }
    }

    /// The DTLS association failed after the handshake, for instance on a fatal alert from the peer.
    ///
    /// @param alert the alert, when one is known
    record DtlsFailed(Optional<DtlsAlert> alert) implements MediaTransportFailure {
        @Override
        public String message() {
            return alert.map(value -> "the DTLS association failed with " + value).orElse("the DTLS association failed");
        }
    }

    /// The datagram path failed: the socket could not be read any more.
    ///
    /// @param reason a description of the failure
    record PathFailed(String reason) implements MediaTransportFailure {
        @Override
        public String message() {
            return "the media path failed: " + reason;
        }
    }
}
