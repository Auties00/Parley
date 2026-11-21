package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsAlert;

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

    /// A run of received packets failed SRTP authentication: the keys no longer match the peer's.
    ///
    /// @param consecutive the length of the run, at least the configured limit
    record SrtpAuthentication(int consecutive) implements MediaTransportFailure {
        @Override
        public String message() {
            return consecutive + " consecutive packets failed SRTP authentication";
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
