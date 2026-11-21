package com.github.auties00.parley.ice;

import com.github.auties00.parley.stun.StunRetransmission;

import java.time.Duration;

/// The timing constants of an ICE agent; tests shorten them.
///
/// @param pacing            `Ta`, the interval between two checks, 50 ms by default (RFC 8445 section 14.2)
/// @param checkRetransmission the retransmission schedule of a check over UDP; its `RTO` is raised to
///                          `Ta * (waiting + in-progress pairs)` when that is larger (RFC 8445 section 14.3)
/// @param reliableCheckTimeout how long a check over TCP waits for its response, `Ti`
/// @param nominationDelay   how long the controlling agent waits after the first valid pair for a better one before
///                          it nominates
/// @param consentInterval   the mean interval of consent checks, randomized by 0.8 to 1.2 (RFC 7675 section 5.1)
/// @param disconnectedAfter how long without a consent response before the transport is `DISCONNECTED`
/// @param consentExpiry     how long without a consent response before consent expires, 30 seconds
/// @param gatherTimeout     how long one STUN or TURN server may take to provide a candidate
/// @param resolveTimeout    how long the resolution of a remote `.local` candidate may take
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
/// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
record IceTimers(Duration pacing, StunRetransmission checkRetransmission, Duration reliableCheckTimeout,
                 Duration nominationDelay, Duration consentInterval, Duration disconnectedAfter,
                 Duration consentExpiry, Duration gatherTimeout, Duration resolveTimeout) {
    /// The timers RFC 8445 and RFC 7675 recommend.
    static final IceTimers DEFAULT = new IceTimers(Duration.ofMillis(50), StunRetransmission.UDP,
            Duration.ofMillis(39_500), Duration.ofMillis(500), Duration.ofSeconds(5), Duration.ofSeconds(10),
            Duration.ofSeconds(30), Duration.ofSeconds(5), Duration.ofSeconds(5));
}
