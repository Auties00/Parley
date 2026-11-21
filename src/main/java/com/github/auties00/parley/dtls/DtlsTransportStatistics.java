package com.github.auties00.parley.dtls;

import java.util.Optional;

/// A snapshot of the state and counters of a [DtlsTransport], the material of the W3C `RTCTransportStats` DTLS
/// members.
///
/// The byte and packet counters count datagrams of DTLS records only; RTP and RTCP that pass through the transport to
/// its non-DTLS receiver are counted by the SRTP layer.
///
/// @param state                  the current state
/// @param role                   the handshake role, absent before the handshake started
/// @param version                the negotiated version, absent before the `ServerHello`
/// @param cipherSuite            the IANA name of the negotiated cipher suite, such as
///                               `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, absent before the `ServerHello`
/// @param srtpProfile            the negotiated SRTP profile, absent before it is agreed or when none is
/// @param bytesSent              the bytes of DTLS datagrams sent
/// @param bytesReceived          the bytes of DTLS datagrams received
/// @param packetsSent            the DTLS datagrams sent
/// @param packetsReceived        the DTLS datagrams received
/// @param retransmissions        the handshake flights sent again
/// @param recordsDropped         the records discarded as malformed, replayed, from an unknown epoch or failing
///                               authentication
/// @param authenticationFailures the records, among [#recordsDropped()], that failed authentication
/// @spec https://www.w3.org/TR/webrtc-stats/#transportstats-dict* Identifiers for WebRTC's Statistics API
public record DtlsTransportStatistics(DtlsState state, Optional<DtlsRole> role, Optional<DtlsVersion> version,
                                      Optional<String> cipherSuite, Optional<SrtpProfile> srtpProfile, long bytesSent,
                                      long bytesReceived, long packetsSent, long packetsReceived, long retransmissions,
                                      long recordsDropped, long authenticationFailures) {
    /// Creates a snapshot.
    ///
    /// @param state                  the current state
    /// @param role                   the handshake role
    /// @param version                the negotiated version
    /// @param cipherSuite            the negotiated cipher suite name
    /// @param srtpProfile            the negotiated SRTP profile
    /// @param bytesSent              the bytes sent
    /// @param bytesReceived          the bytes received
    /// @param packetsSent            the datagrams sent
    /// @param packetsReceived        the datagrams received
    /// @param retransmissions        the flights sent again
    /// @param recordsDropped         the records discarded
    /// @param authenticationFailures the records failing authentication
    public DtlsTransportStatistics {
        java.util.Objects.requireNonNull(state, "state cannot be null");
        java.util.Objects.requireNonNull(role, "role cannot be null");
        java.util.Objects.requireNonNull(version, "version cannot be null");
        java.util.Objects.requireNonNull(cipherSuite, "cipherSuite cannot be null");
        java.util.Objects.requireNonNull(srtpProfile, "srtpProfile cannot be null");
    }
}
