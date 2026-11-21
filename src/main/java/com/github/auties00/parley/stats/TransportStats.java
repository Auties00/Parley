package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/// An ICE and DTLS transport, `transport`: one per BUNDLE group or unbundled media section.
///
/// @param id                           the identifier of this object
/// @param timestamp                    when the object was measured
/// @param packetsSent                  the packets sent over the transport
/// @param packetsReceived              the packets received over the transport
/// @param bytesSent                    the payload bytes sent, without IP, UDP or TURN overhead
/// @param bytesReceived                the payload bytes received, without IP, UDP or TURN overhead
/// @param iceRole                      the ICE role
/// @param iceLocalUsernameFragment     the local ICE username fragment in use, or an empty optional
/// @param iceState                     the ICE transport state
/// @param dtlsState                    the DTLS transport state
/// @param selectedCandidatePairId      the id of the selected [IceCandidatePairStats], or an empty optional before one is selected
/// @param selectedCandidatePairChanges how many times the selected pair changed
/// @param localCertificateId           the id of the local [CertificateStats], or an empty optional
/// @param remoteCertificateId          the id of the remote [CertificateStats], or an empty optional before the handshake
/// @param tlsVersion                   the negotiated DTLS version as the hex of its two wire bytes (`FEFD` for 1.2, `FEFC` for 1.3), or an empty optional
/// @param dtlsCipher                   the IANA name of the negotiated cipher suite, or an empty optional
/// @param dtlsRole                     the DTLS role, or an empty optional before it is known
/// @param srtpCipher                   the name of the negotiated SRTP protection profile, or an empty optional
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record TransportStats(String id, Instant timestamp, long packetsSent, long packetsReceived, long bytesSent,
                             long bytesReceived, IceRole iceRole, Optional<String> iceLocalUsernameFragment,
                             IceState iceState, DtlsState dtlsState, Optional<String> selectedCandidatePairId,
                             long selectedCandidatePairChanges, Optional<String> localCertificateId,
                             Optional<String> remoteCertificateId, Optional<String> tlsVersion,
                             Optional<String> dtlsCipher, Optional<DtlsRole> dtlsRole,
                             Optional<String> srtpCipher) implements RtcStats {
    /// The ICE role of a transport, the W3C `RTCIceRole`.
    public enum IceRole {
        /// `unknown`: Not yet decided.
        UNKNOWN("unknown"),
        /// `controlling`: The controlling agent.
        CONTROLLING("controlling"),
        /// `controlled`: The controlled agent.
        CONTROLLED("controlled");

        /// The W3C enumeration value.
        private final String value;

        IceRole(String value) {
            this.value = value;
        }

        /// {@return the W3C enumeration value}
        public String value() {
            return value;
        }
    }

    /// The ICE state of a transport, the W3C `RTCIceTransportState`.
    public enum IceState {
        /// `new`: Gathering or waiting for candidates.
        NEW("new"),
        /// `checking`: Checking pairs.
        CHECKING("checking"),
        /// `connected`: A usable pair is selected.
        CONNECTED("connected"),
        /// `completed`: Checks are finished.
        COMPLETED("completed"),
        /// `disconnected`: Consent was lost temporarily.
        DISCONNECTED("disconnected"),
        /// `failed`: Every pair failed.
        FAILED("failed"),
        /// `closed`: Closed.
        CLOSED("closed");

        /// The W3C enumeration value.
        private final String value;

        IceState(String value) {
            this.value = value;
        }

        /// {@return the W3C enumeration value}
        public String value() {
            return value;
        }
    }

    /// The DTLS state of a transport, the W3C `RTCDtlsTransportState`.
    public enum DtlsState {
        /// `new`: The handshake has not started.
        NEW("new"),
        /// `connecting`: Handshaking.
        CONNECTING("connecting"),
        /// `connected`: The handshake is done.
        CONNECTED("connected"),
        /// `closed`: Closed by either side.
        CLOSED("closed"),
        /// `failed`: The handshake or the fingerprint check failed.
        FAILED("failed");

        /// The W3C enumeration value.
        private final String value;

        DtlsState(String value) {
            this.value = value;
        }

        /// {@return the W3C enumeration value}
        public String value() {
            return value;
        }
    }

    /// The DTLS role of a transport, the W3C `RTCDtlsRole`.
    public enum DtlsRole {
        /// `client`: The DTLS client.
        CLIENT("client"),
        /// `server`: The DTLS server.
        SERVER("server");

        /// The W3C enumeration value.
        private final String value;

        DtlsRole(String value) {
            this.value = value;
        }

        /// {@return the W3C enumeration value}
        public String value() {
            return value;
        }
    }

    /// Creates the statistics object.
    public TransportStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(iceRole, "iceRole cannot be null");
        Objects.requireNonNull(iceLocalUsernameFragment, "iceLocalUsernameFragment cannot be null");
        Objects.requireNonNull(iceState, "iceState cannot be null");
        Objects.requireNonNull(dtlsState, "dtlsState cannot be null");
        Objects.requireNonNull(selectedCandidatePairId, "selectedCandidatePairId cannot be null");
        Objects.requireNonNull(localCertificateId, "localCertificateId cannot be null");
        Objects.requireNonNull(remoteCertificateId, "remoteCertificateId cannot be null");
        Objects.requireNonNull(tlsVersion, "tlsVersion cannot be null");
        Objects.requireNonNull(dtlsCipher, "dtlsCipher cannot be null");
        Objects.requireNonNull(dtlsRole, "dtlsRole cannot be null");
        Objects.requireNonNull(srtpCipher, "srtpCipher cannot be null");
    }

    /// {@return `TRANSPORT`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.TRANSPORT;
    }
}
