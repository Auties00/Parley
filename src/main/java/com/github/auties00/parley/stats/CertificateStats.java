package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/// A DTLS certificate, `certificate`, local or presented by the peer.
///
/// @param id                   the identifier of this object
/// @param timestamp            when the object was measured
/// @param fingerprint          the fingerprint as upper-case hex bytes separated by colons
/// @param fingerprintAlgorithm the hash function of the fingerprint, such as `sha-256`
/// @param base64Certificate    the DER encoding of the certificate, base64
/// @param issuerCertificateId  the id of the issuer's certificate in a chain, or an empty optional
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record CertificateStats(String id, Instant timestamp, String fingerprint, String fingerprintAlgorithm,
                               String base64Certificate, Optional<String> issuerCertificateId) implements RtcStats {
    /// Creates the statistics object.
    public CertificateStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(fingerprint, "fingerprint cannot be null");
        Objects.requireNonNull(fingerprintAlgorithm, "fingerprintAlgorithm cannot be null");
        Objects.requireNonNull(base64Certificate, "base64Certificate cannot be null");
        Objects.requireNonNull(issuerCertificateId, "issuerCertificateId cannot be null");
    }

    /// {@return `CERTIFICATE`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.CERTIFICATE;
    }
}
