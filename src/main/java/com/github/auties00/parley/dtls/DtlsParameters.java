package com.github.auties00.parley.dtls;

import com.github.auties00.parley.sdp.SetupRole;

import java.util.List;
import java.util.Optional;

/// The DTLS attributes one side of a session description carries for a media transport: `a=setup`, the
/// `a=fingerprint` lines and `a=tls-id`.
///
/// Comparing the parameters of a new description with those of the previous one tells whether the existing
/// association continues or a new handshake must run ([#requiresNewAssociation(DtlsParameters)]), and the
/// fingerprints are what [DtlsTransport#handshake(DtlsRole,List,java.time.Duration)] checks the peer's certificate
/// against.
///
/// @param setup        the `a=setup` value
/// @param fingerprints the `a=fingerprint` values, unmodifiable and not empty
/// @param tlsId        the `a=tls-id` value, absent when the description has none
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
public record DtlsParameters(SetupRole setup, List<DtlsFingerprint> fingerprints, Optional<DtlsTlsId> tlsId) {
    /// Creates the parameters, copying the fingerprints.
    ///
    /// @param setup        the `a=setup` value
    /// @param fingerprints the `a=fingerprint` values
    /// @param tlsId        the `a=tls-id` value, or an empty optional
    /// @throws IllegalArgumentException if `fingerprints` is empty
    public DtlsParameters {
        java.util.Objects.requireNonNull(setup, "setup cannot be null");
        fingerprints = List.copyOf(fingerprints);
        java.util.Objects.requireNonNull(tlsId, "tlsId cannot be null");
        if (fingerprints.isEmpty()) {
            throw new IllegalArgumentException("a DTLS transport needs at least one fingerprint");
        }
    }

    /// {@return whether these parameters, from a new description, require a new DTLS association instead of the one
    /// negotiated with `previous`}
    ///
    /// When both descriptions carry `a=tls-id`, a different value requires a new association and an equal one keeps
    /// it. Otherwise a change of the fingerprints requires one, as does a change between the two definite roles.
    ///
    /// @param previous the parameters the current association was negotiated with
    public boolean requiresNewAssociation(DtlsParameters previous) {
        if (tlsId.isPresent() && previous.tlsId.isPresent()) {
            return !tlsId.equals(previous.tlsId);
        }
        if (!java.util.Set.copyOf(fingerprints).equals(java.util.Set.copyOf(previous.fingerprints))) {
            return true;
        }
        var role = DtlsRole.of(setup);
        var previousRole = DtlsRole.of(previous.setup);
        return role.isPresent() && previousRole.isPresent() && !role.equals(previousRole);
    }
}
