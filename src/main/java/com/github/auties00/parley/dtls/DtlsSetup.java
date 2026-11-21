package com.github.auties00.parley.dtls;

import java.util.Locale;
import java.util.Optional;

/// The values of the `a=setup` attribute, which decide which side of a DTLS association is the client.
///
/// An offer carries `actpass` (either role) or, rarely, a fixed role; the answer picks a definite role with
/// [#answerTo(DtlsSetup)], `active` by default as RFC 8842 recommends so the answerer can start the handshake at once.
/// [#role()] maps a definite value to the [DtlsRole] of the side that wrote it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc4145.html RFC 4145: TCP-Based Media Transport in the Session Description Protocol (SDP)
public enum DtlsSetup {
    /// `active`: the writer opens the association, as the DTLS client.
    ACTIVE,

    /// `passive`: the writer waits for the association, as the DTLS server.
    PASSIVE,

    /// `actpass`: the writer accepts either role; only valid in an offer.
    ACTPASS,

    /// `holdconn`: the writer does not want an association yet.
    HOLDCONN;

    /// {@return the setup value of an `a=setup` attribute, matched case-insensitively}
    ///
    /// @param sdpValue the attribute value
    /// @throws IllegalArgumentException if the value is none of the four
    public static DtlsSetup parse(String sdpValue) {
        return switch (sdpValue.trim().toLowerCase(Locale.ROOT)) {
            case "active" -> ACTIVE;
            case "passive" -> PASSIVE;
            case "actpass" -> ACTPASS;
            case "holdconn" -> HOLDCONN;
            default -> throw new IllegalArgumentException("unknown a=setup value " + sdpValue);
        };
    }

    /// {@return the `a=setup` attribute value}
    public String toSdp() {
        return name().toLowerCase(Locale.ROOT);
    }

    /// {@return the value an answerer writes for an offered value}
    ///
    /// `actpass` and `passive` are answered with `active`, `active` with `passive`, and `holdconn` with `holdconn`.
    ///
    /// @param offer the offered value
    public static DtlsSetup answerTo(DtlsSetup offer) {
        return switch (offer) {
            case ACTPASS, PASSIVE -> ACTIVE;
            case ACTIVE -> PASSIVE;
            case HOLDCONN -> HOLDCONN;
        };
    }

    /// {@return the DTLS role of the side that wrote this value, or an empty optional for `actpass` and `holdconn`}
    public Optional<DtlsRole> role() {
        return switch (this) {
            case ACTIVE -> Optional.of(DtlsRole.CLIENT);
            case PASSIVE -> Optional.of(DtlsRole.SERVER);
            case ACTPASS, HOLDCONN -> Optional.empty();
        };
    }

    /// {@return the local DTLS role once both sides have written their values}
    ///
    /// @param local  the value this side wrote
    /// @param remote the value the peer wrote
    /// @throws IllegalArgumentException if the pair does not decide a role: both definite and equal, both `actpass`, or
    ///                                  either `holdconn`
    public static DtlsRole localRole(DtlsSetup local, DtlsSetup remote) {
        var role = local.role().or(() -> remote.role().map(peer -> peer == DtlsRole.CLIENT ? DtlsRole.SERVER : DtlsRole.CLIENT));
        if (role.isEmpty() || remote.role().equals(role)) {
            throw new IllegalArgumentException("a=setup:" + local.toSdp() + " and a=setup:" + remote.toSdp()
                    + " do not decide a DTLS role");
        }
        return role.get();
    }
}
