package com.github.auties00.parley.dtls;

import com.github.auties00.parley.sdp.SetupRole;

import java.util.Objects;
import java.util.Optional;

/// The role of an endpoint in a DTLS handshake.
///
/// A session description decides it through `a=setup` ([SetupRole]): the side that writes `active` is the client and
/// the side that writes `passive` the server ([#of(SetupRole)], [#local(SetupRole,SetupRole)]).
///
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
public enum DtlsRole {
    /// Sends the `ClientHello`.
    CLIENT,

    /// Answers the `ClientHello`.
    SERVER;

    /// {@return the role of the side that wrote an `a=setup` value, or an empty optional for `actpass` and `holdconn`}
    ///
    /// @param setup the value that side wrote
    public static Optional<DtlsRole> of(SetupRole setup) {
        return switch (Objects.requireNonNull(setup, "setup cannot be null")) {
            case ACTIVE -> Optional.of(CLIENT);
            case PASSIVE -> Optional.of(SERVER);
            case ACTPASS, HOLDCONN -> Optional.empty();
        };
    }

    /// {@return the local role once both sides have written their `a=setup` values}
    ///
    /// @param local  the value this side wrote
    /// @param remote the value the peer wrote
    /// @throws IllegalArgumentException if the pair does not decide a role: both definite and equal, both `actpass`, or
    ///                                  either `holdconn`
    public static DtlsRole local(SetupRole local, SetupRole remote) {
        var role = of(local).or(() -> of(remote).map(DtlsRole::opposite));
        if (local == SetupRole.HOLDCONN || remote == SetupRole.HOLDCONN || role.isEmpty() || of(remote).equals(role)) {
            throw new IllegalArgumentException("a=setup:" + local.sdpName() + " and a=setup:" + remote.sdpName()
                    + " do not decide a DTLS role");
        }
        return role.get();
    }

    /// {@return the role of the peer of an endpoint in this role}
    public DtlsRole opposite() {
        return this == CLIENT ? SERVER : CLIENT;
    }
}
