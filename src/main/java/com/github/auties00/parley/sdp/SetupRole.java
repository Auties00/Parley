package com.github.auties00.parley.sdp;

import java.util.Objects;
import java.util.Optional;

/// The connection setup role of an `a=setup` attribute, which decides which endpoint starts the DTLS handshake.
///
/// An offer carries `ACTPASS`; the answer picks `ACTIVE` (the answerer is the DTLS client) or `PASSIVE` (the
/// answerer is the DTLS server).
///
/// @spec https://www.rfc-editor.org/rfc/rfc4145.html RFC 4145: TCP-Based Media Transport in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
public enum SetupRole {
    /// Starts the connection, `active`: the DTLS client.
    ACTIVE("active"),
    /// Accepts the connection, `passive`: the DTLS server.
    PASSIVE("passive"),
    /// Either role, `actpass`, as an offer states it.
    ACTPASS("actpass"),
    /// No connection now, `holdconn`; WebRTC never sends it.
    HOLDCONN("holdconn");

    /// The attribute value.
    private final String sdpName;

    SetupRole(String sdpName) {
        this.sdpName = sdpName;
    }

    /// {@return the role whose attribute value is `name`, or an empty optional when `name` names none}
    ///
    /// @param name the attribute value, such as `actpass`, compared case-sensitively
    public static Optional<SetupRole> ofSdpName(String name) {
        Objects.requireNonNull(name, "name cannot be null");
        for (var role : values()) {
            if (role.sdpName.equals(name)) {
                return Optional.of(role);
            }
        }
        return Optional.empty();
    }

    /// {@return the attribute value, such as `actpass`}
    public String sdpName() {
        return sdpName;
    }
}
