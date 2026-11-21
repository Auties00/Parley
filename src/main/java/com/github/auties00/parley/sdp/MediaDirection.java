package com.github.auties00.parley.sdp;

import java.util.Objects;
import java.util.Optional;

/// The media direction of a media section, the value of its `a=sendrecv`, `a=sendonly`, `a=recvonly` or `a=inactive`
/// attribute.
///
/// The direction is always stated from the point of view of the endpoint that wrote the description: `SENDONLY` in an
/// offer means the offerer sends and does not receive.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc3264.html RFC 3264: An Offer/Answer Model with the Session Description Protocol (SDP)
public enum MediaDirection {
    /// Sends and receives, `a=sendrecv`; the direction of a section that carries no direction attribute.
    SENDRECV("sendrecv", true, true),
    /// Sends only, `a=sendonly`.
    SENDONLY("sendonly", true, false),
    /// Receives only, `a=recvonly`.
    RECVONLY("recvonly", false, true),
    /// Neither sends nor receives, `a=inactive`.
    INACTIVE("inactive", false, false);

    /// The attribute name.
    private final String sdpName;
    /// Whether the writer sends.
    private final boolean sends;
    /// Whether the writer receives.
    private final boolean receives;

    MediaDirection(String sdpName, boolean sends, boolean receives) {
        this.sdpName = sdpName;
        this.sends = sends;
        this.receives = receives;
    }

    /// {@return the direction that sends when `send` is `true` and receives when `receive` is `true`}
    ///
    /// @param send    whether the direction sends
    /// @param receive whether the direction receives
    public static MediaDirection of(boolean send, boolean receive) {
        if (send) {
            return receive ? SENDRECV : SENDONLY;
        }
        return receive ? RECVONLY : INACTIVE;
    }

    /// {@return the direction whose attribute name is `name`, or an empty optional when `name` names none}
    ///
    /// @param name the attribute name, such as `sendonly`, compared case-sensitively
    public static Optional<MediaDirection> ofSdpName(String name) {
        Objects.requireNonNull(name, "name cannot be null");
        for (var direction : values()) {
            if (direction.sdpName.equals(name)) {
                return Optional.of(direction);
            }
        }
        return Optional.empty();
    }

    /// {@return the attribute name, such as `sendrecv`}
    public String sdpName() {
        return sdpName;
    }

    /// {@return whether the endpoint that wrote this direction sends media}
    public boolean sends() {
        return sends;
    }

    /// {@return whether the endpoint that wrote this direction receives media}
    public boolean receives() {
        return receives;
    }

    /// {@return this direction seen from the other endpoint: `SENDONLY` and `RECVONLY` swap, the others stay}
    public MediaDirection reverse() {
        return of(receives, sends);
    }

    /// {@return the direction that sends only when both this direction and `other` send, and receives only when both
    /// receive}
    ///
    /// @param other the other direction
    public MediaDirection intersect(MediaDirection other) {
        Objects.requireNonNull(other, "other cannot be null");
        return of(sends && other.sends, receives && other.receives);
    }
}
