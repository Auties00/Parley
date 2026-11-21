package com.github.auties00.parley.stun;

import java.util.Optional;

/// The STUN methods Parley sends and understands: Binding, and the TURN methods.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
public enum StunMethod {
    /// Binding, which reports the reflexive transport address and carries ICE connectivity checks.
    BINDING(0x001),

    /// TURN Allocate, which reserves a relayed transport address.
    ALLOCATE(0x003),

    /// TURN Refresh, which extends or deletes an allocation.
    REFRESH(0x004),

    /// TURN Send, the indication that relays data to a peer.
    SEND(0x006),

    /// TURN Data, the indication that carries data relayed from a peer.
    DATA(0x007),

    /// TURN CreatePermission, which lets a peer's IP address send to the relayed address.
    CREATE_PERMISSION(0x008),

    /// TURN ChannelBind, which binds a channel number to a peer.
    CHANNEL_BIND(0x009);

    /// The 12-bit method number.
    private final int code;

    /// Creates a method.
    StunMethod(int code) {
        this.code = code;
    }

    /// {@return the 12-bit method number}
    public int code() {
        return code;
    }

    /// {@return the method numbered `code`, or an empty optional for a method Parley does not know}
    ///
    /// @param code the 12-bit method number
    public static Optional<StunMethod> ofCode(int code) {
        for (var method : values()) {
            if (method.code == code) {
                return Optional.of(method);
            }
        }
        return Optional.empty();
    }
}
