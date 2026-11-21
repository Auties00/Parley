package com.github.auties00.parley.stun;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Optional;

/// An address family as STUN and TURN attributes number it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
public enum StunAddressFamily {
    /// IPv4, family `0x01`, 4-byte addresses.
    IPV4(0x01, 4),

    /// IPv6, family `0x02`, 16-byte addresses.
    IPV6(0x02, 16);

    /// The family number.
    private final int code;

    /// The address length in bytes.
    private final int addressLength;

    /// Creates a family.
    StunAddressFamily(int code, int addressLength) {
        this.code = code;
        this.addressLength = addressLength;
    }

    /// {@return the one-byte family number}
    public int code() {
        return code;
    }

    /// {@return the length of an address of this family, in bytes}
    public int addressLength() {
        return addressLength;
    }

    /// {@return the family numbered `code`, or an empty optional for an unknown number}
    ///
    /// @param code the family number
    public static Optional<StunAddressFamily> ofCode(int code) {
        return switch (code) {
            case 0x01 -> Optional.of(IPV4);
            case 0x02 -> Optional.of(IPV6);
            default -> Optional.empty();
        };
    }

    /// {@return the family of an address}
    ///
    /// @param address the address
    public static StunAddressFamily of(InetAddress address) {
        return address instanceof Inet4Address ? IPV4 : IPV6;
    }
}
