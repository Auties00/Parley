package com.github.auties00.parley.turn;

import com.github.auties00.parley.stun.StunAddressFamily;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/// What an Allocate request asks the TURN server for.
///
/// @param family       the family of the relayed address; [StunAddressFamily#IPV6] adds `REQUESTED-ADDRESS-FAMILY`
/// @param lifetime     the lifetime to ask for, or an empty optional for the server's default (600 seconds)
/// @param dontFragment whether to send `DONT-FRAGMENT`, asking the server to set the DF bit towards peers; a server
///                     that does not understand it is asked again without it
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
public record TurnAllocationOptions(StunAddressFamily family, Optional<Duration> lifetime, boolean dontFragment) {
    /// An IPv4 relay with the server's default lifetime and no `DONT-FRAGMENT`.
    public static final TurnAllocationOptions IPV4 = new TurnAllocationOptions(StunAddressFamily.IPV4, Optional.empty(), false);

    /// An IPv6 relay with the server's default lifetime and no `DONT-FRAGMENT`.
    public static final TurnAllocationOptions IPV6 = new TurnAllocationOptions(StunAddressFamily.IPV6, Optional.empty(), false);

    /// Creates options.
    ///
    /// @param family       the family of the relayed address
    /// @param lifetime     the lifetime to ask for
    /// @param dontFragment whether to send `DONT-FRAGMENT`
    /// @throws IllegalArgumentException if `lifetime` is not positive
    public TurnAllocationOptions {
        Objects.requireNonNull(family, "family cannot be null");
        Objects.requireNonNull(lifetime, "lifetime cannot be null");
        if (lifetime.isPresent() && (lifetime.get().isNegative() || lifetime.get().isZero())) {
            throw new IllegalArgumentException("lifetime must be positive");
        }
    }

    /// {@return a copy of these options with `DONT-FRAGMENT` set as given}
    ///
    /// @param dontFragment whether to send `DONT-FRAGMENT`
    public TurnAllocationOptions withDontFragment(boolean dontFragment) {
        return new TurnAllocationOptions(family, lifetime, dontFragment);
    }
}
