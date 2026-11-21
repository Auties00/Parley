package com.github.auties00.parley.turn;

import com.github.auties00.parley.stun.StunAddressFamily;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/// What an Allocate request asks the TURN server for, and where the allocation delivers relayed data.
///
/// Giving the receiver here means no datagram a peer relays can arrive before it is installed.
///
/// {@snippet lang = java :
/// var options = TurnAllocationOptions.IPV4
///         .receiver((peer, data, arrival) -> handle(peer, data))
///         .evenPort(true);
/// var allocation = client.allocate(options, Duration.ofSeconds(5));
/// }
///
/// @param family           the family of the relayed address; [StunAddressFamily#IPV6] adds `REQUESTED-ADDRESS-FAMILY`
/// @param lifetime         the lifetime to ask for, or an empty optional for the server's default (600 seconds)
/// @param dontFragment     whether to send `DONT-FRAGMENT`, asking the server to set the DF bit towards peers; a
///                         server that does not understand it is asked again without it, and Send indications carry
///                         it only when the allocation accepted it
/// @param evenPort         whether to send `EVEN-PORT`, asking for an even relayed port (RTP's, by RFC 3550
///                         convention)
/// @param reserveNextPort  whether `EVEN-PORT` also asks the server to reserve the next higher port, whose
///                         `RESERVATION-TOKEN` the allocation then reports; only with `evenPort`
/// @param reservationToken the token of a port reserved by an earlier allocation's `EVEN-PORT`, sent as
///                         `RESERVATION-TOKEN` to allocate that port; exclusive with `evenPort`
/// @param receiver         the receiver of datagrams relayed from peers, called on the client's reading thread;
///                         without one, relayed datagrams are dropped
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
public record TurnAllocationOptions(StunAddressFamily family, Optional<Duration> lifetime, boolean dontFragment,
                                    boolean evenPort, boolean reserveNextPort, OptionalLong reservationToken,
                                    Optional<TurnDataReceiver> receiver) {
    /// An IPv4 relay with the server's default lifetime, no `DONT-FRAGMENT` and no receiver.
    public static final TurnAllocationOptions IPV4 = new TurnAllocationOptions(StunAddressFamily.IPV4, Optional.empty(),
            false, false, false, OptionalLong.empty(), Optional.empty());

    /// An IPv6 relay with the server's default lifetime, no `DONT-FRAGMENT` and no receiver.
    public static final TurnAllocationOptions IPV6 = new TurnAllocationOptions(StunAddressFamily.IPV6, Optional.empty(),
            false, false, false, OptionalLong.empty(), Optional.empty());

    /// Creates options.
    ///
    /// @throws IllegalArgumentException if `lifetime` is not positive, `reserveNextPort` is set without `evenPort`,
    ///                                  or both `evenPort` and `reservationToken` are given (RFC 8656 section 7.2)
    public TurnAllocationOptions {
        Objects.requireNonNull(family, "family cannot be null");
        Objects.requireNonNull(lifetime, "lifetime cannot be null");
        Objects.requireNonNull(reservationToken, "reservationToken cannot be null");
        Objects.requireNonNull(receiver, "receiver cannot be null");
        if (lifetime.isPresent() && (lifetime.get().isNegative() || lifetime.get().isZero())) {
            throw new IllegalArgumentException("lifetime must be positive");
        }
        if (reserveNextPort && !evenPort) {
            throw new IllegalArgumentException("reserveNextPort needs evenPort");
        }
        if (evenPort && reservationToken.isPresent()) {
            throw new IllegalArgumentException("EVEN-PORT and RESERVATION-TOKEN cannot be combined");
        }
    }

    /// Creates options without `EVEN-PORT`, a reservation token or a receiver.
    ///
    /// @param family       the family of the relayed address
    /// @param lifetime     the lifetime to ask for
    /// @param dontFragment whether to send `DONT-FRAGMENT`
    /// @throws IllegalArgumentException if `lifetime` is not positive
    public TurnAllocationOptions(StunAddressFamily family, Optional<Duration> lifetime, boolean dontFragment) {
        this(family, lifetime, dontFragment, false, false, OptionalLong.empty(), Optional.empty());
    }

    /// {@return a copy of these options with `DONT-FRAGMENT` set as given}
    ///
    /// @param dontFragment whether to send `DONT-FRAGMENT`
    public TurnAllocationOptions withDontFragment(boolean dontFragment) {
        return new TurnAllocationOptions(family, lifetime, dontFragment, evenPort, reserveNextPort, reservationToken,
                receiver);
    }

    /// {@return a copy of these options asking for an even relayed port, and the next port reserved when
    /// `reserveNext` is set; any reservation token is dropped}
    ///
    /// @param reserveNext whether the next higher port is reserved too
    public TurnAllocationOptions evenPort(boolean reserveNext) {
        return new TurnAllocationOptions(family, lifetime, dontFragment, true, reserveNext, OptionalLong.empty(),
                receiver);
    }

    /// {@return a copy of these options allocating the port an earlier allocation reserved; `EVEN-PORT` is dropped}
    ///
    /// @param token the eight bytes of the `RESERVATION-TOKEN` the earlier allocation reported
    /// @throws IllegalArgumentException if `token` is not eight bytes long
    public TurnAllocationOptions reservationToken(byte[] token) {
        Objects.requireNonNull(token, "token cannot be null");
        if (token.length != 8) {
            throw new IllegalArgumentException("a reservation token is eight bytes: " + token.length);
        }
        return new TurnAllocationOptions(family, lifetime, dontFragment, false, false,
                OptionalLong.of(ByteBuffer.wrap(token).getLong()), receiver);
    }

    /// {@return a copy of these options delivering relayed datagrams to `receiver`}
    ///
    /// @param receiver the receiver, called on the client's reading thread
    public TurnAllocationOptions receiver(TurnDataReceiver receiver) {
        return new TurnAllocationOptions(family, lifetime, dontFragment, evenPort, reserveNextPort, reservationToken,
                Optional.of(Objects.requireNonNull(receiver, "receiver cannot be null")));
    }
}
