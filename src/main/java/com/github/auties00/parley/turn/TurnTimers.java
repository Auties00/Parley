package com.github.auties00.parley.turn;

import java.time.Duration;

/// The refresh intervals of a TURN allocation; tests shorten them.
///
/// @param allocationMargin  how long before an allocation expires it is refreshed (RFC 8656 section 7.1 suggests
///                          one minute); an allocation shorter than twice the margin is refreshed at half its lifetime
/// @param permissionRefresh the interval of permission refreshes, under the five-minute permission lifetime
/// @param channelRefresh    the interval of channel binding refreshes, under the ten-minute channel lifetime
/// @param closeTimeout      the longest time closing waits for the server to delete the allocation
record TurnTimers(Duration allocationMargin, Duration permissionRefresh, Duration channelRefresh, Duration closeTimeout) {
    /// The intervals of a real deployment: refresh one minute before expiry, permissions every four minutes,
    /// channels every nine.
    static final TurnTimers DEFAULT = new TurnTimers(Duration.ofSeconds(60), Duration.ofMinutes(4),
            Duration.ofMinutes(9), Duration.ofSeconds(1));
}
