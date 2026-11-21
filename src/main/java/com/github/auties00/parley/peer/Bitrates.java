package com.github.auties00.parley.peer;

/// The range congestion control keeps a connection's total send bitrate in, and where it starts.
///
/// @param minBps   the lowest bitrate congestion control goes to, in bits per second, positive
/// @param startBps the bitrate before the first estimate, in bits per second, at least `minBps`
/// @param maxBps   the highest bitrate congestion control goes to, in bits per second, at least `startBps`
public record Bitrates(long minBps, long startBps, long maxBps) {
    /// The defaults: between 30 kbit/s and 10 Mbit/s, starting at 300 kbit/s.
    public static final Bitrates DEFAULT = new Bitrates(30_000, 300_000, 10_000_000);

    /// Validates the range.
    ///
    /// @throws IllegalArgumentException unless `0 < minBps <= startBps <= maxBps`
    public Bitrates {
        if (minBps <= 0 || startBps < minBps || maxBps < startBps) {
            throw new IllegalArgumentException("bitrates must satisfy 0 < min <= start <= max: " + minBps + ", "
                    + startBps + ", " + maxBps);
        }
    }
}
