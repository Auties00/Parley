package com.github.auties00.parley.payload;

/// The settings of a [Packetizer].
///
/// @param maxPayloadSize the largest RTP payload the packetizer may produce, in bytes, at least
///                       {@value #MIN_PAYLOAD_SIZE}: the path MTU minus the IP, UDP, RTP header, header extension and
///                       SRTP overhead
public record PacketizerConfig(int maxPayloadSize) {
    /// The smallest accepted payload size, room for the largest payload descriptor plus some media.
    public static final int MIN_PAYLOAD_SIZE = 64;

    /// The payload size of [#defaults()]: what remains of a 1280-byte IPv6 minimum MTU after the IPv6 and UDP
    /// headers, an RTP header with a few header extensions and an SRTP tag, rounded down.
    public static final int DEFAULT_PAYLOAD_SIZE = 1100;

    /// Creates settings.
    ///
    /// @param maxPayloadSize the largest payload
    /// @throws IllegalArgumentException if `maxPayloadSize` is below {@value #MIN_PAYLOAD_SIZE}
    public PacketizerConfig {
        if (maxPayloadSize < MIN_PAYLOAD_SIZE) {
            throw new IllegalArgumentException("max payload size below " + MIN_PAYLOAD_SIZE + ": " + maxPayloadSize);
        }
    }

    /// {@return settings with a payload size of {@value #DEFAULT_PAYLOAD_SIZE} bytes}
    public static PacketizerConfig defaults() {
        return new PacketizerConfig(DEFAULT_PAYLOAD_SIZE);
    }
}
