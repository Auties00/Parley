/// Provides the network plumbing every Parley layer shares: the [PacketReceiver] and [DatagramTransport] contracts
/// packets travel through, the [MonotonicClock] timers read, and the [NetworkStack] SPI through which Parley opens
/// every socket and starts every thread.
///
/// Packets are heap [java.nio.ByteBuffer]s positioned at the first byte with the limit at the last. A buffer handed
/// to a [PacketReceiver] is valid only for the duration of the call; a buffer passed to a `send` method may be reused
/// by the caller once the call returns. Times are nanoseconds of a [MonotonicClock] unless a type says otherwise.
///
/// [NetworkStack#system(java.util.concurrent.ThreadFactory)] is the stack backed by the JDK. An application supplies
/// its own stack to route connections through a proxy, to pick the interfaces candidates are gathered on, or to
/// simulate a lossy network in tests.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
package com.github.auties00.parley.net;
