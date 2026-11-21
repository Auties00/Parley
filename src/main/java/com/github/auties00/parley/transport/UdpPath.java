package com.github.auties00.parley.transport;

import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.net.PacketReceiver;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.ThreadFactory;
import java.util.function.Consumer;

/// A [DatagramTransport] over one UDP endpoint to a remote address without ICE, for peers that signal a fixed media
/// address: SDES (`RTP/SAVP`) and DTLS-SRTP without ICE.
///
/// With latching on, the remote address follows the source of the last packet a higher layer confirmed as
/// authentic ([#confirmSource()], called from within a receiver), which lets media cross a NAT the peer is behind
/// (symmetric RTP); an unauthenticated packet never moves it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4961.html RFC 4961: Symmetric RTP / RTP Control Protocol (RTCP)
final class UdpPath implements DatagramTransport {
    private static final System.Logger LOGGER = System.getLogger(UdpPath.class.getName());

    /// The size budget of a datagram, the 1200 bytes WebRTC stacks assume cross any path.
    static final int MAX_DATAGRAM = 1200;

    /// The receive buffer size, large enough for any UDP payload a peer sends in practice.
    private static final int RECEIVE_BUFFER = 2048;

    /// The source of the datagram the reader thread is delivering, bound around each delivery.
    private static final ScopedValue<InetSocketAddress> SOURCE = ScopedValue.newInstance();

    /// A receiver that drops everything.
    private static final PacketReceiver DISCARD = (packet, arrivalNanos) -> {
    };

    /// The endpoint.
    private final DatagramEndpoint endpoint;

    /// The clock of arrival times.
    private final MonotonicClock clock;

    /// The callback for a fatal read failure.
    private final Consumer<IOException> failureHandler;

    /// The receiver.
    private volatile PacketReceiver receiver = DISCARD;

    /// The remote address, `null` before it is set.
    private volatile InetSocketAddress remote;

    /// Whether the remote address follows authenticated sources.
    private volatile boolean latching;

    /// Whether only datagrams from the remote address are delivered.
    private volatile boolean strict;

    /// Whether the path is closed.
    private volatile boolean closed;

    /// Creates a path and starts its reader thread.
    ///
    /// @param endpoint       the bound endpoint
    /// @param clock          the clock of arrival times
    /// @param threadFactory  the factory of the reader thread
    /// @param failureHandler called once when reading fails before the path was closed
    UdpPath(DatagramEndpoint endpoint, MonotonicClock clock, ThreadFactory threadFactory,
            Consumer<IOException> failureHandler) {
        this.endpoint = endpoint;
        this.clock = clock;
        this.failureHandler = failureHandler;
        threadFactory.newThread(this::readLoop).start();
    }

    /// Sets the remote address.
    ///
    /// @param remote   the address
    /// @param latching whether authenticated packets from another source move it
    /// @param strict   whether datagrams from other sources are dropped before any processing
    void connect(InetSocketAddress remote, boolean latching, boolean strict) {
        this.remote = Objects.requireNonNull(remote, "remote cannot be null");
        this.latching = latching;
        this.strict = strict;
    }

    /// Moves the remote address to the source of the datagram being delivered, when latching is on; called by a
    /// receiver once the datagram authenticated.
    void confirmSource() {
        if (latching && SOURCE.isBound()) {
            var source = SOURCE.get();
            if (!source.equals(remote)) {
                remote = source;
            }
        }
    }

    /// {@return the local address}
    InetSocketAddress localAddress() {
        return endpoint.localAddress();
    }

    /// {@return the remote address, or `null` before it is set}
    InetSocketAddress remoteAddress() {
        return remote;
    }

    @Override
    public void send(ByteBuffer datagram) throws IOException {
        var target = remote;
        if (target == null) {
            throw new IllegalStateException("the UDP path has no remote address yet");
        }
        endpoint.send(datagram, target);
    }

    @Override
    public void setReceiver(PacketReceiver receiver) {
        this.receiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    @Override
    public int maxDatagramSize() {
        return MAX_DATAGRAM;
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        endpoint.close();
    }

    /// Reads datagrams until the path closes.
    private void readLoop() {
        var buffer = ByteBuffer.allocate(RECEIVE_BUFFER);
        while (!closed) {
            InetSocketAddress source;
            try {
                buffer.clear();
                source = endpoint.receive(buffer);
            } catch (IOException exception) {
                if (!closed) {
                    closed = true;
                    failureHandler.accept(exception);
                }
                return;
            }
            buffer.flip();
            if (source == null || !buffer.hasRemaining()) {
                continue;
            }
            var target = remote;
            if (target == null || (strict && !source.equals(target))) {
                continue;
            }
            var arrival = clock.nanos();
            var current = receiver;
            try {
                ScopedValue.where(SOURCE, source).run(() -> current.receive(buffer, arrival));
            } catch (RuntimeException exception) {
                if (LOGGER.isLoggable(Level.WARNING)) {
                    LOGGER.log(Level.WARNING, "a media receiver failed", exception);
                }
            }
        }
    }
}
