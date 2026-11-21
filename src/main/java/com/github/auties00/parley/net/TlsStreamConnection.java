package com.github.auties00.parley.net;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

/// A TLS client session run by an [SSLEngine] over another [StreamConnection].
///
/// Records are read and written through the lower stream, so the session works over any tunnel. One thread may read
/// while another writes: reading and writing take separate locks, and a read that must answer a post-handshake
/// message (a TLS 1.3 key update) takes the write lock for that answer.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
final class TlsStreamConnection implements StreamConnection {
    /// The stream the records travel over.
    private final StreamConnection lower;

    /// The engine.
    private final SSLEngine engine;

    /// The lock of the read side, which guards [#netIn] and [#appIn].
    private final Object readLock = new Object();

    /// The lock of the write side, which guards [#netOut].
    private final Object writeLock = new Object();

    /// Received record bytes not yet unwrapped, in write mode.
    private ByteBuffer netIn;

    /// Unwrapped application bytes not yet read, in read mode.
    private ByteBuffer appIn;

    /// Wrapped record bytes being written, in write mode.
    private ByteBuffer netOut;

    /// Whether [#close()] ran.
    private final AtomicBoolean closed = new AtomicBoolean();

    /// Creates a session over a connected stream; the handshake has not run.
    private TlsStreamConnection(StreamConnection lower, SSLEngine engine) {
        this.lower = lower;
        this.engine = engine;
        var session = engine.getSession();
        this.netIn = ByteBuffer.allocate(session.getPacketBufferSize());
        this.appIn = ByteBuffer.allocate(session.getApplicationBufferSize()).flip();
        this.netOut = ByteBuffer.allocate(session.getPacketBufferSize());
    }

    /// Runs the client handshake over `plain` and returns the session; see
    /// [StreamConnection#startTls(StreamConnection,SSLContext,String,Duration,ThreadFactory)].
    static TlsStreamConnection handshake(StreamConnection plain, SSLContext context, String serverName,
                                         Duration timeout, ThreadFactory threadFactory) throws IOException {
        SSLEngine engine;
        try {
            engine = context.createSSLEngine(serverName, plain.remoteAddress().getPort());
            engine.setUseClientMode(true);
            var parameters = engine.getSSLParameters();
            if (!isIpLiteral(serverName)) {
                parameters.setServerNames(List.of(new SNIHostName(serverName)));
            }
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(parameters);
        } catch (RuntimeException exception) {
            plain.close();
            throw new SSLException("cannot configure TLS for " + serverName, exception);
        }
        var connection = new TlsStreamConnection(plain, engine);
        var done = new AtomicBoolean();
        var expired = new AtomicBoolean();
        var deadline = System.nanoTime() + timeout.toNanos();
        var watchdog = threadFactory.newThread(() -> {
            while (!done.get()) {
                var left = deadline - System.nanoTime();
                if (left <= 0) {
                    expired.set(true);
                    closeQuietly(plain);
                    return;
                }
                LockSupport.parkNanos(left);
            }
        });
        watchdog.start();
        try {
            connection.runHandshake();
            return connection;
        } catch (IOException | RuntimeException exception) {
            closeQuietly(plain);
            if (expired.get()) {
                throw new SocketTimeoutException("TLS handshake with " + serverName + " timed out");
            }
            throw exception;
        } finally {
            done.set(true);
            LockSupport.unpark(watchdog);
        }
    }

    /// {@return whether `host` is an IPv4 or IPv6 literal, which server name indication must not carry}
    private static boolean isIpLiteral(String host) {
        try {
            InetAddress.ofLiteral(host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host);
            return true;
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    /// Drives the engine until the handshake finishes.
    private void runHandshake() throws IOException {
        engine.beginHandshake();
        while (true) {
            switch (engine.getHandshakeStatus()) {
                case NEED_WRAP -> {
                    synchronized (writeLock) {
                        wrapAndFlush(ByteBuffer.allocate(0));
                    }
                }
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    synchronized (readLock) {
                        if (unwrapOnce() < 0) {
                            throw new EOFException("the server closed the connection during the TLS handshake");
                        }
                    }
                }
                case NEED_TASK -> runTasks();
                case FINISHED, NOT_HANDSHAKING -> {
                    return;
                }
            }
        }
    }

    /// Runs the engine's delegated tasks on the calling thread.
    private void runTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    /// Unwraps one record into [#appIn], reading from the lower stream when no whole record is buffered; the caller
    /// holds [#readLock].
    ///
    /// @return the number of application bytes produced, or `-1` at the end of the stream
    private int unwrapOnce() throws IOException {
        while (true) {
            netIn.flip();
            appIn.compact();
            SSLEngineResult result;
            try {
                result = engine.unwrap(netIn, appIn);
            } finally {
                netIn.compact();
                appIn.flip();
            }
            switch (result.getStatus()) {
                case OK -> {
                    if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        runTasks();
                    }
                    return result.bytesProduced();
                }
                case BUFFER_UNDERFLOW -> {
                    var packetSize = engine.getSession().getPacketBufferSize();
                    if (netIn.capacity() < packetSize) {
                        netIn = ByteBuffer.allocate(packetSize).put(netIn.flip());
                    }
                    if (lower.read(netIn) < 0) {
                        return -1;
                    }
                }
                case BUFFER_OVERFLOW -> {
                    var size = engine.getSession().getApplicationBufferSize() + appIn.remaining();
                    appIn = ByteBuffer.allocate(size).put(appIn).flip();
                }
                case CLOSED -> {
                    return -1;
                }
            }
        }
    }

    /// Wraps `source` into records and writes them to the lower stream; the caller holds [#writeLock].
    ///
    /// @return the number of bytes of `source` consumed
    private int wrapAndFlush(ByteBuffer source) throws IOException {
        var consumed = 0;
        do {
            netOut.clear();
            var result = engine.wrap(source, netOut);
            switch (result.getStatus()) {
                case OK -> {
                    if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        runTasks();
                    }
                }
                case BUFFER_OVERFLOW -> {
                    netOut = ByteBuffer.allocate(engine.getSession().getPacketBufferSize() + netOut.capacity());
                    continue;
                }
                case BUFFER_UNDERFLOW -> throw new SSLException("unexpected TLS wrap underflow");
                case CLOSED -> {
                    if (result.bytesProduced() == 0) {
                        throw new SSLException("the TLS session is closed");
                    }
                }
            }
            consumed += result.bytesConsumed();
            netOut.flip();
            while (netOut.hasRemaining()) {
                lower.write(netOut);
            }
        } while (source.hasRemaining());
        return consumed;
    }

    @Override
    public int read(ByteBuffer destination) throws IOException {
        synchronized (readLock) {
            while (!appIn.hasRemaining()) {
                var produced = unwrapOnce();
                if (produced < 0) {
                    return -1;
                }
                if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    synchronized (writeLock) {
                        wrapAndFlush(ByteBuffer.allocate(0));
                    }
                }
            }
            var count = Math.min(destination.remaining(), appIn.remaining());
            destination.put(destination.position(), appIn, appIn.position(), count);
            destination.position(destination.position() + count);
            appIn.position(appIn.position() + count);
            return count;
        }
    }

    @Override
    public int write(ByteBuffer source) throws IOException {
        if (closed.get()) {
            throw new IOException("the TLS connection is closed");
        }
        synchronized (writeLock) {
            return wrapAndFlush(source);
        }
    }

    @Override
    public boolean isOpen() {
        return !closed.get() && lower.isOpen();
    }

    @Override
    public InetSocketAddress localAddress() {
        return lower.localAddress();
    }

    @Override
    public InetSocketAddress remoteAddress() {
        return lower.remoteAddress();
    }

    /// Sends `close_notify` when the session is still writable and closes the lower stream.
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        try {
            engine.closeOutbound();
            synchronized (writeLock) {
                wrapAndFlush(ByteBuffer.allocate(0));
            }
        } catch (IOException | RuntimeException _) {
            // The peer may already be gone; the lower stream is closed either way.
        } finally {
            closeQuietly(lower);
        }
    }

    /// Closes a stream, ignoring a failure.
    private static void closeQuietly(StreamConnection connection) {
        try {
            connection.close();
        } catch (IOException _) {
            // A failed close leaves nothing to release.
        }
    }
}
