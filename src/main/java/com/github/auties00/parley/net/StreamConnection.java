package com.github.auties00.parley.net;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ByteChannel;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ThreadFactory;

/// A connected, blocking byte stream to one peer: a TCP connection, a TLS session over one, or any tunnel an
/// application routes through (a proxy `CONNECT`, a SOCKS connection).
///
/// [#read(java.nio.ByteBuffer)] blocks until at least one byte arrives and returns `-1` at the end of the stream;
/// [#write(java.nio.ByteBuffer)] blocks until every remaining byte is written. One thread may read while another
/// writes.
public interface StreamConnection extends ByteChannel {
    /// {@return the local address of the connection}
    ///
    /// For a tunnelled connection this is the address the application chooses to report, such as the local end of
    /// the connection to the proxy.
    InetSocketAddress localAddress();

    /// {@return the address of the peer the connection reaches}
    ///
    /// For a tunnelled connection this is the final destination, not the proxy.
    InetSocketAddress remoteAddress();

    /// Runs a TLS client handshake over a connected stream and returns the encrypted connection.
    ///
    /// The handshake uses `context`'s default parameters with server name indication set to `serverName` and the
    /// `HTTPS` endpoint identification algorithm, so the server certificate must be trusted by `context` and match
    /// `serverName`. This lets a [NetworkStack] that tunnels TCP through a proxy implement
    /// [NetworkStack#connectTls(InetSocketAddress,String,Duration)] on top of its own
    /// [NetworkStack#connectTcp(InetSocketAddress,Duration)]. Closing the returned connection sends `close_notify` and
    /// closes `plain`.
    ///
    /// @param plain         the connected stream, which the returned connection owns from now on
    /// @param context       the TLS context
    /// @param serverName    the host name the certificate must match, sent as the server name indication
    /// @param timeout       the longest time the handshake may take; when it elapses `plain` is closed
    /// @param threadFactory the factory of the thread that enforces the timeout
    /// @return the TLS connection, with the handshake complete
    /// @throws IOException if the handshake fails or times out; `plain` is closed
    /// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
    /// @spec https://www.rfc-editor.org/rfc/rfc6066.html RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
    static StreamConnection startTls(StreamConnection plain, SSLContext context, String serverName, Duration timeout,
                                     ThreadFactory threadFactory) throws IOException {
        Objects.requireNonNull(plain, "plain cannot be null");
        Objects.requireNonNull(context, "context cannot be null");
        Objects.requireNonNull(serverName, "serverName cannot be null");
        Objects.requireNonNull(timeout, "timeout cannot be null");
        Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
        return TlsStreamConnection.handshake(plain, context, serverName, timeout, threadFactory);
    }
}
