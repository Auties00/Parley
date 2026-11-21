package com.github.auties00.parley.net;

import java.io.IOException;
import java.net.InetSocketAddress;

/// A listening TCP socket, as a [NetworkStack] opens it for passive ICE-TCP candidates.
public interface StreamListener extends AutoCloseable {
    /// {@return the local address and port the listener is bound to}
    InetSocketAddress localAddress();

    /// Accepts one connection, blocking until a peer connects.
    ///
    /// @return the connection
    /// @throws IOException if the listener is closed, before or while the call blocks
    StreamConnection accept() throws IOException;

    /// Closes the listener; a thread blocked in [#accept()] fails with an [IOException]. Connections already accepted
    /// stay open. Calling it again has no effect.
    @Override
    void close();
}
