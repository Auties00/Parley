package com.github.auties00.parley.net;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ThreadFactory;

/// Opens every socket Parley uses and supplies every thread it starts.
///
/// ICE host candidates, STUN and TURN servers, ICE-TCP and the mDNS resolver all reach the network through the stack
/// an application passes, so an application can route TURN over TCP or TLS (and even UDP) through its own proxy or
/// tunnel, restrict the interfaces candidates are gathered on, or inject loss and delay in tests. [#system(ThreadFactory)]
/// is the stack backed by the JDK: `DatagramChannel`, `SocketChannel` and an `SSLEngine` for TLS.
///
/// {@snippet lang = java :
/// var stack = NetworkStack.system(Thread.ofVirtual().name("parley-net-", 0).factory());
/// var agent = IceAgent.builder()
///         .networkStack(stack)
///         .build();
/// }
///
/// @implSpec Implementations are safe for use by several threads at once. Every method that touches the network may
/// block the calling thread; the returned endpoints, connections and listeners follow the blocking contracts of
/// their types. An implementation that wraps the system stack delegates the methods it does not change.
public interface NetworkStack {
    /// Binds a UDP socket.
    ///
    /// @param local the local address and port to bind; port `0` picks an ephemeral port, and the wildcard address
    ///              binds every interface
    /// @return the bound endpoint
    /// @throws IOException if the socket cannot be bound
    DatagramEndpoint bindUdp(InetSocketAddress local) throws IOException;

    /// Opens a TCP connection.
    ///
    /// @param remote  the peer; an unresolved address is resolved by the stack, which lets a proxying stack hand
    ///                the host name to the proxy
    /// @param timeout the longest time the connection may take
    /// @return the connected stream
    /// @throws IOException if the connection fails or times out
    StreamConnection connectTcp(InetSocketAddress remote, Duration timeout) throws IOException;

    /// Opens a TLS connection over TCP, as a `turns:` server needs.
    ///
    /// @param remote     the peer; an unresolved address is resolved by the stack
    /// @param serverName the host name the server certificate must match, sent as the server name indication
    /// @param timeout    the longest time the connection and the handshake may take together
    /// @return the connected stream, with the handshake complete
    /// @throws IOException if the connection or the handshake fails or times out
    /// @see StreamConnection#startTls(StreamConnection,SSLContext,String,Duration,ThreadFactory)
    StreamConnection connectTls(InetSocketAddress remote, String serverName, Duration timeout) throws IOException;

    /// Opens a listening TCP socket.
    ///
    /// @param local the local address and port to bind; port `0` picks an ephemeral port
    /// @return the listener
    /// @throws IOException if the socket cannot be bound
    StreamListener listenTcp(InetSocketAddress local) throws IOException;

    /// {@return the addresses of the local network interfaces that are up, the source of host candidates}
    ///
    /// @throws IOException if the interfaces cannot be enumerated
    List<NetworkInterfaceAddress> interfaceAddresses() throws IOException;

    /// {@return the factory of every thread Parley starts on behalf of this stack: socket readers, timers and event
    /// dispatchers}
    ThreadFactory threadFactory();

    /// Resolves a host name, as STUN and TURN server URIs and remote candidates need.
    ///
    /// @implSpec The default implementation calls [InetAddress#getAllByName(String)].
    ///
    /// @param hostName the host name or IP literal
    /// @return the addresses, never empty
    /// @throws IOException if the name cannot be resolved
    default List<InetAddress> resolve(String hostName) throws IOException {
        Objects.requireNonNull(hostName, "hostName cannot be null");
        var addresses = InetAddress.getAllByName(hostName);
        if (addresses.length == 0) {
            throw new UnknownHostException(hostName);
        }
        return List.of(addresses);
    }

    /// {@return the stack backed by the JDK, verifying TLS servers against the JDK's default trust store}
    ///
    /// @param threadFactory the factory of every thread Parley starts, typically a virtual thread factory
    /// @throws IllegalStateException if the JDK has no default `SSLContext`
    static NetworkStack system(ThreadFactory threadFactory) {
        Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
        try {
            return new SystemNetworkStack(threadFactory, SSLContext.getDefault());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("no default SSLContext", exception);
        }
    }

    /// {@return the stack backed by the JDK, with TLS connections made through `context`}
    ///
    /// A `context` that trusts a private certificate authority or a self-signed certificate lets `turns:` reach a
    /// server the default trust store does not know.
    ///
    /// @param threadFactory the factory of every thread Parley starts
    /// @param context       the TLS context of [#connectTls(InetSocketAddress,String,Duration)]
    static NetworkStack system(ThreadFactory threadFactory, SSLContext context) {
        Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
        Objects.requireNonNull(context, "context cannot be null");
        return new SystemNetworkStack(threadFactory, context);
    }
}
