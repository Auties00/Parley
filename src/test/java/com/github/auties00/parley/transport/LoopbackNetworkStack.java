package com.github.auties00.parley.transport;

import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.NetworkInterfaceAddress;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.net.StreamConnection;
import com.github.auties00.parley.net.StreamListener;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ThreadFactory;

/// A [NetworkStack] for tests with real UDP sockets from the JDK, standing in for the system stack the ice lane
/// provides; only UDP is implemented.
final class LoopbackNetworkStack implements NetworkStack {
    @Override
    public DatagramEndpoint bindUdp(InetSocketAddress local) throws IOException {
        var channel = DatagramChannel.open();
        channel.bind(local);
        return new DatagramEndpoint() {
            @Override
            public InetSocketAddress localAddress() {
                try {
                    return (InetSocketAddress) channel.getLocalAddress();
                } catch (IOException exception) {
                    throw new UncheckedIOException(exception);
                }
            }

            @Override
            public void send(ByteBuffer datagram, InetSocketAddress remote) throws IOException {
                channel.send(datagram.duplicate(), remote);
            }

            @Override
            public InetSocketAddress receive(ByteBuffer destination) throws IOException {
                return (InetSocketAddress) channel.receive(destination);
            }

            @Override
            public void close() {
                try {
                    channel.close();
                } catch (IOException ignored) {
                    // closing is best effort
                }
            }
        };
    }

    @Override
    public StreamConnection connectTcp(InetSocketAddress remote, Duration timeout) {
        throw new UnsupportedOperationException();
    }

    @Override
    public StreamConnection connectTls(InetSocketAddress remote, String serverName, Duration timeout) {
        throw new UnsupportedOperationException();
    }

    @Override
    public StreamListener listenTcp(InetSocketAddress local) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<NetworkInterfaceAddress> interfaceAddresses() {
        return List.of();
    }

    @Override
    public ThreadFactory threadFactory() {
        return Thread.ofVirtual().factory();
    }
}
