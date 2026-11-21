package com.github.auties00.parley.net;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ThreadFactory;
import java.util.regex.Pattern;

/// The [NetworkStack] backed by the JDK's blocking NIO channels.
final class SystemNetworkStack implements NetworkStack {
    /// The receive buffer size asked for each UDP socket, large enough to absorb a burst of video packets.
    private static final int RECEIVE_BUFFER = 1 << 20;

    /// Interface names that denote tunnels and virtual adapters on Linux, macOS, BSD and Windows.
    private static final Pattern VIRTUAL_NAME = Pattern.compile("^(tun|tap|utun|ppp|wg|ipsec|zt|gif|stf|vboxnet|vmnet|docker|br-|veth|virbr).*");

    /// The factory of every thread this stack starts.
    private final ThreadFactory threadFactory;

    /// The TLS context of [#connectTls(InetSocketAddress,String,Duration)].
    private final SSLContext context;

    /// Creates the stack.
    SystemNetworkStack(ThreadFactory threadFactory, SSLContext context) {
        this.threadFactory = threadFactory;
        this.context = context;
    }

    @Override
    public DatagramEndpoint bindUdp(InetSocketAddress local) throws IOException {
        var address = local.getAddress();
        var channel = address == null || address.isAnyLocalAddress()
                ? DatagramChannel.open()
                : DatagramChannel.open(address instanceof Inet6Address ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET);
        try {
            channel.setOption(StandardSocketOptions.SO_RCVBUF, RECEIVE_BUFFER);
            channel.bind(local);
            return new ChannelDatagramEndpoint(channel);
        } catch (IOException | RuntimeException exception) {
            channel.close();
            throw exception;
        }
    }

    @Override
    public StreamConnection connectTcp(InetSocketAddress remote, Duration timeout) throws IOException {
        var resolved = remote.isUnresolved()
                ? new InetSocketAddress(resolve(remote.getHostString()).getFirst(), remote.getPort())
                : remote;
        var channel = SocketChannel.open();
        try {
            channel.setOption(StandardSocketOptions.TCP_NODELAY, true);
            var millis = (int) Math.max(1, Math.min(Integer.MAX_VALUE, timeout.toMillis()));
            channel.socket().connect(resolved, millis);
            return new ChannelStreamConnection(channel);
        } catch (SocketTimeoutException exception) {
            channel.close();
            throw new SocketTimeoutException("connection to " + resolved + " timed out");
        } catch (IOException | RuntimeException exception) {
            channel.close();
            throw exception;
        }
    }

    @Override
    public StreamConnection connectTls(InetSocketAddress remote, String serverName, Duration timeout) throws IOException {
        var start = System.nanoTime();
        var plain = connectTcp(remote, timeout);
        var left = Duration.ofNanos(Math.max(1, timeout.toNanos() - (System.nanoTime() - start)));
        return TlsStreamConnection.handshake(plain, context, serverName, left, threadFactory);
    }

    @Override
    public StreamListener listenTcp(InetSocketAddress local) throws IOException {
        var channel = ServerSocketChannel.open();
        try {
            channel.bind(local);
            return new ChannelStreamListener(channel);
        } catch (IOException | RuntimeException exception) {
            channel.close();
            throw exception;
        }
    }

    @Override
    public List<NetworkInterfaceAddress> interfaceAddresses() throws IOException {
        var result = new ArrayList<NetworkInterfaceAddress>();
        var interfaces = NetworkInterface.networkInterfaces().toList();
        for (var networkInterface : interfaces) {
            if (!networkInterface.isUp()) {
                continue;
            }
            var name = networkInterface.getName();
            var display = networkInterface.getDisplayName() == null ? "" : networkInterface.getDisplayName().toLowerCase(Locale.ROOT);
            var virtual = networkInterface.isVirtual()
                    || networkInterface.isPointToPoint()
                    || VIRTUAL_NAME.matcher(name.toLowerCase(Locale.ROOT)).matches()
                    || display.contains("vpn")
                    || display.contains("virtual")
                    || display.contains("tunnel");
            for (var interfaceAddress : networkInterface.getInterfaceAddresses()) {
                var address = interfaceAddress.getAddress();
                if (address == null) {
                    continue;
                }
                var prefix = Math.clamp(interfaceAddress.getNetworkPrefixLength(), 0, address.getAddress().length * 8);
                result.add(new NetworkInterfaceAddress(name, address, prefix, address.isLoopbackAddress(),
                        address.isLinkLocalAddress(), virtual));
            }
        }
        return List.copyOf(result);
    }

    @Override
    public ThreadFactory threadFactory() {
        return threadFactory;
    }

    /// A UDP endpoint over a blocking [DatagramChannel].
    private record ChannelDatagramEndpoint(DatagramChannel channel) implements DatagramEndpoint {
        @Override
        public InetSocketAddress localAddress() {
            try {
                return (InetSocketAddress) channel.getLocalAddress();
            } catch (IOException exception) {
                return new InetSocketAddress(0);
            }
        }

        @Override
        public void send(ByteBuffer datagram, InetSocketAddress remote) throws IOException {
            channel.send(datagram, remote);
        }

        @Override
        public boolean setTrafficClass(int dscp) {
            if (dscp < 0 || dscp > 63) {
                throw new IllegalArgumentException("dscp must be in 0..63: " + dscp);
            }
            try {
                channel.setOption(StandardSocketOptions.IP_TOS, dscp << 2);
                return true;
            } catch (IOException | UnsupportedOperationException exception) {
                return false;
            }
        }

        @Override
        public InetSocketAddress receive(ByteBuffer destination) throws IOException {
            var source = channel.receive(destination);
            if (source == null) {
                throw new IOException("the channel returned no datagram");
            }
            return (InetSocketAddress) source;
        }

        @Override
        public void close() {
            try {
                channel.close();
            } catch (IOException _) {
                // A failed close leaves nothing to release.
            }
        }
    }

    /// A TCP connection over a blocking [SocketChannel].
    private record ChannelStreamConnection(SocketChannel channel) implements StreamConnection {
        @Override
        public InetSocketAddress localAddress() {
            try {
                return (InetSocketAddress) channel.getLocalAddress();
            } catch (IOException exception) {
                return new InetSocketAddress(0);
            }
        }

        @Override
        public InetSocketAddress remoteAddress() {
            try {
                return (InetSocketAddress) channel.getRemoteAddress();
            } catch (IOException exception) {
                return new InetSocketAddress(0);
            }
        }

        @Override
        public int read(ByteBuffer destination) throws IOException {
            return channel.read(destination);
        }

        @Override
        public int write(ByteBuffer source) throws IOException {
            var written = 0;
            while (source.hasRemaining()) {
                written += channel.write(source);
            }
            return written;
        }

        @Override
        public boolean isOpen() {
            return channel.isOpen();
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }

    /// A TCP listener over a blocking [ServerSocketChannel].
    private record ChannelStreamListener(ServerSocketChannel channel) implements StreamListener {
        @Override
        public InetSocketAddress localAddress() {
            try {
                return (InetSocketAddress) channel.getLocalAddress();
            } catch (IOException exception) {
                return new InetSocketAddress(0);
            }
        }

        @Override
        public StreamConnection accept() throws IOException {
            var accepted = channel.accept();
            accepted.setOption(StandardSocketOptions.TCP_NODELAY, true);
            return new ChannelStreamConnection(accepted);
        }

        @Override
        public void close() {
            try {
                channel.close();
            } catch (IOException _) {
                // A failed close leaves nothing to release.
            }
        }
    }
}
