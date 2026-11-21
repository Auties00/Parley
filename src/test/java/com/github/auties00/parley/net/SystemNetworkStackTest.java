package com.github.auties00.parley.net;

import com.github.auties00.parley.turn.TestCertificates;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ThreadFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Exercises the JDK network stack over the loopback interface: UDP, TCP, TLS with a self-signed certificate, and
/// interface enumeration.
@DisplayName("NetworkStack.system")
class SystemNetworkStackTest {
    private static final ThreadFactory THREADS = Thread.ofVirtual().name("net-test-", 0).factory();
    private static final InetAddress LOOPBACK = InetAddress.ofLiteral("127.0.0.1");

    @Test
    @DisplayName("sends and receives datagrams between two UDP endpoints")
    void udp() throws IOException {
        var stack = NetworkStack.system(THREADS);
        try (var first = stack.bindUdp(new InetSocketAddress(LOOPBACK, 0)); var second = stack.bindUdp(new InetSocketAddress(LOOPBACK, 0))) {
            first.send(ByteBuffer.wrap("hello".getBytes(StandardCharsets.UTF_8)), second.localAddress());
            var buffer = ByteBuffer.allocate(100);
            var source = second.receive(buffer);
            assertEquals(first.localAddress(), source);
            assertEquals("hello", new String(buffer.array(), 0, buffer.position(), StandardCharsets.UTF_8));
        }
    }

    @Test
    @DisplayName("unblocks a receive when the endpoint closes")
    void udpCloseUnblocks() throws Exception {
        var stack = NetworkStack.system(THREADS);
        var endpoint = stack.bindUdp(new InetSocketAddress(LOOPBACK, 0));
        var failed = new boolean[1];
        var reader = Thread.ofVirtual().start(() -> {
            try {
                endpoint.receive(ByteBuffer.allocate(10));
            } catch (IOException exception) {
                failed[0] = true;
            }
        });
        Thread.sleep(50);
        endpoint.close();
        reader.join(Duration.ofSeconds(5));
        assertTrue(failed[0]);
    }

    @Test
    @DisplayName("connects, accepts and exchanges bytes over TCP")
    void tcp() throws Exception {
        var stack = NetworkStack.system(THREADS);
        try (var listener = stack.listenTcp(new InetSocketAddress(LOOPBACK, 0))) {
            var accepted = new StreamConnection[1];
            var acceptor = Thread.ofVirtual().start(() -> {
                try {
                    accepted[0] = listener.accept();
                } catch (IOException exception) {
                    throw new AssertionError(exception);
                }
            });
            try (var client = stack.connectTcp(InetSocketAddress.createUnresolved("127.0.0.1", listener.localAddress().getPort()), Duration.ofSeconds(5))) {
                acceptor.join(Duration.ofSeconds(5));
                client.write(ByteBuffer.wrap(new byte[]{1, 2, 3}));
                var buffer = ByteBuffer.allocate(3);
                while (buffer.hasRemaining()) {
                    accepted[0].read(buffer);
                }
                assertEquals(ByteBuffer.wrap(new byte[]{1, 2, 3}), buffer.flip());
                assertEquals(listener.localAddress().getPort(), client.remoteAddress().getPort());
                accepted[0].close();
            }
        }
    }

    @Test
    @DisplayName("runs a TLS handshake over SSLEngine and exchanges data both ways")
    void tls() throws Exception {
        var stack = NetworkStack.system(THREADS, TestCertificates.clientContext());
        try (var server = (SSLServerSocket) TestCertificates.serverContext().getServerSocketFactory().createServerSocket(0, 10, LOOPBACK)) {
            var echo = Thread.ofVirtual().start(() -> {
                try (var socket = server.accept()) {
                    var input = socket.getInputStream();
                    var output = socket.getOutputStream();
                    var bytes = input.readNBytes(5);
                    output.write(bytes);
                    output.write("!".repeat(20_000).getBytes(StandardCharsets.US_ASCII));
                    output.flush();
                    input.read();
                } catch (IOException exception) {
                    // The client closed the connection.
                }
            });
            try (var connection = stack.connectTls(InetSocketAddress.createUnresolved("localhost", server.getLocalPort()), "localhost", Duration.ofSeconds(10))) {
                connection.write(ByteBuffer.wrap("hello".getBytes(StandardCharsets.UTF_8)));
                var buffer = ByteBuffer.allocate(5 + 20_000);
                while (buffer.hasRemaining()) {
                    assertTrue(connection.read(buffer) >= 0);
                }
                assertEquals("hello", new String(buffer.array(), 0, 5, StandardCharsets.UTF_8));
                assertTrue(connection.isOpen());
            }
            echo.join(Duration.ofSeconds(5));
        }
    }

    @Test
    @DisplayName("refuses a TLS server whose certificate does not match the name")
    void tlsWrongName() throws Exception {
        var stack = NetworkStack.system(THREADS, TestCertificates.clientContext());
        try (var server = (SSLServerSocket) TestCertificates.serverContext().getServerSocketFactory().createServerSocket(0, 10, LOOPBACK)) {
            Thread.ofVirtual().start(() -> {
                try (var socket = server.accept()) {
                    socket.getInputStream().read();
                } catch (IOException exception) {
                    // The handshake fails.
                }
            });
            assertThrows(IOException.class, () -> stack.connectTls(new InetSocketAddress(LOOPBACK, server.getLocalPort()), "wrong.example", Duration.ofSeconds(10)));
        }
    }

    @Test
    @DisplayName("times out a TLS handshake the server never answers")
    void tlsTimeout() throws Exception {
        var stack = NetworkStack.system(THREADS, TestCertificates.clientContext());
        try (var listener = stack.listenTcp(new InetSocketAddress(LOOPBACK, 0))) {
            Thread.ofVirtual().start(() -> {
                try {
                    var connection = listener.accept();
                    Thread.sleep(5_000);
                    connection.close();
                } catch (IOException | InterruptedException exception) {
                    // The test is over.
                }
            });
            var start = System.nanoTime();
            assertThrows(SocketTimeoutException.class, () -> stack.connectTls(listener.localAddress(), "localhost", Duration.ofMillis(300)));
            assertTrue(System.nanoTime() - start < Duration.ofSeconds(4).toNanos());
        }
    }

    @Test
    @DisplayName("lists at least the loopback interface and validates prefixes")
    void interfaces() throws IOException {
        var addresses = NetworkStack.system(THREADS).interfaceAddresses();
        assertTrue(addresses.stream().anyMatch(NetworkInterfaceAddress::loopback));
        assertThrows(IllegalArgumentException.class, () -> new NetworkInterfaceAddress("x", LOOPBACK, 33, true, false, false));
        assertFalse(NetworkStack.system(THREADS).resolve("127.0.0.1").isEmpty());
    }

    @Test
    @DisplayName("reads the system clock monotonically")
    void clock() {
        var clock = MonotonicClock.system();
        var first = clock.nanos();
        assertTrue(clock.nanos() - first >= 0);
    }
}
