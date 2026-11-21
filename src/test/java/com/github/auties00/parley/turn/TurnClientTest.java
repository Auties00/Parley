package com.github.auties00.parley.turn;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.stun.StunAttribute;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/// Drives the TURN client against [TestTurnServer] over UDP, TCP and TLS, with a peer on a plain UDP socket.
@DisplayName("TurnClient")
class TurnClientTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private TestTurnServer server;
    private NetworkStack stack;
    private DatagramChannel peer;

    @BeforeEach
    void start() throws IOException {
        server = TestTurnServer.start();
        stack = NetworkStack.system(Thread.ofVirtual().name("turn-test-", 0).factory(), TestCertificates.clientContext());
        peer = DatagramChannel.open().bind(new InetSocketAddress(InetAddress.ofLiteral("127.0.0.1"), 0));
        peer.socket().setSoTimeout(5_000);
    }

    @AfterEach
    void stop() throws IOException {
        server.close();
        peer.close();
    }

    private InetSocketAddress peerAddress() throws IOException {
        return (InetSocketAddress) peer.getLocalAddress();
    }

    private TurnClient connect(TurnTransport transport) throws IOException {
        return TurnClient.connect(server.turnServer(transport), server.credentials(), stack, MonotonicClock.system(), TIMEOUT);
    }

    private static byte[] receiveOnPeer(DatagramChannel peer) throws IOException {
        var buffer = ByteBuffer.allocate(2048);
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        peer.configureBlocking(false);
        try {
            while (System.nanoTime() < deadline) {
                if (peer.receive(buffer) != null) {
                    buffer.flip();
                    var bytes = new byte[buffer.remaining()];
                    buffer.get(bytes);
                    return bytes;
                }
                Thread.onSpinWait();
                Thread.yield();
            }
            throw new AssertionError("the peer received nothing");
        } finally {
            peer.configureBlocking(true);
        }
    }

    @ParameterizedTest
    @EnumSource(TurnTransport.class)
    @DisplayName("allocates after the 401 challenge and relays both ways with Send/Data and with a channel")
    void relaysBothWays(TurnTransport transport) throws Exception {
        try (var client = connect(transport)) {
            var allocation = client.allocate(TurnAllocationOptions.IPV4, TIMEOUT);
            assertEquals(1, server.challenges());
            assertEquals(server.relayedAddresses().getFirst(), allocation.relayedAddress());
            assertTrue(allocation.mappedAddress().isPresent());
            var received = new LinkedBlockingQueue<byte[]>();
            allocation.setReceiver((source, data, arrival) -> {
                var bytes = new byte[data.remaining()];
                data.get(bytes);
                received.add(bytes);
            });
            allocation.createPermission(peerAddress().getAddress(), TIMEOUT);
            assertTrue(allocation.hasPermission(peerAddress().getAddress()));

            allocation.send(ByteBuffer.wrap(new byte[]{1, 2, 3}), peerAddress());
            assertEquals(List.of((byte) 1, (byte) 2, (byte) 3), toList(receiveOnPeer(peer)));
            assertEquals(1, server.sendIndications());

            peer.send(ByteBuffer.wrap(new byte[]{4, 5}), allocation.relayedAddress());
            assertEquals(List.of((byte) 4, (byte) 5), toList(received.poll(5, TimeUnit.SECONDS)));

            var channel = allocation.bindChannel(peerAddress(), TIMEOUT);
            assertTrue(channel >= 0x4000 && channel <= 0x4FFF);
            assertEquals(channel, allocation.bindChannel(peerAddress(), TIMEOUT));
            assertEquals(1, server.channelBinds());

            allocation.send(ByteBuffer.wrap(new byte[]{6, 7, 8, 9, 10}), peerAddress());
            assertEquals(List.of((byte) 6, (byte) 7, (byte) 8, (byte) 9, (byte) 10), toList(receiveOnPeer(peer)));
            assertEquals(1, server.channelDataMessages());

            peer.send(ByteBuffer.wrap(new byte[]{11}), allocation.relayedAddress());
            assertEquals(List.of((byte) 11), toList(received.poll(5, TimeUnit.SECONDS)));
            assertTrue(allocation.maxPayloadSize() > 1000);
        }
        assertEquals(1, server.deallocations());
    }

    @Test
    @DisplayName("drops data from a peer without a permission")
    void permissionsFilter() throws Exception {
        try (var client = connect(TurnTransport.UDP)) {
            var allocation = client.allocate(TurnAllocationOptions.IPV4, TIMEOUT);
            var received = new LinkedBlockingQueue<byte[]>();
            allocation.setReceiver((source, data, arrival) -> received.add(new byte[data.remaining()]));
            peer.send(ByteBuffer.wrap(new byte[]{1}), allocation.relayedAddress());
            assertEquals(null, received.poll(300, TimeUnit.MILLISECONDS));
        }
    }

    @Test
    @DisplayName("retries a request after 438 Stale Nonce")
    void staleNonce() throws Exception {
        try (var client = connect(TurnTransport.UDP)) {
            var allocation = client.allocate(TurnAllocationOptions.IPV4, TIMEOUT);
            server.staleNonceOnce();
            allocation.createPermission(peerAddress().getAddress(), TIMEOUT);
            assertEquals(1, server.permissionRequests());
        }
    }

    @Test
    @DisplayName("negotiates the SHA-256 password algorithm and MESSAGE-INTEGRITY-SHA256")
    void sha256() throws Exception {
        server.requireSha256(true);
        try (var client = connect(TurnTransport.TCP)) {
            var allocation = client.allocate(TurnAllocationOptions.IPV4, TIMEOUT);
            allocation.createPermission(peerAddress().getAddress(), TIMEOUT);
            assertEquals(1, server.permissionRequests());
        }
    }

    @Test
    @DisplayName("fails with 401 when the credentials are wrong")
    void wrongCredentials() throws Exception {
        try (var client = TurnClient.connect(server.turnServer(TurnTransport.UDP), new TurnCredentials(TestTurnServer.USERNAME, "wrong"),
                stack, MonotonicClock.system(), TIMEOUT)) {
            var failure = assertThrows(TurnException.class, () -> client.allocate(TurnAllocationOptions.IPV4, TIMEOUT));
            assertEquals(401, failure.errorCode().orElseThrow());
        }
    }

    @Test
    @DisplayName("drops DONT-FRAGMENT and retries when the server does not understand it")
    void dontFragment() throws Exception {
        server.rejectDontFragment(true);
        try (var client = connect(TurnTransport.UDP)) {
            var options = TurnAllocationOptions.IPV4.withDontFragment(true);
            var allocation = client.allocate(options, TIMEOUT);
            assertTrue(allocation.isActive());
        }
    }

    @Test
    @DisplayName("allocates an IPv6 relayed address when the host has IPv6 loopback")
    void ipv6Relay() throws Exception {
        assumeTrue(ipv6LoopbackAvailable());
        try (var client = connect(TurnTransport.UDP)) {
            var allocation = client.allocate(TurnAllocationOptions.IPV6, TIMEOUT);
            assertTrue(allocation.relayedAddress().getAddress() instanceof Inet6Address);
        }
    }

    @Test
    @DisplayName("times out against a silent server")
    void silentServer() throws Exception {
        server.silent(true);
        try (var client = connect(TurnTransport.UDP)) {
            assertThrows(IOException.class, () -> client.allocate(TurnAllocationOptions.IPV4, Duration.ofMillis(800)));
        }
    }

    @Test
    @DisplayName("refreshes the allocation, permissions and channels on its timers")
    void refreshTimers() throws Exception {
        var timers = new TurnTimers(Duration.ofSeconds(60), Duration.ofMillis(150), Duration.ofMillis(200), Duration.ofSeconds(1));
        try (var client = TurnClient.connect(server.turnServer(TurnTransport.UDP), server.credentials(), stack, MonotonicClock.system(), TIMEOUT, timers)) {
            var shortLived = new TurnAllocationOptions(com.github.auties00.parley.stun.StunAddressFamily.IPV4, java.util.Optional.of(Duration.ofSeconds(1)), false);
            var allocation = client.allocate(shortLived, TIMEOUT);
            allocation.createPermission(peerAddress().getAddress(), TIMEOUT);
            allocation.bindChannel(peerAddress(), TIMEOUT);
            var deadline = System.nanoTime() + TIMEOUT.toNanos();
            while ((server.refreshes() < 1 || server.permissionRequests() < 3 || server.channelBinds() < 3) && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertTrue(server.refreshes() >= 1, "refreshes " + server.refreshes());
            assertTrue(server.permissionRequests() >= 3, "permissions " + server.permissionRequests());
            assertTrue(server.channelBinds() >= 3, "channel binds " + server.channelBinds());
        }
    }

    @Test
    @DisplayName("marks the allocation inactive when the server forgets it")
    void allocationMismatch() throws Exception {
        try (var client = connect(TurnTransport.TCP)) {
            var allocation = client.allocate(TurnAllocationOptions.IPV4, TIMEOUT);
            server.close();
            var deadline = System.nanoTime() + TIMEOUT.toNanos();
            while (allocation.isActive() && System.nanoTime() < deadline) {
                Thread.sleep(20);
            }
            assertFalse(allocation.isActive());
            assertThrows(IOException.class, () -> allocation.send(ByteBuffer.wrap(new byte[1]), peerAddress()));
        }
    }

    @Test
    @DisplayName("refuses a second allocation on one client")
    void oneAllocation() throws Exception {
        try (var client = connect(TurnTransport.UDP)) {
            client.allocate(TurnAllocationOptions.IPV4, TIMEOUT);
            assertNotNull(client.allocation().orElseThrow());
            assertThrows(IllegalStateException.class, () -> client.allocate(TurnAllocationOptions.IPV4, TIMEOUT));
        }
    }

    @Test
    @DisplayName("parses turn: and turns: URIs per RFC 7065")
    void uris() {
        assertEquals(new TurnServer("example.org", 3478, TurnTransport.UDP), TurnServer.parse(URI.create("turn:example.org")));
        assertEquals(new TurnServer("example.org", 3478, TurnTransport.UDP), TurnServer.parse(URI.create("turn:example.org?transport=udp")));
        assertEquals(new TurnServer("example.org", 3478, TurnTransport.TCP), TurnServer.parse(URI.create("turn:example.org?transport=tcp")));
        assertEquals(new TurnServer("example.org", 5349, TurnTransport.TLS), TurnServer.parse(URI.create("turns:example.org")));
        assertEquals(new TurnServer("example.org", 443, TurnTransport.TLS), TurnServer.parse(URI.create("turns:example.org:443?transport=tcp")));
        assertEquals(new TurnServer("2001:db8::1", 3479, TurnTransport.UDP), TurnServer.parse(URI.create("turn:[2001:db8::1]:3479")));
        assertThrows(IllegalArgumentException.class, () -> TurnServer.parse(URI.create("turns:example.org?transport=udp")));
        assertThrows(IllegalArgumentException.class, () -> TurnServer.parse(URI.create("turn:example.org?transport=sctp")));
        assertThrows(IllegalArgumentException.class, () -> TurnServer.parse(URI.create("stun:example.org")));
        for (var transport : TurnTransport.values()) {
            var original = new TurnServer("2001:db8::1", 1234, transport);
            assertEquals(original, TurnServer.parse(original.toUri()));
        }
        assertFalse(new TurnCredentials("user", "secret").toString().contains("secret"));
    }

    @Test
    @DisplayName("throws only IllegalArgumentException when parsing random STUN and TURN URIs")
    void uriFuzz() {
        var random = new java.util.Random(9);
        var pieces = List.of("turn:", "turns:", "stun:", "stuns:", "example.org", "[", "]", "::1", "2001:db8::1", ":", "3478",
                "99999", "?", "transport=", "udp", "tcp", "&", "/", "", "a", "0");
        for (var i = 0; i < 20_000; i++) {
            var builder = new StringBuilder();
            for (var j = random.nextInt(7); j >= 0; j--) {
                builder.append(pieces.get(random.nextInt(pieces.size())));
            }
            URI uri;
            try {
                uri = URI.create(builder.toString());
            } catch (IllegalArgumentException notAUri) {
                continue;
            }
            try {
                var server = TurnServer.parse(uri);
                assertEquals(server, TurnServer.parse(server.toUri()));
            } catch (IllegalArgumentException expected) {
                // Malformed input fails this way only.
            }
            try {
                var server = com.github.auties00.parley.stun.StunServer.parse(uri);
                assertEquals(server, com.github.auties00.parley.stun.StunServer.parse(server.toUri()));
            } catch (IllegalArgumentException expected) {
                // Malformed input fails this way only.
            }
        }
    }

    @Test
    @DisplayName("frames ChannelData with and without stream padding, and survives fuzzing")
    void channelData() {
        var unpadded = ChannelData.encode(0x4001, ByteBuffer.wrap(new byte[]{1, 2, 3}), false);
        assertEquals(7, unpadded.remaining());
        assertTrue(ChannelData.isChannelData(unpadded));
        assertEquals(0x4001, ChannelData.channel(unpadded));
        assertEquals(ByteBuffer.wrap(new byte[]{1, 2, 3}), ChannelData.payload(unpadded));
        var padded = ChannelData.encode(0x4001, ByteBuffer.wrap(new byte[]{1, 2, 3}), true);
        assertEquals(8, padded.remaining());
        assertEquals(8, ChannelData.streamFrameLength(padded));
        assertFalse(ChannelData.isChannelData(ByteBuffer.wrap(new byte[]{0x50, 0, 0, 0})));
        var random = new java.util.Random(3);
        for (var i = 0; i < 10_000; i++) {
            var bytes = new byte[random.nextInt(12)];
            random.nextBytes(bytes);
            var buffer = ByteBuffer.wrap(bytes);
            if (ChannelData.isChannelData(buffer)) {
                assertTrue(ChannelData.payload(buffer).remaining() <= bytes.length - 4);
            }
        }
        assertEquals(StunAttribute.DontFragment.TYPE, 0x001A);
    }

    private static boolean ipv6LoopbackAvailable() {
        try (var channel = DatagramChannel.open()) {
            channel.bind(new InetSocketAddress(InetAddress.ofLiteral("::1"), 0));
            return true;
        } catch (IOException | UnsupportedOperationException exception) {
            return false;
        }
    }

    private static List<Byte> toList(byte[] bytes) {
        assertNotNull(bytes);
        var list = new java.util.ArrayList<Byte>();
        for (var value : bytes) {
            list.add(value);
        }
        return list;
    }
}
