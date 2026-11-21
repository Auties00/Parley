package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.dtls.DtlsRole;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Runs two [SctpTransport]s against each other over an in-memory datagram pipe that stands in for the DTLS
/// application data, so the association, DCEP and the stream resets are exercised end to end without DTLS.
@DisplayName("SCTP transport and data channels")
@Timeout(60)
class SctpTransportTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final List<SctpTransport> opened = new ArrayList<>();

    @AfterEach
    void closeAll() {
        opened.forEach(SctpTransport::close);
    }

    private SctpTransport[] connectedPair(SctpConfig clientConfig, SctpConfig serverConfig,
                                          LoopbackDatagramTransport[] pipe) throws Exception {
        var client = SctpTransport.overDatagrams(pipe[0], clientConfig);
        var server = SctpTransport.overDatagrams(pipe[1], serverConfig);
        opened.add(client);
        opened.add(server);
        var failure = new AtomicReference<Throwable>();
        var serverThread = Thread.ofVirtual().start(() -> {
            try {
                server.start(DtlsRole.SERVER, clientConfig.localPort(), clientConfig.maxMessageSize(), TIMEOUT);
            } catch (Throwable throwable) {
                failure.set(throwable);
            }
        });
        client.start(DtlsRole.CLIENT, serverConfig.localPort(), serverConfig.maxMessageSize(), TIMEOUT);
        serverThread.join();
        if (failure.get() != null) {
            throw new AssertionError("server failed to start", failure.get());
        }
        return new SctpTransport[]{client, server};
    }

    private SctpTransport[] connectedPair() throws Exception {
        return connectedPair(SctpConfig.defaults(), SctpConfig.defaults(), LoopbackDatagramTransport.pair());
    }

    @Test
    @DisplayName("connects both sides at once and reports the negotiated limits")
    void connects() throws Exception {
        var pair = connectedPair();
        assertEquals(SctpTransportState.CONNECTED, pair[0].state());
        assertEquals(SctpTransportState.CONNECTED, pair[1].state());
        assertEquals(SctpConfig.DEFAULT_MAX_MESSAGE_SIZE, pair[0].maxMessageSize());
        assertTrue(pair[0].maxChannels().isPresent());
        assertTrue(pair[0].messageInterleaving(), "both sides offer I-DATA by default");
        assertEquals(DtlsRole.CLIENT, pair[0].role().orElseThrow());
    }

    @Test
    @DisplayName("does not negotiate interleaving when one side does not offer it")
    void noInterleaving() throws Exception {
        var pair = connectedPair(SctpConfig.defaults().withMessageInterleaving(false), SctpConfig.defaults(),
                LoopbackDatagramTransport.pair());
        assertFalse(pair[0].messageInterleaving());
        assertFalse(pair[1].messageInterleaving());
        var channel = pair[0].createDataChannel("plain", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        channel.send("works");
        assertEquals(new DataChannelMessage.Text("works"), remote.receive(TIMEOUT).orElseThrow());
    }

    @Test
    @DisplayName("opens an in-band channel with DCEP and carries its label, protocol and options to the peer")
    void inBandOpen() throws Exception {
        var pair = connectedPair();
        var init = DataChannelInit.reliable()
                .withOrdered(false)
                .withMaxRetransmits(3)
                .withProtocol("chat-v1")
                .withPriority(DataChannelPriority.HIGH);
        var local = pair[0].createDataChannel("chat", init);
        assertEquals(DataChannelState.OPEN, local.readyState());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        assertEquals("chat", remote.label());
        assertEquals("chat-v1", remote.protocol());
        assertFalse(remote.ordered());
        assertEquals(3, remote.maxRetransmits().orElseThrow());
        assertTrue(remote.maxPacketLifeTime().isEmpty());
        assertEquals(DataChannelPriority.HIGH, remote.priority());
        assertFalse(remote.negotiated());
        assertEquals(local.id(), remote.id());
        assertEquals(DataChannelState.OPEN, remote.readyState());
    }

    @Test
    @DisplayName("gives the DTLS client even stream ids and the server odd ones")
    void streamIdParity() throws Exception {
        var pair = connectedPair();
        var clientIds = new HashSet<Integer>();
        var serverIds = new HashSet<Integer>();
        for (var index = 0; index < 4; index++) {
            clientIds.add(pair[0].createDataChannel("c" + index, DataChannelInit.reliable()).id().orElseThrow());
            serverIds.add(pair[1].createDataChannel("s" + index, DataChannelInit.reliable()).id().orElseThrow());
        }
        assertEquals(4, clientIds.size());
        assertEquals(4, serverIds.size());
        assertTrue(clientIds.stream().allMatch(id -> id % 2 == 0), clientIds.toString());
        assertTrue(serverIds.stream().allMatch(id -> id % 2 == 1), serverIds.toString());
        for (var index = 0; index < 4; index++) {
            pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
            pair[0].acceptDataChannel(TIMEOUT).orElseThrow();
        }
    }

    @Test
    @DisplayName("carries text, binary and empty messages in both directions with their types")
    void messages() throws Exception {
        var pair = connectedPair();
        var local = pair[0].createDataChannel("data", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        local.send("hello, \u00e8\u4e16\u754c");
        local.send(ByteBuffer.wrap(new byte[]{1, 2, 3}));
        local.send("");
        local.send(ByteBuffer.allocate(0));
        assertEquals(new DataChannelMessage.Text("hello, \u00e8\u4e16\u754c"), remote.receive());
        var binary = assertInstanceOf(DataChannelMessage.Binary.class, remote.receive());
        assertArrayEquals(new byte[]{1, 2, 3}, binary.toByteArray());
        assertEquals(new DataChannelMessage.Text(""), remote.receive());
        var empty = assertInstanceOf(DataChannelMessage.Binary.class, remote.receive());
        assertEquals(0, empty.sizeBytes());
        remote.send("back");
        assertEquals(new DataChannelMessage.Text("back"), local.receive(TIMEOUT).orElseThrow());
        var sent = local.statistics();
        assertEquals(4, sent.messagesSent());
        assertEquals("hello, \u00e8\u4e16\u754c".getBytes(StandardCharsets.UTF_8).length + 3, sent.bytesSent());
        assertEquals(4, remote.statistics().messagesReceived());
    }

    @Test
    @DisplayName("keeps message order and content across many messages larger than one packet")
    void ordering() throws Exception {
        var pair = connectedPair();
        var local = pair[0].createDataChannel("bulk", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        var random = new java.util.Random(7);
        var expected = new ArrayList<byte[]>();
        for (var index = 0; index < 50; index++) {
            var payload = new byte[1 + random.nextInt(20_000)];
            random.nextBytes(payload);
            expected.add(payload);
            local.send(ByteBuffer.wrap(payload));
        }
        for (var payload : expected) {
            var received = assertInstanceOf(DataChannelMessage.Binary.class, remote.receive(TIMEOUT).orElseThrow());
            assertArrayEquals(payload, received.toByteArray());
        }
    }

    @Test
    @DisplayName("delivers reliably over a lossy path")
    void lossyPath() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var pair = connectedPair(SctpConfig.defaults(), SctpConfig.defaults(), pipe);
        var local = pair[0].createDataChannel("lossy", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        pipe[0].setDrop(index -> index % 7 == 3);
        pipe[1].setDrop(index -> index % 11 == 5);
        for (var index = 0; index < 100; index++) {
            local.send("message " + index);
        }
        for (var index = 0; index < 100; index++) {
            assertEquals(new DataChannelMessage.Text("message " + index), remote.receive(TIMEOUT).orElseThrow());
        }
    }

    @Test
    @DisplayName("abandons messages of a channel with no retransmissions when the path drops everything")
    void partialReliability() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var pair = connectedPair(SctpConfig.defaults(), SctpConfig.defaults(), pipe);
        var local = pair[0].createDataChannel("unreliable",
                DataChannelInit.reliable().withOrdered(false).withMaxRetransmits(0));
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        local.send("first");
        assertEquals(new DataChannelMessage.Text("first"), remote.receive(TIMEOUT).orElseThrow());
        var dropping = new java.util.concurrent.atomic.AtomicBoolean(true);
        var base = pipe[0].sentDatagrams();
        pipe[0].setDrop(index -> dropping.get() && index >= base);
        local.send("lost");
        Thread.sleep(200);
        dropping.set(false);
        local.send("after");
        var received = remote.receive(TIMEOUT).orElseThrow();
        assertEquals(new DataChannelMessage.Text("after"), received);
        assertTrue(remote.receive(Duration.ofMillis(1500)).isEmpty(), "the dropped message is never retransmitted");
    }

    @Test
    @DisplayName("abandons messages of a timed channel once their lifetime expires")
    void timedReliability() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var pair = connectedPair(SctpConfig.defaults(), SctpConfig.defaults(), pipe);
        var local = pair[0].createDataChannel("timed",
                DataChannelInit.reliable().withMaxPacketLifeTime(Duration.ofMillis(50)));
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        assertEquals(Duration.ofMillis(50), remote.maxPacketLifeTime().orElseThrow());
        local.send("first");
        assertEquals(new DataChannelMessage.Text("first"), remote.receive(TIMEOUT).orElseThrow());
        var dropping = new java.util.concurrent.atomic.AtomicBoolean(true);
        var base = pipe[0].sentDatagrams();
        pipe[0].setDrop(index -> dropping.get() && index >= base);
        local.send("expired");
        Thread.sleep(700);
        dropping.set(false);
        local.send("fresh");
        assertEquals(new DataChannelMessage.Text("fresh"), remote.receive(TIMEOUT).orElseThrow(),
                "the ordered channel skips the expired message instead of waiting for it");
        assertTrue(remote.receive(Duration.ofMillis(1500)).isEmpty());
    }

    @Test
    @DisplayName("opens out-of-band negotiated channels on both sides without DCEP")
    void negotiated() throws Exception {
        var pair = connectedPair();
        var init = DataChannelInit.reliable().withNegotiatedId(42).withProtocol("p");
        var a = pair[0].createDataChannel("shared", init);
        var b = pair[1].createDataChannel("shared", init);
        assertEquals(42, a.id().orElseThrow());
        assertTrue(a.negotiated());
        a.send("ping");
        assertEquals(new DataChannelMessage.Text("ping"), b.receive(TIMEOUT).orElseThrow());
        b.send("pong");
        assertEquals(new DataChannelMessage.Text("pong"), a.receive(TIMEOUT).orElseThrow());
        assertTrue(pair[1].acceptDataChannel(Duration.ofMillis(100)).isEmpty(), "negotiated channels are not announced");
        assertThrows(IllegalArgumentException.class, () -> pair[0].createDataChannel("again", init));
    }

    @Test
    @DisplayName("opens channels created before the transport connects")
    void createdBeforeStart() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var client = SctpTransport.overDatagrams(pipe[0], SctpConfig.defaults());
        var server = SctpTransport.overDatagrams(pipe[1], SctpConfig.defaults());
        opened.add(client);
        opened.add(server);
        var early = client.createDataChannel("early", DataChannelInit.reliable());
        var negotiated = server.createDataChannel("neg", DataChannelInit.reliable().withNegotiatedId(7));
        var counterpart = client.createDataChannel("neg", DataChannelInit.reliable().withNegotiatedId(7));
        assertEquals(DataChannelState.CONNECTING, early.readyState());
        assertTrue(early.id().isEmpty());
        assertThrows(IllegalStateException.class, () -> early.send("too soon"));
        var serverThread = Thread.ofVirtual().start(() -> {
            try {
                server.start(DtlsRole.SERVER, 5000, 65536, TIMEOUT);
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        });
        client.start(DtlsRole.CLIENT, 5000, 65536, TIMEOUT);
        serverThread.join();
        assertTrue(early.awaitOpen(TIMEOUT));
        assertEquals(0, early.id().orElseThrow() % 2);
        var accepted = server.acceptDataChannel(TIMEOUT).orElseThrow();
        assertEquals("early", accepted.label());
        early.send("now");
        assertEquals(new DataChannelMessage.Text("now"), accepted.receive(TIMEOUT).orElseThrow());
        assertTrue(negotiated.awaitOpen(TIMEOUT));
        counterpart.send("x");
        assertEquals(new DataChannelMessage.Text("x"), negotiated.receive(TIMEOUT).orElseThrow());
        assertEquals(65536, client.maxMessageSize());
    }

    @Test
    @DisplayName("closes a channel by resetting both streams, delivering what was sent before")
    void closeByReset() throws Exception {
        var pair = connectedPair();
        var local = pair[0].createDataChannel("closing", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        local.send("last words");
        local.close();
        assertTrue(local.awaitClosed(TIMEOUT), "local side closes once the peer resets back");
        assertTrue(remote.awaitClosed(TIMEOUT), "remote side closes once both streams are reset");
        assertEquals(new DataChannelMessage.Text("last words"), remote.receive(TIMEOUT).orElseThrow());
        assertThrows(ClosedChannelException.class, remote::receive);
        assertThrows(IllegalStateException.class, () -> local.send("nope"));
        var reused = pair[0].createDataChannel("reused", DataChannelInit.reliable());
        assertEquals(local.id(), reused.id(), "a closed channel frees its stream id");
        assertEquals("reused", pair[1].acceptDataChannel(TIMEOUT).orElseThrow().label());
    }

    @Test
    @DisplayName("closes when the peer closes")
    void remoteClose() throws Exception {
        var pair = connectedPair();
        var local = pair[0].createDataChannel("victim", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        remote.close();
        assertTrue(local.awaitClosed(TIMEOUT));
        assertTrue(remote.awaitClosed(TIMEOUT));
    }

    @Test
    @DisplayName("enforces the peer's maximum message size")
    void maxMessageSize() throws Exception {
        var pair = connectedPair(SctpConfig.defaults(), SctpConfig.defaults().withMaxMessageSize(1000),
                LoopbackDatagramTransport.pair());
        assertEquals(1000, pair[0].maxMessageSize());
        var local = pair[0].createDataChannel("small", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        assertThrows(IllegalArgumentException.class, () -> local.send(ByteBuffer.allocate(1001)));
        local.send(ByteBuffer.allocate(1000));
        assertEquals(1000, remote.receive(TIMEOUT).orElseThrow().sizeBytes());
    }

    @Test
    @DisplayName("reports buffered data and wakes a producer once it drains below the threshold")
    void bufferedAmount() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var pair = connectedPair(SctpConfig.defaults(), SctpConfig.defaults(), pipe);
        var local = pair[0].createDataChannel("bulk", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        var stalled = new java.util.concurrent.atomic.AtomicBoolean(true);
        pipe[0].setDrop(_ -> stalled.get());
        local.setBufferedAmountLowThreshold(1024);
        for (var index = 0; index < 20; index++) {
            local.send(ByteBuffer.allocate(16 * 1024));
        }
        assertTrue(local.bufferedAmount() > 1024, "data piles up while the path is stalled: " + local.bufferedAmount());
        assertFalse(local.awaitBufferedAmountLow(Duration.ofMillis(50)));
        stalled.set(false);
        assertTrue(local.awaitBufferedAmountLow(TIMEOUT));
        for (var index = 0; index < 20; index++) {
            remote.receive(TIMEOUT).orElseThrow();
        }
    }

    @Test
    @DisplayName("closes every channel when the transport closes")
    void transportClose() throws Exception {
        var pair = connectedPair();
        var local = pair[0].createDataChannel("doomed", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        pair[0].close();
        assertEquals(SctpTransportState.CLOSED, pair[0].state());
        assertEquals(DataChannelState.CLOSED, local.readyState());
        assertTrue(remote.awaitClosed(TIMEOUT), "the peer sees the association end");
        assertThrows(ClosedChannelException.class, pair[0]::acceptDataChannel);
        assertThrows(IllegalStateException.class, () -> pair[0].createDataChannel("late", DataChannelInit.reliable()));
    }

    @Test
    @DisplayName("fails to start when the peer never answers")
    void startTimeout() {
        var pipe = LoopbackDatagramTransport.pair();
        pipe[0].setDrop(_ -> true);
        var client = SctpTransport.overDatagrams(pipe[0], SctpConfig.defaults());
        opened.add(client);
        var early = assertDoesNotThrowCreate(client);
        assertThrows(SctpTransportException.class,
                () -> client.start(DtlsRole.CLIENT, 5000, 65536, Duration.ofMillis(300)));
        assertEquals(SctpTransportState.CLOSED, client.state());
        assertEquals(DataChannelState.CLOSED, early.readyState());
        assertThrows(IllegalStateException.class,
                () -> client.start(DtlsRole.CLIENT, 5000, 65536, Duration.ofMillis(300)));
    }

    private static DataChannel assertDoesNotThrowCreate(SctpTransport transport) {
        try {
            return transport.createDataChannel("early", DataChannelInit.reliable());
        } catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }

    @Test
    @DisplayName("validates its arguments")
    void validation() {
        var pipe = LoopbackDatagramTransport.pair();
        var transport = SctpTransport.overDatagrams(pipe[0], SctpConfig.defaults());
        opened.add(transport);
        assertThrows(IllegalArgumentException.class, () -> transport.start(DtlsRole.CLIENT, 0, 0, TIMEOUT));
        assertThrows(IllegalArgumentException.class, () -> transport.start(DtlsRole.CLIENT, 5000, -1, TIMEOUT));
        assertThrows(IllegalArgumentException.class, () -> transport.start(DtlsRole.CLIENT, 5000, 0, Duration.ZERO));
        assertThrows(NullPointerException.class, () -> transport.createDataChannel(null, DataChannelInit.reliable()));
        assertThrows(IllegalArgumentException.class,
                () -> transport.createDataChannel("x".repeat(70_000), DataChannelInit.reliable()));
        assertEquals(0, transport.maxMessageSize());
        assertEquals(SctpConfig.DEFAULT_PORT, transport.localPort());
    }

    @Nested
    @DisplayName("under concurrency")
    class Concurrency {
        @Test
        @DisplayName("carries many channels in parallel without mixing their messages")
        void parallelChannels() throws Exception {
            var pair = connectedPair();
            var count = 8;
            var locals = new ArrayList<DataChannel>();
            for (var index = 0; index < count; index++) {
                locals.add(pair[0].createDataChannel("ch" + index, DataChannelInit.reliable()));
            }
            var remotes = new java.util.HashMap<String, DataChannel>();
            for (var index = 0; index < count; index++) {
                var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
                remotes.put(remote.label(), remote);
            }
            var threads = new ArrayList<Thread>();
            for (var local : locals) {
                threads.add(Thread.ofVirtual().start(() -> {
                    try {
                        for (var message = 0; message < 50; message++) {
                            local.send(local.label() + ":" + message);
                        }
                    } catch (Exception exception) {
                        throw new RuntimeException(exception);
                    }
                }));
            }
            for (var thread : threads) {
                thread.join();
            }
            for (var entry : remotes.entrySet()) {
                for (var message = 0; message < 50; message++) {
                    assertEquals(new DataChannelMessage.Text(entry.getKey() + ":" + message),
                            entry.getValue().receive(TIMEOUT).orElseThrow());
                }
            }
        }
    }
}
