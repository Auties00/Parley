package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Flow control and events of data channels: a channel the application does not read never stalls another, a send
/// never blocks on the association, messages for a negotiated channel created late are kept, an in-band open on this
/// side's stream parity is refused, events arrive in order, and close survives a failing DTLS layer.
@DisplayName("Data channel flow and events")
@Timeout(60)
class DataChannelFlowTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final List<SctpTransport> opened = new ArrayList<>();

    @AfterEach
    void closeAll() {
        opened.forEach(SctpTransport::close);
    }

    private SctpTransport[] connect(SctpConfig clientConfig, SctpConfig serverConfig, DatagramTransport clientPath,
                                    DatagramTransport serverPath) throws Exception {
        var client = SctpTransport.overDatagrams(clientPath, clientConfig);
        var server = SctpTransport.overDatagrams(serverPath, serverConfig);
        opened.add(client);
        opened.add(server);
        var failure = new AtomicReference<Throwable>();
        var thread = Thread.ofVirtual().start(() -> {
            try {
                server.start(DtlsRole.SERVER, clientConfig.localPort(), OptionalLong.empty(), TIMEOUT);
            } catch (Throwable throwable) {
                failure.set(throwable);
            }
        });
        client.start(DtlsRole.CLIENT, serverConfig.localPort(), OptionalLong.empty(), TIMEOUT);
        thread.join();
        if (failure.get() != null) {
            throw new AssertionError("server failed to start", failure.get());
        }
        return new SctpTransport[]{client, server};
    }

    private SctpTransport[] connect(SctpConfig clientConfig, SctpConfig serverConfig) throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        return connect(clientConfig, serverConfig, pipe[0], pipe[1]);
    }

    @Test
    @DisplayName("closes an unread channel that overflows and keeps delivering on another")
    void unreadChannelDoesNotStallAnother() throws Exception {
        var pair = connect(SctpConfig.defaults(), SctpConfig.defaults().withMaxReceiveBufferedBytes(64 * 1024));
        var bulk = pair[0].createDataChannel("bulk", DataChannelInit.reliable());
        var remoteBulk = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        var bulkEvents = new CopyOnWriteArrayList<DataChannelEvent>();
        remoteBulk.eventSink(bulkEvents::add);
        var chat = pair[0].createDataChannel("chat", DataChannelInit.reliable());
        var remoteChat = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        for (var index = 0; index < 40; index++) {
            bulk.send(ByteBuffer.allocate(16 * 1024));
        }
        chat.send("hello");
        assertEquals(new DataChannelMessage.Text("hello"), remoteChat.receive(TIMEOUT).orElseThrow());
        assertTrue(remoteBulk.awaitClosed(TIMEOUT), "the overflowing channel closes");
        var error = bulkEvents.stream().filter(DataChannelEvent.Error.class::isInstance)
                .map(DataChannelEvent.Error.class::cast).findFirst().orElseThrow();
        assertInstanceOf(DataChannelReceiveOverflowException.class, error.cause());
        assertTrue(remoteBulk.messagesDropped() > 0);
        chat.send("still here");
        assertEquals(new DataChannelMessage.Text("still here"), remoteChat.receive(TIMEOUT).orElseThrow());
    }

    @Test
    @DisplayName("fails a send past the buffered amount limit at once, and waits for room when asked to")
    void sendNeverBlocks() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var pair = connect(SctpConfig.defaults().withMaxBufferedAmount(64 * 1024), SctpConfig.defaults(), pipe[0], pipe[1]);
        var local = pair[0].createDataChannel("bulk", DataChannelInit.reliable());
        var remote = pair[1].acceptDataChannel(TIMEOUT).orElseThrow();
        var stalled = new AtomicBoolean(true);
        pipe[0].setDrop(_ -> stalled.get());
        var message = new DataChannelMessage.Binary(ByteBuffer.allocate(16 * 1024));
        var sent = 0;
        var start = System.nanoTime();
        assertThrows(DataChannelBufferFullException.class, () -> {
            for (var index = 0; index < 100; index++) {
                local.send(message);
            }
        });
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(2)) < 0, "send blocked");
        assertFalse(local.send(message, Duration.ofMillis(100)));
        stalled.set(false);
        assertTrue(local.send(message, TIMEOUT));
        while (remote.receive(Duration.ofMillis(500)).isPresent()) {
            sent++;
        }
        assertTrue(sent >= 4, "received " + sent);
    }

    @Test
    @DisplayName("hands messages that arrived before a negotiated channel was created to that channel")
    void lateNegotiatedChannel() throws Exception {
        var pair = connect(SctpConfig.defaults(), SctpConfig.defaults());
        var init = DataChannelInit.reliable().withNegotiatedId(7);
        var early = pair[0].createDataChannel("late", init);
        early.send("early");
        early.send("second");
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        Thread.sleep(300);
        var late = pair[1].createDataChannel("late", init);
        assertEquals(new DataChannelMessage.Text("early"), late.receive(TIMEOUT).orElseThrow());
        assertEquals(new DataChannelMessage.Text("second"), late.receive(TIMEOUT).orElseThrow());
        assertTrue(System.nanoTime() < deadline);
        assertEquals(0, pair[1].unclaimedMessagesDropped());
    }

    @Test
    @DisplayName("bounds the messages kept for streams without a channel and counts the rest")
    void unclaimedBound() throws Exception {
        var pair = connect(SctpConfig.defaults(), SctpConfig.defaults());
        var channel = pair[0].createDataChannel("flood", DataChannelInit.reliable().withNegotiatedId(9));
        for (var index = 0; index < SctpTransport.MAX_UNCLAIMED_MESSAGES + 10; index++) {
            channel.send("m" + index);
        }
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (pair[1].unclaimedMessagesDropped() < 10 && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertEquals(10, pair[1].unclaimedMessagesDropped());
        var late = pair[1].createDataChannel("flood", DataChannelInit.reliable().withNegotiatedId(9));
        assertEquals(new DataChannelMessage.Text("m0"), late.receive(TIMEOUT).orElseThrow());
    }

    @Test
    @DisplayName("refuses a DATA_CHANNEL_OPEN on a stream id of this side's parity")
    void openWithLocalParity() throws Exception {
        var pair = connect(SctpConfig.defaults(), SctpConfig.defaults());
        var open = DcepMessage.Open.of("intruder", DataChannelInit.reliable());
        // The client opens on an even id of its own and on an odd id, which is the server's to use.
        assertTrue(pair[0].trySendMessage(2, PayloadProtocol.DCEP, open.encode(), true, DataChannelInit.reliable()));
        assertTrue(pair[1].acceptDataChannel(TIMEOUT).isPresent());
        assertTrue(pair[0].trySendMessage(1, PayloadProtocol.DCEP, open.encode(), true, DataChannelInit.reliable()));
        assertTrue(pair[1].acceptDataChannel(Duration.ofMillis(500)).isEmpty());
    }

    @Test
    @DisplayName("raises Opened, Closing and Closed in order and reports the maximum message size")
    void events() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var client = SctpTransport.overDatagrams(pipe[0], SctpConfig.defaults());
        var server = SctpTransport.overDatagrams(pipe[1], SctpConfig.defaults().withMaxMessageSize(5000));
        opened.add(client);
        opened.add(server);
        var channel = client.createDataChannel("events", DataChannelInit.reliable());
        assertEquals(SctpTransport.DEFAULT_REMOTE_MAX_MESSAGE_SIZE, channel.maxMessageSize());
        var events = new CopyOnWriteArrayList<DataChannelEvent>();
        channel.eventSink(events::add);
        var thread = Thread.ofVirtual().start(() -> assertDoesNotThrow(() ->
                server.start(DtlsRole.SERVER, 5000, OptionalLong.empty(), TIMEOUT)));
        client.start(DtlsRole.CLIENT, 5000, OptionalLong.of(5000), TIMEOUT);
        thread.join();
        assertTrue(channel.awaitOpen(TIMEOUT));
        assertEquals(5000, channel.maxMessageSize());
        var remote = server.acceptDataChannel(TIMEOUT).orElseThrow();
        channel.close();
        assertTrue(channel.awaitClosed(TIMEOUT));
        assertTrue(remote.awaitClosed(TIMEOUT));
        assertEquals(List.of(new DataChannelEvent.Opened(), new DataChannelEvent.Closing(), new DataChannelEvent.Closed()),
                events);
    }

    @Test
    @DisplayName("closes without throwing when the DTLS layer underneath fails during shutdown")
    void closeSurvivesFailingLower() throws Exception {
        var pipe = LoopbackDatagramTransport.pair();
        var failing = new AtomicBoolean();
        var path = new DatagramTransport() {
            @Override
            public void send(ByteBuffer datagram) throws IOException {
                if (failing.get()) {
                    throw new IllegalStateException("the DTLS association is not connected");
                }
                pipe[0].send(datagram);
            }

            @Override
            public void setReceiver(PacketReceiver receiver) {
                pipe[0].setReceiver(receiver);
            }

            @Override
            public int maxDatagramSize() {
                return pipe[0].maxDatagramSize();
            }

            @Override
            public void close() {
                pipe[0].close();
            }
        };
        var pair = connect(SctpConfig.defaults(), SctpConfig.defaults(), path, pipe[1]);
        var channel = pair[0].createDataChannel("doomed", DataChannelInit.reliable());
        failing.set(true);
        assertDoesNotThrow(pair[0]::close);
        assertEquals(SctpTransportState.CLOSED, pair[0].state());
        assertEquals(DataChannelState.CLOSED, channel.readyState());
    }
}
