package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.media.Priority;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Optional;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the data channel value types and the datagram adapter the SCTP socket runs over.
@DisplayName("Data channel values")
class DataChannelValuesTest {
    @Nested
    @DisplayName("DataChannelInit")
    class Init {
        @Test
        @DisplayName("defaults to the W3C ordered, reliable, in-band channel")
        void defaults() {
            var init = DataChannelInit.reliable();
            assertTrue(init.ordered());
            assertTrue(init.reliableDelivery());
            assertFalse(init.negotiated());
            assertEquals(Priority.LOW, init.priority());
            assertEquals("", init.protocol());
        }

        @Test
        @DisplayName("rejects both reliability limits, negative values, and an id without negotiation")
        void validation() {
            assertThrows(IllegalArgumentException.class, () -> new DataChannelInit(true, OptionalInt.of(1),
                    Optional.of(Duration.ofSeconds(1)), "", false, OptionalInt.empty(), Priority.LOW));
            assertThrows(IllegalArgumentException.class, () -> DataChannelInit.reliable().withMaxRetransmits(-1));
            assertThrows(IllegalArgumentException.class,
                    () -> DataChannelInit.reliable().withMaxPacketLifeTime(Duration.ofMillis(-1)));
            assertThrows(IllegalArgumentException.class, () -> new DataChannelInit(true, OptionalInt.empty(),
                    Optional.empty(), "", false, OptionalInt.of(3), Priority.LOW));
            assertThrows(IllegalArgumentException.class, () -> new DataChannelInit(true, OptionalInt.empty(),
                    Optional.empty(), "", true, OptionalInt.empty(), Priority.LOW));
            assertThrows(IllegalArgumentException.class, () -> DataChannelInit.reliable().withNegotiatedId(65535));
            assertThrows(IllegalArgumentException.class, () -> DataChannelInit.reliable().withProtocol("p".repeat(70_000)));
        }

        @Test
        @DisplayName("clamps limits to the 16-bit range and makes the two limits exclusive")
        void clamping() {
            assertEquals(Duration.ofMillis(65535),
                    DataChannelInit.reliable().withMaxPacketLifeTime(Duration.ofHours(1)).maxPacketLifeTime().orElseThrow());
            assertEquals(65535, DataChannelInit.reliable().withMaxRetransmits(1_000_000).maxRetransmits().getAsInt());
            var swapped = DataChannelInit.reliable().withMaxRetransmits(2).withMaxPacketLifeTime(Duration.ofMillis(10));
            assertTrue(swapped.maxRetransmits().isEmpty());
            assertFalse(swapped.reliableDelivery());
        }
    }

    @ParameterizedTest
    @CsvSource({"0,VERY_LOW", "128,VERY_LOW", "129,LOW", "256,LOW", "300,MEDIUM", "512,MEDIUM", "513,HIGH",
            "1024,HIGH", "65535,HIGH"})
    @DisplayName("maps wire priorities to the W3C priority ranges")
    void priorities(int wire, Priority expected) {
        assertEquals(expected, Priority.ofWireValue(wire));
        assertEquals(expected, Priority.ofWireValue(expected.wireValue()));
    }

    @Test
    @DisplayName("copies binary messages so they stay immutable")
    void binaryImmutable() {
        var source = ByteBuffer.wrap(new byte[]{1, 2, 3});
        var message = new DataChannelMessage.Binary(source);
        source.put(0, (byte) 9);
        assertArrayEquals(new byte[]{1, 2, 3}, message.toByteArray());
        assertTrue(message.value().isReadOnly());
        message.value().get();
        assertEquals(3, message.value().remaining());
        assertEquals(message, new DataChannelMessage.Binary(ByteBuffer.wrap(new byte[]{1, 2, 3})));
        assertNotEquals(message, new DataChannelMessage.Binary(ByteBuffer.wrap(new byte[]{1, 2})));
        assertEquals(6, new DataChannelMessage.Text("\u00e9\u00e9\u00e9").sizeBytes());
    }

    @Test
    @DisplayName("rejects invalid configurations")
    void config() {
        assertThrows(IllegalArgumentException.class, () -> SctpConfig.defaults().withLocalPort(0));
        assertThrows(IllegalArgumentException.class, () -> SctpConfig.defaults().withMaxMessageSize(0));
        assertThrows(IllegalArgumentException.class, () -> SctpConfig.defaults().withMaxSendBufferSize(-1));
        assertEquals(5001, SctpConfig.defaults().withLocalPort(5001).localPort());
        assertThrows(IllegalArgumentException.class, () -> new DataChannelStatistics("", "", OptionalInt.empty(),
                DataChannelState.OPEN, -1, 0, 0, 0));
    }

    @Nested
    @DisplayName("DatagramChannelAdapter")
    class Adapter {
        @Test
        @DisplayName("reads one datagram per call, truncating to the buffer, and writes one per call")
        void datagrams() throws Exception {
            var pipe = LoopbackDatagramTransport.pair();
            var a = new DatagramChannelAdapter(pipe[0]);
            var b = new DatagramChannelAdapter(pipe[1]);
            var data = ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5});
            assertEquals(5, a.write(data));
            assertFalse(data.hasRemaining());
            a.write(ByteBuffer.wrap(new byte[]{6}));
            var into = ByteBuffer.allocate(3);
            assertEquals(3, b.read(into));
            assertArrayEquals(new byte[]{1, 2, 3}, into.array());
            var next = ByteBuffer.allocate(10);
            assertEquals(1, b.read(next));
            assertEquals(6, next.get(0));
        }

        @Test
        @DisplayName("wakes a blocked reader at close and leaves the transport open")
        void closeWakesReader() throws Exception {
            var pipe = LoopbackDatagramTransport.pair();
            var adapter = new DatagramChannelAdapter(pipe[1]);
            var result = new java.util.concurrent.atomic.AtomicInteger(Integer.MIN_VALUE);
            var reader = Thread.ofVirtual().start(() -> {
                try {
                    result.set(adapter.read(ByteBuffer.allocate(10)));
                } catch (Exception exception) {
                    result.set(Integer.MAX_VALUE);
                }
            });
            Thread.sleep(50);
            adapter.close();
            reader.join(5_000);
            assertEquals(-1, result.get());
            assertFalse(adapter.isOpen());
            assertEquals(-1, adapter.read(ByteBuffer.allocate(1)));
            assertThrows(java.nio.channels.ClosedChannelException.class, () -> adapter.write(ByteBuffer.allocate(1)));
            pipe[0].send(ByteBuffer.allocate(1));
        }

        @Test
        @DisplayName("drops datagrams beyond its queue capacity instead of blocking the sender")
        void overflow() throws Exception {
            var pipe = LoopbackDatagramTransport.pair();
            var adapter = new DatagramChannelAdapter(pipe[1]);
            for (var index = 0; index < DatagramChannelAdapter.QUEUE_CAPACITY + 10; index++) {
                pipe[0].send(ByteBuffer.allocate(1));
            }
            assertEquals(10, adapter.droppedDatagrams());
        }
    }
}
