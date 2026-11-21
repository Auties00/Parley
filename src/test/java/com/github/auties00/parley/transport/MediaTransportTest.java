package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.ice.IceParameters;
import com.github.auties00.srtp.SrtpCryptoSuite;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Runs [MediaTransport] in UDP mode over real loopback sockets: SDES with symmetric RTP, DTLS-SRTP without ICE,
/// failure reporting and misuse. ICE mode needs the ice lane's agent and is covered by the integration tests.
@DisplayName("MediaTransport in UDP mode")
class MediaTransportTest {
    private static final InetSocketAddress LOOPBACK = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

    static MediaTransport.Builder builder(LinkedBlockingQueue<MediaTransportEvent> events) {
        return MediaTransport.builder().networkStack(new LoopbackNetworkStack()).eventListener(events::add);
    }

    static <T extends MediaTransportEvent> T next(LinkedBlockingQueue<MediaTransportEvent> events, Class<T> type)
            throws InterruptedException {
        var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            var event = events.poll(100, TimeUnit.MILLISECONDS);
            if (type.isInstance(event)) {
                return type.cast(event);
            }
        }
        throw new AssertionError("no " + type.getSimpleName() + " event");
    }

    @Test
    @DisplayName("carries media with SDES keys and follows the peer's source address")
    void sdes() throws Exception {
        var eventsA = new LinkedBlockingQueue<MediaTransportEvent>();
        var eventsB = new LinkedBlockingQueue<MediaTransportEvent>();
        var atA = new LinkedBlockingQueue<byte[]>();
        var atB = new LinkedBlockingQueue<byte[]>();
        try (var a = builder(eventsA).rtpReceiver((packet, _) -> atA.add(SrtpTransportTest.bytes(packet))).buildUdp(LOOPBACK);
             var b = builder(eventsB).rtpReceiver((packet, _) -> atB.add(SrtpTransportTest.bytes(packet))).buildUdp(LOOPBACK)) {
            var suite = SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80;
            var keys = SrtpTransportTest.Keys.of(suite, 9);
            var wrongPort = new InetSocketAddress(InetAddress.getLoopbackAddress(), 9);
            a.establishSdes(b.localAddress().orElseThrow(), keys.first(suite), keys.second(suite));
            b.establishSdes(wrongPort, keys.second(suite), keys.first(suite));
            assertEquals(next(eventsA, MediaTransportEvent.Established.class).profile(), java.util.Optional.empty());
            var packet = SrtpTransportTest.rtp(1, 1, 100);
            a.sendRtp(ByteBuffer.wrap(packet));
            assertArrayEquals(packet, atB.poll(5, TimeUnit.SECONDS));
            assertEquals(a.localAddress(), b.remoteAddress(), "B latched onto A's address");
            var reply = SrtpTransportTest.rtp(2, 1, 50);
            b.sendRtp(ByteBuffer.wrap(reply));
            assertArrayEquals(reply, atA.poll(5, TimeUnit.SECONDS));
            assertTrue(b.statistics().lastMediaNanos().isPresent());
            assertEquals(1, b.statistics().rtp().orElseThrow().rtpPacketsReceived());
        }
    }

    @Test
    @DisplayName("keys media with a DTLS-SRTP handshake to a fixed address and reports the peer's close")
    void dtlsSrtp() throws Exception {
        var eventsA = new LinkedBlockingQueue<MediaTransportEvent>();
        var eventsB = new LinkedBlockingQueue<MediaTransportEvent>();
        var atB = new LinkedBlockingQueue<byte[]>();
        var a = builder(eventsA).buildUdp(LOOPBACK);
        var b = builder(eventsB).rtpReceiver((packet, _) -> atB.add(SrtpTransportTest.bytes(packet))).buildUdp(LOOPBACK);
        var serverResult = new AtomicReference<Object>();
        var thread = Thread.ofVirtual().start(() -> {
            try {
                serverResult.set(b.establishDtlsSrtp(a.localAddress().orElseThrow(), DtlsRole.SERVER,
                        a.fingerprints(), Duration.ofSeconds(10)));
            } catch (Throwable throwable) {
                serverResult.set(throwable);
            }
        });
        var profile = a.establishDtlsSrtp(b.localAddress().orElseThrow(), DtlsRole.CLIENT, b.fingerprints(),
                Duration.ofSeconds(10));
        thread.join(10_000);
        assertEquals(profile, serverResult.get());
        assertEquals(SrtpProfile.AEAD_AES_128_GCM, profile);
        var packet = SrtpTransportTest.rtp(3, 3, 120);
        a.sendRtp(ByteBuffer.wrap(packet));
        assertArrayEquals(packet, atB.poll(5, TimeUnit.SECONDS));
        assertTrue(a.statistics().dtls().isPresent());
        a.close();
        var failed = next(eventsB, MediaTransportEvent.Failed.class);
        assertInstanceOf(MediaTransportFailure.DtlsClosedByPeer.class, failed.failure());
        assertThrows(ClosedChannelException.class, () -> b.sendRtp(ByteBuffer.wrap(packet)));
    }

    @Test
    @DisplayName("survives 250 garbage datagrams from a third host and keeps its latched peer")
    void garbageNeverFails() throws Exception {
        var events = new LinkedBlockingQueue<MediaTransportEvent>();
        var atB = new LinkedBlockingQueue<byte[]>();
        var suite = SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80;
        var keys = SrtpTransportTest.Keys.of(suite, 5);
        try (var a = builder(new LinkedBlockingQueue<>()).buildUdp(LOOPBACK);
             var b = builder(events).rtpReceiver((packet, _) -> atB.add(SrtpTransportTest.bytes(packet))).buildUdp(LOOPBACK);
             var attacker = java.nio.channels.DatagramChannel.open().bind(LOOPBACK)) {
            a.establishSdes(b.localAddress().orElseThrow(), keys.first(suite), keys.second(suite));
            b.establishSdes(a.localAddress().orElseThrow(), keys.second(suite), keys.first(suite));
            a.sendRtp(ByteBuffer.wrap(SrtpTransportTest.rtp(1, 1, 40)));
            assertTrue(atB.poll(5, TimeUnit.SECONDS) != null);
            var random = new java.util.Random(250);
            for (var index = 0; index < 250; index++) {
                var garbage = SrtpTransportTest.rtp(1, 2 + index, 40);
                for (var offset = 12; offset < garbage.length; offset++) {
                    garbage[offset] = (byte) random.nextInt(256);
                }
                attacker.send(ByteBuffer.wrap(garbage), b.localAddress().orElseThrow());
            }
            var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (b.statistics().rtp().orElseThrow().authenticationFailures() < 250 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            assertEquals(250, b.statistics().rtp().orElseThrow().authenticationFailures());
            assertEquals(a.localAddress(), b.remoteAddress(), "garbage must not move the latched address");
            a.sendRtp(ByteBuffer.wrap(SrtpTransportTest.rtp(1, 300, 40)));
            assertTrue(atB.poll(5, TimeUnit.SECONDS) != null);
            Thread.sleep(200);
            assertTrue(events.stream().noneMatch(MediaTransportEvent.Failed.class::isInstance), events.toString());
        }
    }

    @Test
    @DisplayName("fails with MediaTimeout when nothing authenticates for the media timeout")
    void mediaTimeout() throws Exception {
        var events = new LinkedBlockingQueue<MediaTransportEvent>();
        var suite = SrtpCryptoSuite.AEAD_AES_128_GCM;
        var keys = SrtpTransportTest.Keys.of(suite, 1);
        var other = SrtpTransportTest.Keys.of(suite, 2);
        try (var sender = builder(new LinkedBlockingQueue<>()).buildUdp(LOOPBACK);
             var receiver = builder(events).mediaTimeout(Duration.ofMillis(400)).buildUdp(LOOPBACK)) {
            sender.establishSdes(receiver.localAddress().orElseThrow(), keys.first(suite), keys.second(suite));
            receiver.establishSdes(sender.localAddress().orElseThrow(), other.second(suite), other.first(suite));
            for (var sequence = 0; sequence < 10; sequence++) {
                sender.sendRtp(ByteBuffer.wrap(SrtpTransportTest.rtp(1, sequence, 10)));
            }
            var failed = next(events, MediaTransportEvent.Failed.class);
            var failure = assertInstanceOf(MediaTransportFailure.MediaTimeout.class, failed.failure());
            assertTrue(failure.silence().compareTo(Duration.ofMillis(400)) >= 0);
            assertEquals(10, failure.authenticationFailures());
            assertTrue(failure.message().contains("SRTP"));
            assertThrows(IllegalArgumentException.class, () -> MediaTransport.builder().mediaTimeout(Duration.ZERO));
        }
    }

    @Test
    @DisplayName("refuses an establishment of the other mode, a second establishment and sends before one")
    void misuse() throws Exception {
        try (var transport = builder(new LinkedBlockingQueue<>()).buildUdp(LOOPBACK)) {
            assertThrows(ClosedChannelException.class, () -> transport.sendRtp(ByteBuffer.wrap(new byte[12])));
            assertThrows(IllegalStateException.class, () -> transport.establishDtlsSrtp(
                    new IceParameters("ufrag", "password", false), List.of(), DtlsRole.CLIENT,
                    transport.fingerprints(), Duration.ofSeconds(1)));
            var suite = SrtpCryptoSuite.AEAD_AES_128_GCM;
            var keys = SrtpTransportTest.Keys.of(suite, 1);
            var nowhere = new InetSocketAddress(InetAddress.getLoopbackAddress(), 9);
            assertThrows(IllegalArgumentException.class, () -> transport.establishSdes(nowhere, keys.first(suite),
                    keys.second(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80)));
            transport.establishSdes(nowhere, keys.first(suite), keys.second(suite));
            assertThrows(IllegalStateException.class, () -> transport.establishSdes(nowhere, keys.first(suite),
                    keys.second(suite)));
            assertTrue(transport.iceAgent().isEmpty());
            assertTrue(transport.dtls().isEmpty());
        }
    }

    @Test
    @DisplayName("closes quietly, with no failure event")
    void closeQuietly() throws Exception {
        var events = new LinkedBlockingQueue<MediaTransportEvent>();
        var transport = builder(events).buildUdp(LOOPBACK);
        transport.close();
        transport.close();
        assertNull(events.poll(300, TimeUnit.MILLISECONDS));
    }
}
