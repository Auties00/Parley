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
        try (var a = builder(eventsA).buildUdp(LOOPBACK); var b = builder(eventsB).buildUdp(LOOPBACK)) {
            var keys = SrtpTransportTest.Keys.of(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, 9);
            var atA = new LinkedBlockingQueue<byte[]>();
            var atB = new LinkedBlockingQueue<byte[]>();
            a.setRtpReceiver((packet, _) -> atA.add(SrtpTransportTest.bytes(packet)));
            b.setRtpReceiver((packet, _) -> atB.add(SrtpTransportTest.bytes(packet)));
            var wrongPort = new InetSocketAddress(InetAddress.getLoopbackAddress(), 9);
            a.establishSdes(b.localAddress().orElseThrow(), SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80,
                    keys.key1(), keys.salt1(), keys.key2(), keys.salt2());
            b.establishSdes(wrongPort, SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80,
                    keys.key2(), keys.salt2(), keys.key1(), keys.salt1());
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
        var a = builder(eventsA).buildUdp(LOOPBACK);
        var b = builder(eventsB).buildUdp(LOOPBACK);
        var atB = new LinkedBlockingQueue<byte[]>();
        b.setRtpReceiver((packet, _) -> atB.add(SrtpTransportTest.bytes(packet)));
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
        assertThrows(IllegalStateException.class, () -> b.sendRtp(ByteBuffer.wrap(packet)));
    }

    @Test
    @DisplayName("fails after a run of packets that do not authenticate")
    void authenticationFailures() throws Exception {
        var events = new LinkedBlockingQueue<MediaTransportEvent>();
        try (var sender = builder(new LinkedBlockingQueue<>()).buildUdp(LOOPBACK);
             var receiver = builder(events).authenticationFailureLimit(5).buildUdp(LOOPBACK)) {
            var keys = SrtpTransportTest.Keys.of(SrtpCryptoSuite.AEAD_AES_128_GCM, 1);
            var other = SrtpTransportTest.Keys.of(SrtpCryptoSuite.AEAD_AES_128_GCM, 2);
            sender.establishSdes(receiver.localAddress().orElseThrow(), SrtpCryptoSuite.AEAD_AES_128_GCM,
                    keys.key1(), keys.salt1(), keys.key2(), keys.salt2());
            receiver.establishSdes(sender.localAddress().orElseThrow(), SrtpCryptoSuite.AEAD_AES_128_GCM,
                    other.key2(), other.salt2(), other.key1(), other.salt1());
            for (var sequence = 0; sequence < 10; sequence++) {
                sender.sendRtp(ByteBuffer.wrap(SrtpTransportTest.rtp(1, sequence, 10)));
            }
            var failed = next(events, MediaTransportEvent.Failed.class);
            var failure = assertInstanceOf(MediaTransportFailure.SrtpAuthentication.class, failed.failure());
            assertTrue(failure.consecutive() >= 5);
            assertTrue(failure.message().contains("SRTP"));
        }
    }

    @Test
    @DisplayName("refuses an establishment of the other mode, a second establishment and sends before one")
    void misuse() throws Exception {
        try (var transport = builder(new LinkedBlockingQueue<>()).buildUdp(LOOPBACK)) {
            assertThrows(IllegalStateException.class, () -> transport.sendRtp(ByteBuffer.wrap(new byte[12])));
            assertThrows(IllegalStateException.class, () -> transport.establishDtlsSrtp(
                    new IceParameters("ufrag", "password", false), List.of(), DtlsRole.CLIENT,
                    transport.fingerprints(), Duration.ofSeconds(1)));
            var keys = SrtpTransportTest.Keys.of(SrtpCryptoSuite.AEAD_AES_128_GCM, 1);
            transport.establishSdes(new InetSocketAddress(InetAddress.getLoopbackAddress(), 9),
                    SrtpCryptoSuite.AEAD_AES_128_GCM, keys.key1(), keys.salt1(), keys.key2(), keys.salt2());
            assertThrows(IllegalStateException.class, () -> transport.establishSdes(
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), 9), SrtpCryptoSuite.AEAD_AES_128_GCM,
                    keys.key1(), keys.salt1(), keys.key2(), keys.salt2()));
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
