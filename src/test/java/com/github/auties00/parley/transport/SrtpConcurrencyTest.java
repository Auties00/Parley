package com.github.auties00.parley.transport;

import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.srtp.SrtpCryptoSuite;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Regression tests for [SrtpTransport] driven from several threads at once: RTCP from the RTCP timer, the feedback
/// generators and keyframe requests on one feedback SSRC, packets of one stream arriving on two reader threads, and a
/// close racing both. The SRTP library requires each stream to be driven by one thread at a time; the transport must
/// serialize, never corrupt a context or reuse a GCM nonce.
@DisplayName("SrtpTransport under concurrency")
class SrtpConcurrencyTest {
    /// A path that records what it is asked to send and hands nothing back by itself.
    static final class Capture implements DatagramTransport {
        volatile PacketReceiver receiver;
        final List<byte[]> sent = Collections.synchronizedList(new ArrayList<>());

        @Override
        public void send(ByteBuffer datagram) {
            var bytes = new byte[datagram.remaining()];
            datagram.get(bytes);
            sent.add(bytes);
        }

        @Override
        public void setReceiver(PacketReceiver receiver) {
            this.receiver = receiver;
        }

        @Override
        public int maxDatagramSize() {
            return 1500;
        }

        @Override
        public void close() {
        }
    }

    @ParameterizedTest
    @EnumSource(value = SrtpCryptoSuite.class, names = {"AES_CM_128_HMAC_SHA1_80", "AEAD_AES_128_GCM"})
    @DisplayName("protects RTCP of one SSRC from four threads with every packet authenticating at the peer")
    void concurrentSrtcpProtect(SrtpCryptoSuite suite) throws Exception {
        try (var pair = SrtpTransportTest.Pair.sdes(suite, SrtpOptions.DEFAULT)) {
            var threads = 4;
            var perThread = 2_000;
            var failures = new CopyOnWriteArrayList<Throwable>();
            var start = new CountDownLatch(1);
            var done = new CountDownLatch(threads);
            for (var thread = 0; thread < threads; thread++) {
                Thread.ofPlatform().start(() -> {
                    try {
                        start.await();
                        for (var index = 0; index < perThread; index++) {
                            pair.left().sendRtcp(SrtpTransportTest.withTailroom(SrtpTransportTest.senderReport(0x1234),
                                    pair.left().protectionOverhead()));
                        }
                    } catch (Throwable throwable) {
                        failures.add(throwable);
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(60, TimeUnit.SECONDS));
            assertEquals(List.of(), failures);
            var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (pair.rtcpAtRight().size() < threads * perThread && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            var statistics = pair.right().statistics();
            assertEquals(0, statistics.authenticationFailures());
            assertEquals(0, statistics.replayedPackets());
            assertEquals(threads * perThread, pair.rtcpAtRight().size());
        }
    }

    @Test
    @DisplayName("unprotects one SSRC arriving on two reader threads without a corrupted context")
    void concurrentUnprotectOneSsrc() throws Exception {
        var suite = SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80;
        var keys = SrtpTransportTest.Keys.of(suite, 7);
        var out = new Capture();
        var sender = SrtpTransport.sdes(out, keys.first(suite), keys.second(suite));
        var count = 20_000;
        for (var index = 0; index < count; index++) {
            sender.sendRtp(SrtpTransportTest.withTailroom(SrtpTransportTest.rtp(0xABCD, index & 0xFFFF, 200),
                    sender.protectionOverhead()));
        }
        var in = new Capture();
        var receiver = SrtpTransport.sdes(in, keys.second(suite), keys.first(suite));
        var delivered = new AtomicInteger();
        receiver.setRtpReceiver((packet, arrival) -> delivered.incrementAndGet());
        var failures = new CopyOnWriteArrayList<Throwable>();
        var start = new CountDownLatch(1);
        var threads = new ArrayList<Thread>();
        for (var reader = 0; reader < 2; reader++) {
            var parity = reader;
            threads.add(Thread.ofPlatform().start(() -> {
                try {
                    start.await();
                    for (var index = parity; index < count; index += 2) {
                        in.receiver.receive(ByteBuffer.wrap(out.sent.get(index).clone()), System.nanoTime());
                    }
                } catch (Throwable throwable) {
                    failures.add(throwable);
                }
            }));
        }
        start.countDown();
        for (var thread : threads) {
            thread.join();
        }
        assertEquals(List.of(), failures);
        var statistics = receiver.statistics();
        assertEquals(0, statistics.authenticationFailures());
        assertEquals(count, delivered.get() + statistics.replayedPackets());
        sender.close();
        receiver.close();
    }

    @Test
    @DisplayName("closes while other threads protect and unprotect, failing them only with ClosedChannelException")
    void closeDuringTraffic() throws Exception {
        try (var pair = SrtpTransportTest.Pair.sdes(SrtpCryptoSuite.AEAD_AES_128_GCM, SrtpOptions.DEFAULT)) {
            var failures = new CopyOnWriteArrayList<Throwable>();
            var stop = new java.util.concurrent.atomic.AtomicBoolean();
            var threads = new ArrayList<Thread>();
            for (var sender = 0; sender < 3; sender++) {
                var ssrc = 0x100 + sender;
                threads.add(Thread.ofPlatform().start(() -> {
                    var sequence = 0;
                    while (!stop.get()) {
                        try {
                            pair.left().sendRtp(SrtpTransportTest.withTailroom(SrtpTransportTest.rtp(ssrc, sequence++ & 0xFFFF, 100),
                                    pair.left().protectionOverhead()));
                        } catch (ClosedChannelException closed) {
                            return;
                        } catch (Throwable throwable) {
                            failures.add(throwable);
                            return;
                        }
                    }
                }));
            }
            Thread.sleep(100);
            pair.left().close();
            pair.right().close();
            stop.set(true);
            for (var thread : threads) {
                thread.join(5_000);
            }
            assertEquals(List.of(), failures);
        }
    }
}
