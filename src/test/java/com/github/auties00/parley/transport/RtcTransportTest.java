package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsDatagramIo;
import com.github.auties00.parley.dtls.DtlsEndpoint;
import com.github.auties00.parley.dtls.DtlsSrtpKeys;
import com.github.auties00.parley.dtls.SrtpProfile;
import com.github.auties00.parley.ice.IceAgent;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceCredentials;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.stun.StunMessage;
import com.github.auties00.srtp.SrtpCryptoSuite;
import com.github.auties00.srtp.SrtpErrorStatus;
import com.github.auties00.srtp.SrtpPacket;
import com.github.auties00.srtp.SrtpTransformer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/// Runs [RtcTransport] over real loopback UDP sockets: against a second transport with SDES keys, and against an
/// in-test `ice-lite` peer that is the DTLS client.
@DisplayName("RtcTransport")
class RtcTransportTest {
    private static final ThreadFactory THREADS = Thread.ofVirtual().factory();

    @Test
    @DisplayName("exchanges SRTP packets with another transport keyed through SDES")
    void sdesLoopback() throws Exception {
        var loopback = InetAddress.getLoopbackAddress();
        try (var left = RtcTransport.open(loopback, THREADS); var right = RtcTransport.open(loopback, THREADS)) {
            var leftKey = new byte[16];
            var leftSalt = new byte[14];
            var rightKey = new byte[16];
            var rightSalt = new byte[14];
            Arrays.fill(leftKey, (byte) 1);
            Arrays.fill(rightKey, (byte) 2);
            left.establishSdes(new InetSocketAddress(loopback, right.localPort()), SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80,
                    leftKey, leftSalt, rightKey, rightSalt);
            right.establishSdes(new InetSocketAddress(loopback, left.localPort()), SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80,
                    rightKey, rightSalt, leftKey, leftSalt);
            var received = new LinkedBlockingQueue<RtpPacket>();
            right.setListener(new CollectingListener(received));
            left.sendRtp(new RtpPacket(111, true, 7, 960, 42, new byte[]{9, 8, 7}));
            var packet = received.poll(5, TimeUnit.SECONDS);
            assertNotNull(packet);
            assertArrayEquals(new byte[]{9, 8, 7}, packet.payload());
            assertEquals(7, packet.sequence());
        }
    }

    @Test
    @DisplayName("connects to an ice-lite peer that is the DTLS client and carries SRTP both ways")
    void webRtcAgainstLitePeer() throws Exception {
        var loopback = InetAddress.getLoopbackAddress();
        try (var transport = RtcTransport.open(loopback, THREADS); var peerSocket = new DatagramSocket(0, loopback)) {
            var peerCredentials = IceCredentials.generate();
            var peerCertificate = DtlsCertificate.generate();
            var peerAddress = new InetSocketAddress(loopback, peerSocket.getLocalPort());
            var transportAddress = new InetSocketAddress(loopback, transport.localPort());
            var dtlsQueue = new LinkedBlockingQueue<byte[]>();
            var mediaQueue = new LinkedBlockingQueue<byte[]>();
            var peerAgent = new IceAgent(peerCredentials, transport.localCredentials(), false,
                    (data, target) -> peerSocket.send(new DatagramPacket(data, data.length, target)));
            Thread.ofVirtual().start(() -> {
                var buffer = new byte[2048];
                while (!peerSocket.isClosed()) {
                    var packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        peerSocket.receive(packet);
                    } catch (Exception exception) {
                        return;
                    }
                    var data = Arrays.copyOf(buffer, packet.getLength());
                    var first = data[0] & 0xFF;
                    if (StunMessage.isStun(data, 0, data.length)) {
                        peerAgent.handle(StunMessage.decode(data, 0, data.length), (InetSocketAddress) packet.getSocketAddress());
                    } else if (first >= 20 && first <= 63) {
                        dtlsQueue.add(data);
                    } else {
                        mediaQueue.add(data);
                    }
                }
            });
            var peerKeys = new AtomicReference<DtlsSrtpKeys>();
            var peerFailure = new AtomicReference<Throwable>();
            var peerDtls = Thread.ofVirtual().start(() -> {
                try {
                    var endpoint = new DtlsEndpoint(DtlsEndpoint.Role.CLIENT, peerCertificate,
                            transport.certificate().fingerprint(), List.of(SrtpProfile.AES128_CM_HMAC_SHA1_80),
                            new DtlsDatagramIo() {
                                @Override
                                public void send(byte[] datagram) throws java.io.IOException {
                                    peerSocket.send(new DatagramPacket(datagram, datagram.length, transportAddress));
                                }

                                @Override
                                public byte[] receive(long timeoutNanos) throws InterruptedException {
                                    return dtlsQueue.poll(timeoutNanos, TimeUnit.NANOSECONDS);
                                }
                            });
                    peerKeys.set(endpoint.handshake(Duration.ofSeconds(10)));
                } catch (Throwable throwable) {
                    peerFailure.set(throwable);
                }
            });
            var candidate = IceCandidate.host("1", peerAddress, 65535);
            var profile = transport.establishWebRtc(peerCredentials, List.of(candidate), DtlsEndpoint.Role.SERVER,
                    peerCertificate.fingerprint(), Duration.ofSeconds(10));
            peerDtls.join(10_000);
            if (peerFailure.get() != null) {
                throw new AssertionError("peer DTLS failed", peerFailure.get());
            }
            assertEquals(SrtpProfile.AES128_CM_HMAC_SHA1_80, profile);
            assertEquals(peerAddress, transport.remoteAddress());

            transport.sendRtp(new RtpPacket(111, false, 1, 960, 99, new byte[]{1, 2, 3, 4}));
            var protectedPacket = mediaQueue.poll(5, TimeUnit.SECONDS);
            assertNotNull(protectedPacket);
            var keys = peerKeys.get();
            try (var inbound = new SrtpTransformer(keys.remoteKey(), keys.remoteSalt(), SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80);
                 var outbound = new SrtpTransformer(keys.localKey(), keys.localSalt(), SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80)) {
                var srtp = new SrtpPacket(protectedPacket, 0, protectedPacket.length);
                assertEquals(SrtpErrorStatus.OK, inbound.unprotectRtp(srtp));
                assertArrayEquals(new byte[]{1, 2, 3, 4}, RtpPacket.decode(protectedPacket, 0, srtp.length()).payload());

                var received = new LinkedBlockingQueue<RtpPacket>();
                transport.setListener(new CollectingListener(received));
                var reply = new RtpPacket(111, false, 5, 1920, 77, new byte[]{5, 6});
                var buffer = reply.encode(16);
                var outgoing = new SrtpPacket(buffer, 0, reply.length());
                assertEquals(SrtpErrorStatus.OK, outbound.protectRtp(outgoing));
                peerSocket.send(new DatagramPacket(buffer, outgoing.length(), transportAddress));
                var delivered = received.poll(5, TimeUnit.SECONDS);
                assertNotNull(delivered);
                assertArrayEquals(new byte[]{5, 6}, delivered.payload());
            }
        }
    }

    private record CollectingListener(LinkedBlockingQueue<RtpPacket> received) implements RtcTransport.Listener {
        @Override
        public void onRtp(RtpPacket packet) {
            received.add(packet);
        }

        @Override
        public void onRtcp(byte[] packet) {
        }

        @Override
        public void onFailure(RtcTransport.Failure failure, String message) {
        }
    }
}
