package com.github.auties00.parley.transport;

import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.sdp.SdesCrypto;
import com.github.auties00.srtp.SrtpCryptoSuite;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/// SRTP protection and unprotection through [SrtpTransport], SDES-keyed, over an in-memory path that hands each
/// protected datagram to the peer on the sending thread.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class SrtpBenchmark {
    @Param({"AES_CM_128_HMAC_SHA1_80", "AEAD_AES_128_GCM"})
    public String suite;

    @Param({"1200"})
    public int payloadSize;

    private SrtpTransport sender;
    private SrtpTransport receiver;
    private Link link;
    private ByteBuffer packet;
    private byte[] payload;
    private int sequence;
    private long timestamp;

    /// A path whose send calls the peer's receiver, or drops the datagram when `deliver` is off.
    static final class Link {
        final End left = new End();
        final End right = new End();
        boolean deliver = true;

        final class End implements DatagramTransport {
            PacketReceiver receiver = (_, _) -> { };
            End peer;

            @Override
            public void send(ByteBuffer datagram) {
                if (deliver) {
                    peer.receiver.receive(datagram, 0);
                }
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

        Link() {
            left.peer = right;
            right.peer = left;
        }
    }

    static SdesCrypto crypto(SrtpCryptoSuite suite, long seed) {
        var material = new byte[suite.masterKeyLength() + suite.masterSaltLength()];
        new Random(seed).nextBytes(material);
        return new SdesCrypto(1, suite, material);
    }

    @Setup
    public void setup(Blackhole blackhole) {
        var cryptoSuite = SrtpCryptoSuite.valueOf(suite);
        var a = crypto(cryptoSuite, 1);
        var b = crypto(cryptoSuite, 2);
        link = new Link();
        sender = SrtpTransport.sdes(link.left, a, b);
        receiver = SrtpTransport.sdes(link.right, b, a);
        receiver.setRtpReceiver((datagram, _) -> blackhole.consume(datagram.get(datagram.position() + 12)));
        packet = ByteBuffer.allocate(12 + payloadSize + 64);
        payload = new byte[payloadSize];
        new Random(3).nextBytes(payload);
    }

    @TearDown
    public void tearDown() {
        sender.close();
        receiver.close();
    }

    private ByteBuffer nextPacket() {
        var seq = sequence++ & 0xFFFF;
        timestamp += 3000;
        packet.clear();
        packet.put((byte) 0x80).put((byte) 96).putShort((short) seq).putInt((int) timestamp).putInt(0x11223344)
                .put(payload);
        return packet.flip();
    }

    /// Protects one packet and drops it.
    @Benchmark
    public void protect() throws IOException {
        link.deliver = false;
        sender.sendRtp(nextPacket());
    }

    /// Protects one packet and unprotects it at the peer.
    @Benchmark
    public void protectUnprotect() throws IOException {
        link.deliver = true;
        sender.sendRtp(nextPacket());
    }
}
