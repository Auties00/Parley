package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.rtcp.RtcpFormatException;
import com.github.auties00.parley.rtp.rtcp.RtcpPacket;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SplittableRandom;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertTrue;

/// An in-memory network of two endpoints with a shared manual clock: datagrams are queued until the test delivers
/// them, can be dropped by predicate, and receive buffers are scribbled over after each callback so a receiver that
/// keeps a buffer beyond its call fails.
final class TestNetwork {
    static final int OVERHEAD = 16;

    final ManualClock clock = new ManualClock();
    final Endpoint left = new Endpoint("left");
    final Endpoint right = new Endpoint("right");
    private final ArrayDeque<Datagram> queue = new ArrayDeque<>();

    TestNetwork() {
        left.peer = right;
        right.peer = left;
    }

    /// A monotonic clock moved by hand, also usable as the wall clock.
    static final class ManualClock implements MonotonicClock, InstantSource {
        private long nanos = 1_000_000_000L;

        @Override
        public long nanos() {
            return nanos;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochSecond(1_800_000_000L).plusNanos(nanos);
        }

        void advanceMillis(long millis) {
            nanos += millis * 1_000_000L;
        }
    }

    private record Datagram(Endpoint to, byte[] bytes, boolean rtcp) {
    }

    /// One side of the network, the transport a session runs over.
    final class Endpoint implements SessionTransport {
        final String name;
        Endpoint peer;
        PacketReceiver rtpReceiver = (packet, arrival) -> {
        };
        PacketReceiver rtcpReceiver = (packet, arrival) -> {
        };
        Predicate<RtpPacket> dropRtp = packet -> false;
        Predicate<List<RtcpPacket>> dropRtcp = packets -> false;
        final List<RtpPacket> sentRtp = java.util.Collections.synchronizedList(new ArrayList<>());
        final List<List<RtcpPacket>> sentRtcp = java.util.Collections.synchronizedList(new ArrayList<>());

        Endpoint(String name) {
            this.name = name;
        }

        @Override
        public void sendRtp(ByteBuffer plainRtp) {
            assertTrue(plainRtp.capacity() - plainRtp.limit() >= OVERHEAD, "missing SRTP tailroom");
            var bytes = new byte[plainRtp.remaining()];
            plainRtp.duplicate().get(bytes);
            Arrays.fill(plainRtp.array(), plainRtp.position(), plainRtp.limit(), (byte) 0x5A);
            try {
                var packet = RtpPacket.parse(ByteBuffer.wrap(bytes));
                sentRtp.add(packet);
                if (!dropRtp.test(packet)) {
                    queue.add(new Datagram(peer, bytes, false));
                }
            } catch (RtpFormatException exception) {
                throw new AssertionError(exception);
            }
        }

        @Override
        public void sendRtcp(ByteBuffer plainCompoundRtcp) {
            assertTrue(plainCompoundRtcp.capacity() - plainCompoundRtcp.limit() >= OVERHEAD, "missing SRTCP tailroom");
            var bytes = new byte[plainCompoundRtcp.remaining()];
            plainCompoundRtcp.duplicate().get(bytes);
            try {
                var packets = RtcpPacket.parseCompound(ByteBuffer.wrap(bytes));
                sentRtcp.add(packets);
                if (!dropRtcp.test(packets)) {
                    queue.add(new Datagram(peer, bytes, true));
                }
            } catch (RtcpFormatException exception) {
                throw new AssertionError(exception);
            }
        }

        @Override
        public void setRtpReceiver(PacketReceiver receiver) {
            this.rtpReceiver = receiver;
        }

        @Override
        public void setRtcpReceiver(PacketReceiver receiver) {
            this.rtcpReceiver = receiver;
        }

        @Override
        public int protectionOverhead() {
            return OVERHEAD;
        }

        <T> List<T> sentRtcpOf(Class<T> type) {
            var out = new ArrayList<T>();
            for (var compound : sentRtcp) {
                for (var packet : compound) {
                    if (type.isInstance(packet)) {
                        out.add(type.cast(packet));
                    }
                }
            }
            return out;
        }
    }

    /// Delivers every queued datagram, including those sent in reaction, in order.
    void deliver() {
        var rounds = 0;
        while (!queue.isEmpty()) {
            if (++rounds > 100_000) {
                throw new AssertionError("delivery does not converge");
            }
            var datagram = queue.poll();
            var buffer = ByteBuffer.wrap(datagram.bytes().clone());
            if (datagram.rtcp()) {
                datagram.to().rtcpReceiver.receive(buffer, clock.nanos());
            } else {
                datagram.to().rtpReceiver.receive(buffer, clock.nanos());
            }
            Arrays.fill(buffer.array(), (byte) 0x5A);
        }
    }

    RtpSession.Builder session(Endpoint endpoint, long localSsrc) {
        return RtpSession.builder(endpoint).clock(clock).wallClock(clock).manualTimers()
                .random(new SplittableRandom(localSsrc)).localSsrc(localSsrc).cname(endpoint.name);
    }
}
