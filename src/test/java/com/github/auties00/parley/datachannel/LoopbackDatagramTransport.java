package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongPredicate;

/// One end of an in-memory datagram pipe standing in for the DTLS application data of a real transport: what one
/// end sends, the other end's receiver gets synchronously on the sending thread, unless the drop predicate (asked
/// with the datagram's index) says to lose it.
final class LoopbackDatagramTransport implements DatagramTransport {
    private final AtomicReference<PacketReceiver> receiver;
    private final AtomicLong sent;
    private final int maxDatagramSize;
    private volatile LoopbackDatagramTransport peer;
    private volatile LongPredicate drop;
    private volatile boolean closed;

    private LoopbackDatagramTransport(int maxDatagramSize) {
        this.receiver = new AtomicReference<>((_, _) -> {
        });
        this.sent = new AtomicLong();
        this.maxDatagramSize = maxDatagramSize;
        this.drop = _ -> false;
    }

    /// {@return two connected ends}
    static LoopbackDatagramTransport[] pair() {
        return pair(1200);
    }

    /// {@return two connected ends with the given path budget}
    static LoopbackDatagramTransport[] pair(int maxDatagramSize) {
        var a = new LoopbackDatagramTransport(maxDatagramSize);
        var b = new LoopbackDatagramTransport(maxDatagramSize);
        a.peer = b;
        b.peer = a;
        return new LoopbackDatagramTransport[]{a, b};
    }

    /// Makes this end lose the datagrams whose send index matches.
    void setDrop(LongPredicate drop) {
        this.drop = drop;
    }

    /// {@return the datagrams sent from this end}
    long sentDatagrams() {
        return sent.get();
    }

    @Override
    public void send(ByteBuffer datagram) throws IOException {
        if (closed) {
            throw new ClosedChannelException();
        }
        var index = sent.getAndIncrement();
        if (drop.test(index)) {
            return;
        }
        var target = peer;
        if (target == null || target.closed) {
            return;
        }
        var copy = ByteBuffer.allocate(datagram.remaining()).put(datagram.duplicate()).flip();
        target.receiver.get().receive(copy, System.nanoTime());
    }

    @Override
    public void setReceiver(PacketReceiver receiver) {
        this.receiver.set(receiver);
    }

    @Override
    public int maxDatagramSize() {
        return maxDatagramSize;
    }

    @Override
    public void close() {
        closed = true;
    }
}
