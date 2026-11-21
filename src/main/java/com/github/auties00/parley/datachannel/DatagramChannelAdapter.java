package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.net.DatagramTransport;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.LinkedBlockingQueue;

/// Presents a [DatagramTransport] (the DTLS application data) as the one-datagram-per-read-and-write
/// [ByteChannel] the SCTP socket runs over: each `write` sends its whole buffer as one datagram, and each `read`
/// blocks for the next received datagram.
///
/// Received datagrams are queued up to [#QUEUE_CAPACITY]; beyond that they are dropped, as a full socket buffer
/// would, and SCTP retransmits them. Closing the adapter detaches it from the transport without closing the
/// transport, which belongs to the DTLS layer.
final class DatagramChannelAdapter implements ByteChannel {
    /// The most received datagrams waiting for the SCTP reader.
    static final int QUEUE_CAPACITY = 1024;

    /// The marker that wakes a blocked reader at close.
    private static final byte[] END = new byte[0];

    private final DatagramTransport transport;
    private final LinkedBlockingQueue<byte[]> received;
    private volatile boolean closed;
    private volatile long droppedDatagrams;

    /// Creates an adapter and installs it as the transport's receiver.
    ///
    /// @param transport the datagram transport
    DatagramChannelAdapter(DatagramTransport transport) {
        this.transport = transport;
        this.received = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
        transport.setReceiver((packet, _) -> {
            if (closed) {
                return;
            }
            var bytes = new byte[packet.remaining()];
            packet.duplicate().get(bytes);
            if (!received.offer(bytes)) {
                droppedDatagrams++;
            }
        });
    }

    /// Blocks for the next datagram and copies it into `destination`, truncating what does not fit.
    ///
    /// @param destination the buffer to fill from its position
    /// @return the bytes copied, or `-1` once the adapter is closed
    /// @throws ClosedByInterruptException if the reading thread is interrupted, which also closes the adapter
    @Override
    public int read(ByteBuffer destination) throws IOException {
        if (closed) {
            return -1;
        }
        byte[] datagram;
        try {
            datagram = received.take();
        } catch (InterruptedException exception) {
            close();
            Thread.currentThread().interrupt();
            throw new ClosedByInterruptException();
        }
        if (datagram == END) {
            return -1;
        }
        var length = Math.min(datagram.length, destination.remaining());
        destination.put(datagram, 0, length);
        return length;
    }

    /// Sends the remaining bytes of `source` as one datagram and consumes them.
    ///
    /// @param source the datagram
    /// @return the bytes sent
    /// @throws ClosedChannelException if the adapter is closed
    @Override
    public int write(ByteBuffer source) throws IOException {
        if (closed) {
            throw new ClosedChannelException();
        }
        var length = source.remaining();
        transport.send(source.duplicate());
        source.position(source.limit());
        return length;
    }

    @Override
    public boolean isOpen() {
        return !closed;
    }

    /// Detaches the adapter from the transport and wakes a blocked reader. Idempotent; the transport stays open.
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        transport.setReceiver((_, _) -> {
        });
        received.clear();
        received.offer(END);
    }

    /// {@return the datagrams dropped because the queue was full}
    long droppedDatagrams() {
        return droppedDatagrams;
    }
}
