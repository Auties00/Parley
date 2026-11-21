package com.github.auties00.parley.ice;

import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.StreamConnection;
import com.github.auties00.parley.net.StreamListener;
import com.github.auties00.parley.turn.TurnAllocation;
import com.github.auties00.parley.turn.TurnClient;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/// The network resource behind a local candidate, the one datagrams of its pairs leave through.
sealed interface IcePath {
    /// A UDP socket: host candidates and the server-reflexive candidates based on them.
    ///
    /// @param endpoint the socket
    record UdpPath(DatagramEndpoint endpoint) implements IcePath {
    }

    /// A TURN allocation: relayed candidates.
    ///
    /// @param client     the client holding the allocation
    /// @param allocation the allocation
    record RelayPath(TurnClient client, TurnAllocation allocation) implements IcePath {
    }

    /// A listening TCP socket: passive TCP host candidates, whose pairs each own an accepted [TcpLink].
    ///
    /// @param listener the listener
    record TcpPassivePath(StreamListener listener) implements IcePath {
    }

    /// The local address active TCP host candidates connect from; each pair opens its own [TcpLink].
    ///
    /// @param address the local address
    record TcpActivePath(InetAddress address) implements IcePath {
    }

    /// One TCP connection of an ICE-TCP pair, framing every datagram with the two-byte length of RFC 4571.
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// -----------------------------------------------------------------
    /// |             LENGTH            |  STUN, DTLS, RTP or RTCP ...  |
    /// -----------------------------------------------------------------
    /// ```
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc4571.html RFC 4571: Framing Real-time Transport Protocol (RTP) and RTP Control Protocol (RTCP) Packets over Connection-Oriented Transport
    /// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
    final class TcpLink {
        /// The connection.
        private final StreamConnection connection;

        /// The lock that keeps frames from interleaving.
        private final Object writeLock = new Object();

        /// Creates a link over a connection.
        TcpLink(StreamConnection connection) {
            this.connection = connection;
        }

        /// {@return the peer's address}
        InetSocketAddress remoteAddress() {
            return connection.remoteAddress();
        }

        /// Writes one datagram as a frame.
        ///
        /// @throws IOException if the datagram is longer than 65535 bytes or the write fails
        void send(ByteBuffer datagram) throws IOException {
            var length = datagram.remaining();
            if (length > 0xFFFF) {
                throw new IOException("datagram longer than 65535 bytes");
            }
            var frame = ByteBuffer.allocate(2 + length).putShort((short) length).put(datagram).flip();
            synchronized (writeLock) {
                while (frame.hasRemaining()) {
                    connection.write(frame);
                }
            }
        }

        /// Reads frames until the connection ends, handing each to `receiver`.
        ///
        /// @throws IOException when the connection ends or fails
        void readLoop(FrameReceiver receiver) throws IOException {
            var buffer = ByteBuffer.allocate(2 * (0xFFFF + 2));
            while (true) {
                if (connection.read(buffer) < 0) {
                    throw new EOFException("ICE-TCP connection closed");
                }
                buffer.flip();
                while (buffer.remaining() >= 2) {
                    var length = buffer.getShort(buffer.position()) & 0xFFFF;
                    if (buffer.remaining() < 2 + length) {
                        break;
                    }
                    receiver.receive(buffer.slice(buffer.position() + 2, length));
                    buffer.position(buffer.position() + 2 + length);
                }
                buffer.compact();
            }
        }

        /// Closes the connection.
        void close() {
            try {
                connection.close();
            } catch (IOException _) {
                // A failed close leaves nothing to release.
            }
        }

        /// Receives the frames of a link.
        @FunctionalInterface
        interface FrameReceiver {
            /// Handles one frame's payload, valid only during the call.
            void receive(ByteBuffer frame);
        }
    }
}
