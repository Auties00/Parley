package com.github.auties00.parley.net;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/// Covers the DSCP marking hook of [DatagramEndpoint]: the refusing default and the JDK stack's `IP_TOS`.
@DisplayName("DatagramEndpoint.setTrafficClass")
class TrafficClassTest {
    @Test
    @DisplayName("refuses by default and checks the code point range")
    void defaults() {
        DatagramEndpoint endpoint = new DatagramEndpoint() {
            @Override
            public InetSocketAddress localAddress() {
                return new InetSocketAddress(0);
            }

            @Override
            public void send(ByteBuffer datagram, InetSocketAddress remote) {
            }

            @Override
            public InetSocketAddress receive(ByteBuffer destination) {
                return new InetSocketAddress(0);
            }

            @Override
            public void close() {
            }
        };
        assertFalse(endpoint.setTrafficClass(46));
        assertThrows(IllegalArgumentException.class, () -> endpoint.setTrafficClass(64));
        assertThrows(IllegalArgumentException.class, () -> endpoint.setTrafficClass(-1));
    }

    @Test
    @DisplayName("marks the JDK stack's datagrams and keeps sending whatever the platform decides")
    void system() throws IOException {
        var stack = NetworkStack.system(Thread.ofVirtual().factory());
        var loopback = InetAddress.ofLiteral("127.0.0.1");
        try (var first = stack.bindUdp(new InetSocketAddress(loopback, 0));
             var second = stack.bindUdp(new InetSocketAddress(loopback, 0))) {
            first.setTrafficClass(46);
            first.send(ByteBuffer.wrap(new byte[]{1}), second.localAddress());
            second.receive(ByteBuffer.allocate(4));
            assertThrows(IllegalArgumentException.class, () -> first.setTrafficClass(100));
        }
    }
}
