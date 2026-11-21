package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.transport.RtpTransport;

import java.io.IOException;
import java.nio.ByteBuffer;

/// The part of an [RtpTransport] a session uses, so tests can drive a session over an in-memory transport.
interface SessionTransport {
    void sendRtp(ByteBuffer plainRtp) throws IOException;

    void sendRtcp(ByteBuffer plainCompoundRtcp) throws IOException;

    void setRtpReceiver(PacketReceiver receiver);

    void setRtcpReceiver(PacketReceiver receiver);

    int protectionOverhead();

    static SessionTransport of(RtpTransport transport) {
        return new SessionTransport() {
            @Override
            public void sendRtp(ByteBuffer plainRtp) throws IOException {
                transport.sendRtp(plainRtp);
            }

            @Override
            public void sendRtcp(ByteBuffer plainCompoundRtcp) throws IOException {
                transport.sendRtcp(plainCompoundRtcp);
            }

            @Override
            public void setRtpReceiver(PacketReceiver receiver) {
                transport.setRtpReceiver(receiver);
            }

            @Override
            public void setRtcpReceiver(PacketReceiver receiver) {
                transport.setRtcpReceiver(receiver);
            }

            @Override
            public int protectionOverhead() {
                return transport.protectionOverhead();
            }
        };
    }
}
