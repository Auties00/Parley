package com.github.auties00.parley.rtp.session;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;

/// The scheduler of [OutgoingPacketScheduler#immediate()].
final class ImmediateScheduler implements OutgoingPacketScheduler {
    static final ImmediateScheduler INSTANCE = new ImmediateScheduler();

    private static final System.Logger LOGGER = System.getLogger(ImmediateScheduler.class.getName());

    private ImmediateScheduler() {
    }

    @Override
    public void schedule(ByteBuffer plainRtp, Priority priority, long ssrc, PacketSink sink) {
        try {
            sink.send(plainRtp);
        } catch (IOException exception) {
            LOGGER.log(Level.DEBUG, "dropping an RTP packet the transport failed to send", exception);
        }
    }

    @Override
    public String toString() {
        return "OutgoingPacketScheduler.immediate()";
    }
}
