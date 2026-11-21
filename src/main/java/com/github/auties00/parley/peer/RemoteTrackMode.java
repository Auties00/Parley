package com.github.auties00.parley.peer;

/// How a [RemoteTrack] delivers what it receives.
public enum RemoteTrackMode {
    /// Encoded frames in decode order after the jitter buffer, read with [RemoteTrack#read()], for an application
    /// that decodes and plays media.
    JITTER_BUFFERED,
    /// Every RTP packet as it arrives, after SRTP and retransmission recovery, read with
    /// [RemoteTrack#readPacket()], for an SFU or a recorder that forwards or stores packets without decoding them.
    RAW_PACKETS
}
