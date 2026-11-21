package com.github.auties00.parley.datachannel;

import java.io.IOException;
import java.io.Serial;

/// Thrown by [DataChannel#send(DataChannelMessage)] when the message does not fit in the send buffer: the channel's
/// [buffered amount][DataChannel#bufferedAmount()] would exceed [SctpConfig#maxBufferedAmount()], or the association's
/// send buffer is full. The message was not sent; the W3C `send()` throws `OperationError` in this case.
///
/// A producer that would rather wait for room uses [DataChannel#send(DataChannelMessage,java.time.Duration)], or waits
/// with [DataChannel#awaitBufferedAmountLow(java.time.Duration)].
///
/// @spec https://www.w3.org/TR/webrtc/#dom-rtcdatachannel-send WebRTC: Real-Time Communication in Browsers, send()
public final class DataChannelBufferFullException extends IOException {
    @Serial
    private static final long serialVersionUID = 1L;

    /// Creates the exception.
    ///
    /// @param message the detail message
    public DataChannelBufferFullException(String message) {
        super(message);
    }
}
