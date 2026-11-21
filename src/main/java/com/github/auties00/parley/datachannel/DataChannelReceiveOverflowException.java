package com.github.auties00.parley.datachannel;

import java.io.IOException;
import java.io.Serial;

/// The cause of the [DataChannelEvent.Error] a channel raises when a received message would take it past
/// [SctpConfig#maxReceiveBufferedBytes()]: the application did not take messages as fast as the peer sent them. The
/// message is dropped and the channel is closed, so the other channels of the association keep receiving.
public final class DataChannelReceiveOverflowException extends IOException {
    @Serial
    private static final long serialVersionUID = 1L;

    /// Creates the exception.
    ///
    /// @param message the detail message
    public DataChannelReceiveOverflowException(String message) {
        super(message);
    }
}
