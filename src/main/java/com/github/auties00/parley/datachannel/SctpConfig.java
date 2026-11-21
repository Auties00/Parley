package com.github.auties00.parley.datachannel;

import java.util.Objects;
import java.util.concurrent.ThreadFactory;

/// The configuration of an [SctpTransport].
///
/// @param localPort               the local SCTP port, announced in `a=sctp-port`; `1` to `65535`
/// @param maxMessageSize          the largest message this endpoint accepts, announced in `a=max-message-size`;
///                                positive
/// @param maxSendBufferSize       the bytes the association buffers for sending before sends block, positive
/// @param maxReceiveBufferedBytes the bytes one channel holds received but not yet taken by `receive`; the
///                                transport stops reading the association while a channel is over this bound
/// @param messageInterleaving     whether to offer RFC 8260 user message interleaving (I-DATA); it is used when
///                                the peer offers it too
/// @param threadFactory           the factory of the transport's reader thread and of the threads that close
///                                channels
///
/// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
/// @spec https://www.rfc-editor.org/rfc/rfc8260.html RFC 8260: Stream Schedulers and User Message Interleaving for the Stream Control Transmission Protocol
public record SctpConfig(int localPort, long maxMessageSize, int maxSendBufferSize, long maxReceiveBufferedBytes,
                         boolean messageInterleaving, ThreadFactory threadFactory) {
    /// The SCTP port WebRTC endpoints use by default.
    public static final int DEFAULT_PORT = 5000;

    /// The default largest accepted message: 256 KiB.
    public static final long DEFAULT_MAX_MESSAGE_SIZE = 256 * 1024;

    /// The default send buffer: about 2 MB.
    public static final int DEFAULT_MAX_SEND_BUFFER_SIZE = 2_000_000;

    /// The default per-channel receive bound: 16 MiB.
    public static final long DEFAULT_MAX_RECEIVE_BUFFERED_BYTES = 16L * 1024 * 1024;

    /// Validates the configuration.
    ///
    /// @throws IllegalArgumentException if `localPort` is outside `1` to `65535` or a size is not positive
    public SctpConfig {
        Objects.requireNonNull(threadFactory, "threadFactory");
        if (localPort < 1 || localPort > 0xFFFF) {
            throw new IllegalArgumentException("localPort must be in 1..65535: " + localPort);
        }
        if (maxMessageSize <= 0 || maxSendBufferSize <= 0 || maxReceiveBufferedBytes <= 0) {
            throw new IllegalArgumentException("sizes must be positive");
        }
    }

    /// {@return the default configuration}: port 5000, 256 KiB messages, a 2 MB send buffer, 16 MiB per channel
    /// received, interleaving offered, and virtual threads named `parley-sctp-<n>`
    public static SctpConfig defaults() {
        return new SctpConfig(DEFAULT_PORT, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MAX_SEND_BUFFER_SIZE,
                DEFAULT_MAX_RECEIVE_BUFFERED_BYTES, true, Thread.ofVirtual().name("parley-sctp-", 0).factory());
    }

    /// {@return a copy using `localPort`}
    ///
    /// @param localPort the local SCTP port
    /// @throws IllegalArgumentException if `localPort` is outside `1` to `65535`
    public SctpConfig withLocalPort(int localPort) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory);
    }

    /// {@return a copy accepting messages up to `maxMessageSize` bytes}
    ///
    /// @param maxMessageSize the largest accepted message, positive
    /// @throws IllegalArgumentException if `maxMessageSize` is not positive
    public SctpConfig withMaxMessageSize(long maxMessageSize) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory);
    }

    /// {@return a copy with the given send buffer}
    ///
    /// @param maxSendBufferSize the send buffer, positive
    /// @throws IllegalArgumentException if `maxSendBufferSize` is not positive
    public SctpConfig withMaxSendBufferSize(int maxSendBufferSize) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory);
    }

    /// {@return a copy with the given per-channel receive bound}
    ///
    /// @param maxReceiveBufferedBytes the receive bound, positive
    /// @throws IllegalArgumentException if `maxReceiveBufferedBytes` is not positive
    public SctpConfig withMaxReceiveBufferedBytes(long maxReceiveBufferedBytes) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory);
    }

    /// {@return a copy that offers interleaving or not}
    ///
    /// @param messageInterleaving whether to offer I-DATA
    public SctpConfig withMessageInterleaving(boolean messageInterleaving) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory);
    }

    /// {@return a copy starting its threads from `threadFactory`}
    ///
    /// @param threadFactory the thread factory
    public SctpConfig withThreadFactory(ThreadFactory threadFactory) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory);
    }
}
