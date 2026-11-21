package com.github.auties00.parley.datachannel;

import java.util.Objects;
import java.util.concurrent.ThreadFactory;

/// The configuration of an [SctpTransport].
///
/// @param localPort               the local SCTP port, announced in `a=sctp-port`; `1` to `65535`
/// @param maxMessageSize          the largest message this endpoint accepts, announced in `a=max-message-size`;
///                                positive
/// @param maxSendBufferSize       the bytes the association buffers for sending across every channel, positive; the
///                                association uses at least [#maxBufferedAmount()]
/// @param maxReceiveBufferedBytes the bytes one channel holds received but not yet taken by `receive`; a message that
///                                would take a channel past it closes that channel with a
///                                [DataChannelReceiveOverflowException], so one slow reader never stalls the others
/// @param messageInterleaving     whether to offer RFC 8260 user message interleaving (I-DATA); it is used when
///                                the peer offers it too
/// @param threadFactory           the factory of the transport's reader thread and of the threads that close
///                                channels and watch their buffered amount
/// @param maxBufferedAmount       the most bytes one channel may have waiting to be sent; a send beyond it fails
///                                with [DataChannelBufferFullException], positive
///
/// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
/// @spec https://www.rfc-editor.org/rfc/rfc8260.html RFC 8260: Stream Schedulers and User Message Interleaving for the Stream Control Transmission Protocol
public record SctpConfig(int localPort, long maxMessageSize, int maxSendBufferSize, long maxReceiveBufferedBytes,
                         boolean messageInterleaving, ThreadFactory threadFactory, long maxBufferedAmount) {
    /// The SCTP port WebRTC endpoints use by default.
    public static final int DEFAULT_PORT = 5000;

    /// The default largest accepted message: 256 KiB.
    public static final long DEFAULT_MAX_MESSAGE_SIZE = 256 * 1024;

    /// The default send buffer: about 2 MB.
    public static final int DEFAULT_MAX_SEND_BUFFER_SIZE = 2_000_000;

    /// The default per-channel receive bound: 16 MiB.
    public static final long DEFAULT_MAX_RECEIVE_BUFFERED_BYTES = 16L * 1024 * 1024;

    /// The default per-channel send bound: 16 MiB, the queue browsers allow a channel before `send()` throws.
    public static final long DEFAULT_MAX_BUFFERED_AMOUNT = 16L * 1024 * 1024;

    /// Validates the configuration.
    ///
    /// @throws IllegalArgumentException if `localPort` is outside `1` to `65535` or a size is not positive
    public SctpConfig {
        Objects.requireNonNull(threadFactory, "threadFactory");
        if (localPort < 1 || localPort > 0xFFFF) {
            throw new IllegalArgumentException("localPort must be in 1..65535: " + localPort);
        }
        if (maxMessageSize <= 0 || maxSendBufferSize <= 0 || maxReceiveBufferedBytes <= 0 || maxBufferedAmount <= 0) {
            throw new IllegalArgumentException("sizes must be positive");
        }
    }

    /// Creates a configuration with the default per-channel send bound, [#DEFAULT_MAX_BUFFERED_AMOUNT].
    ///
    /// @param localPort               the local SCTP port
    /// @param maxMessageSize          the largest accepted message
    /// @param maxSendBufferSize       the association's send buffer
    /// @param maxReceiveBufferedBytes the per-channel receive bound
    /// @param messageInterleaving     whether to offer I-DATA
    /// @param threadFactory           the thread factory
    /// @throws IllegalArgumentException if `localPort` is outside `1` to `65535` or a size is not positive
    public SctpConfig(int localPort, long maxMessageSize, int maxSendBufferSize, long maxReceiveBufferedBytes,
                      boolean messageInterleaving, ThreadFactory threadFactory) {
        this(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes, messageInterleaving, threadFactory,
                DEFAULT_MAX_BUFFERED_AMOUNT);
    }

    /// {@return the default configuration}: port 5000, 256 KiB messages, a 2 MB send buffer, 16 MiB per channel
    /// received and buffered for sending, interleaving offered, and virtual threads named `parley-sctp-<n>`
    public static SctpConfig defaults() {
        return new SctpConfig(DEFAULT_PORT, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MAX_SEND_BUFFER_SIZE,
                DEFAULT_MAX_RECEIVE_BUFFERED_BYTES, true, Thread.ofVirtual().name("parley-sctp-", 0).factory(),
                DEFAULT_MAX_BUFFERED_AMOUNT);
    }

    /// {@return a copy using `localPort`}
    ///
    /// @param localPort the local SCTP port
    /// @throws IllegalArgumentException if `localPort` is outside `1` to `65535`
    public SctpConfig withLocalPort(int localPort) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory, maxBufferedAmount);
    }

    /// {@return a copy accepting messages up to `maxMessageSize` bytes}
    ///
    /// @param maxMessageSize the largest accepted message, positive
    /// @throws IllegalArgumentException if `maxMessageSize` is not positive
    public SctpConfig withMaxMessageSize(long maxMessageSize) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory, maxBufferedAmount);
    }

    /// {@return a copy with the given send buffer}
    ///
    /// @param maxSendBufferSize the send buffer, positive
    /// @throws IllegalArgumentException if `maxSendBufferSize` is not positive
    public SctpConfig withMaxSendBufferSize(int maxSendBufferSize) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory, maxBufferedAmount);
    }

    /// {@return a copy with the given per-channel receive bound}
    ///
    /// @param maxReceiveBufferedBytes the receive bound, positive
    /// @throws IllegalArgumentException if `maxReceiveBufferedBytes` is not positive
    public SctpConfig withMaxReceiveBufferedBytes(long maxReceiveBufferedBytes) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory, maxBufferedAmount);
    }

    /// {@return a copy with the given per-channel send bound}
    ///
    /// @param maxBufferedAmount the most bytes a channel may have waiting to be sent, positive
    /// @throws IllegalArgumentException if `maxBufferedAmount` is not positive
    public SctpConfig withMaxBufferedAmount(long maxBufferedAmount) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory, maxBufferedAmount);
    }

    /// {@return a copy that offers interleaving or not}
    ///
    /// @param messageInterleaving whether to offer I-DATA
    public SctpConfig withMessageInterleaving(boolean messageInterleaving) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory, maxBufferedAmount);
    }

    /// {@return a copy starting its threads from `threadFactory`}
    ///
    /// @param threadFactory the thread factory
    public SctpConfig withThreadFactory(ThreadFactory threadFactory) {
        return new SctpConfig(localPort, maxMessageSize, maxSendBufferSize, maxReceiveBufferedBytes,
                messageInterleaving, threadFactory, maxBufferedAmount);
    }
}
