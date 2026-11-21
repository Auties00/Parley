package com.github.auties00.parley.datachannel;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/// A WebRTC data channel: a bidirectional, message-oriented channel carried on one SCTP stream of an
/// [SctpTransport], as the W3C `RTCDataChannel`.
///
/// A channel is created locally with [SctpTransport#createDataChannel(String, DataChannelInit)] or accepted from the
/// peer with [SctpTransport#acceptDataChannel()]. Messages are text or binary and keep their boundaries; whether
/// they arrive in order and whether lost ones are retransmitted indefinitely follows the channel's
/// [DataChannelInit].
///
/// # Lifecycle
///
/// A channel created before its transport connects is [DataChannelState#CONNECTING]; it opens, and receives its
/// stream id, when the transport connects. [#close()] resets the channel's outgoing stream once everything already
/// sent has left, and the channel is [DataChannelState#CLOSED] once the peer has reset its outgoing stream too;
/// a reset started by the peer closes the channel the same way. Messages received before the channel closed can
/// still be taken with [#receive()].
///
/// # Threading
///
/// All methods are safe to call from any thread. [#receive()] and [#awaitBufferedAmountLow()] block the caller;
/// [#send(String)] and [#send(ByteBuffer)] block while the association's send buffer is full.
///
/// @spec https://www.w3.org/TR/webrtc/#rtcdatachannel WebRTC: Real-Time Communication in Browsers, RTCDataChannel
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html RFC 8831: WebRTC Data Channels
/// @spec https://www.rfc-editor.org/rfc/rfc6525.html RFC 6525: Stream Control Transmission Protocol (SCTP) Stream Reconfiguration
public final class DataChannel implements AutoCloseable {
    /// How often [#awaitBufferedAmountLow()] samples the buffered amount.
    private static final long BUFFERED_POLL_NANOS = 5_000_000L;

    private final SctpTransport transport;
    private final String label;
    private final DataChannelInit init;
    private final ReentrantLock lock;
    private final Condition changed;
    private final ArrayDeque<DataChannelMessage> inbox;
    private final long maxInboxBytes;
    private int id;
    private DataChannelState state;
    private boolean acknowledged;
    private long inboxBytes;
    private long bufferedAmountLowThreshold;
    private boolean localResetStarted;
    private boolean localResetDone;
    private boolean remoteResetSeen;
    private long messagesSent;
    private long bytesSent;
    private long messagesReceived;
    private long bytesReceived;

    /// Creates a channel in the [DataChannelState#CONNECTING] state.
    ///
    /// @param transport     the owning transport
    /// @param label         the label
    /// @param init          the options; a negotiated channel takes its id from them
    /// @param maxInboxBytes the receive bound
    DataChannel(SctpTransport transport, String label, DataChannelInit init, long maxInboxBytes) {
        this.transport = transport;
        this.label = label;
        this.init = init;
        this.maxInboxBytes = maxInboxBytes;
        this.lock = new ReentrantLock();
        this.changed = lock.newCondition();
        this.inbox = new ArrayDeque<>();
        this.id = init.id().orElse(-1);
        this.state = DataChannelState.CONNECTING;
    }

    /// {@return the label the channel was created with}
    public String label() {
        return label;
    }

    /// {@return the SCTP stream id, empty while the channel waits for its transport to assign one}
    public OptionalInt id() {
        lock.lock();
        try {
            return id < 0 ? OptionalInt.empty() : OptionalInt.of(id);
        } finally {
            lock.unlock();
        }
    }

    /// {@return whether messages are delivered in order}
    public boolean ordered() {
        return init.ordered();
    }

    /// {@return the retransmission limit, empty when unlimited}
    public OptionalInt maxRetransmits() {
        return init.maxRetransmits();
    }

    /// {@return the lifetime limit, empty when unlimited}
    public Optional<Duration> maxPacketLifeTime() {
        return init.maxPacketLifeTime();
    }

    /// {@return the sub-protocol, possibly empty}
    public String protocol() {
        return init.protocol();
    }

    /// {@return whether the channel was negotiated out of band}
    public boolean negotiated() {
        return init.negotiated();
    }

    /// {@return the channel's priority}
    public DataChannelPriority priority() {
        return init.priority();
    }

    /// {@return the options the channel was created with; for a channel the peer opened, the options its
    /// `DATA_CHANNEL_OPEN` announced}
    public DataChannelInit init() {
        return init;
    }

    /// {@return the channel's ready state}
    public DataChannelState readyState() {
        lock.lock();
        try {
            return state;
        } finally {
            lock.unlock();
        }
    }

    /// Sends a text message, UTF-8 encoded.
    ///
    /// @param text the text, possibly empty
    /// @throws IllegalStateException    if the channel is not [DataChannelState#OPEN]
    /// @throws IllegalArgumentException if the encoded text is larger than the transport's
    ///                                  [SctpTransport#maxMessageSize()]
    /// @throws IOException              if the association refuses the message or fails, or the thread is
    ///                                  interrupted while blocked on a full send buffer
    ///                                  ([java.io.InterruptedIOException], with the interrupt status set)
    public void send(String text) throws IOException {
        Objects.requireNonNull(text, "text");
        var bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0) {
            sendPayload(PayloadProtocol.STRING_EMPTY, ByteBuffer.wrap(new byte[1]), 0);
        } else {
            sendPayload(PayloadProtocol.STRING, ByteBuffer.wrap(bytes), bytes.length);
        }
    }

    /// Sends the remaining bytes of `binary` as a binary message. The bytes are copied, so the buffer may be reused
    /// once the call returns; its position is not changed.
    ///
    /// @param binary the message, possibly empty
    /// @throws IllegalStateException    if the channel is not [DataChannelState#OPEN]
    /// @throws IllegalArgumentException if the message is larger than the transport's
    ///                                  [SctpTransport#maxMessageSize()]
    /// @throws IOException              if the association refuses the message or fails, or the thread is
    ///                                  interrupted while blocked on a full send buffer
    public void send(ByteBuffer binary) throws IOException {
        Objects.requireNonNull(binary, "binary");
        var length = binary.remaining();
        if (length == 0) {
            sendPayload(PayloadProtocol.BINARY_EMPTY, ByteBuffer.wrap(new byte[1]), 0);
        } else {
            var copy = ByteBuffer.allocate(length);
            copy.put(binary.duplicate()).flip();
            sendPayload(PayloadProtocol.BINARY, copy, length);
        }
    }

    /// Sends `message`, as [#send(String)] or [#send(ByteBuffer)] would.
    ///
    /// @param message the message
    /// @throws IllegalStateException    if the channel is not [DataChannelState#OPEN]
    /// @throws IllegalArgumentException if the message is larger than the transport's
    ///                                  [SctpTransport#maxMessageSize()]
    /// @throws IOException              if the association refuses the message or fails
    public void send(DataChannelMessage message) throws IOException {
        Objects.requireNonNull(message, "message");
        switch (message) {
            case DataChannelMessage.Text(var text) -> send(text);
            case DataChannelMessage.Binary binary -> send(binary.value());
        }
    }

    /// Takes the next received message, blocking until one arrives.
    ///
    /// @return the message
    /// @throws ClosedChannelException if the channel is closed and every message received before was taken
    /// @throws InterruptedException   if the thread is interrupted while waiting
    public DataChannelMessage receive() throws IOException, InterruptedException {
        lock.lock();
        try {
            while (inbox.isEmpty()) {
                if (state == DataChannelState.CLOSED) {
                    throw new ClosedChannelException();
                }
                changed.await();
            }
            return takeLocked();
        } finally {
            lock.unlock();
        }
    }

    /// Takes the next received message, waiting at most `timeout` for one.
    ///
    /// @param timeout the longest wait, not negative
    /// @return the message, or empty if none arrived in time
    /// @throws ClosedChannelException  if the channel is closed and every message received before was taken
    /// @throws InterruptedException    if the thread is interrupted while waiting
    /// @throws IllegalArgumentException if `timeout` is negative
    public Optional<DataChannelMessage> receive(Duration timeout) throws IOException, InterruptedException {
        var remaining = nanos(timeout);
        lock.lock();
        try {
            while (inbox.isEmpty()) {
                if (state == DataChannelState.CLOSED) {
                    throw new ClosedChannelException();
                }
                if (remaining <= 0) {
                    return Optional.empty();
                }
                remaining = changed.awaitNanos(remaining);
            }
            return Optional.of(takeLocked());
        } finally {
            lock.unlock();
        }
    }

    /// {@return the bytes of sent messages the association has not transmitted yet}
    public long bufferedAmount() {
        var streamId = currentId();
        return streamId < 0 ? 0 : transport.bufferedAmount(streamId);
    }

    /// {@return the threshold [#awaitBufferedAmountLow()] waits for, `0` by default}
    public long bufferedAmountLowThreshold() {
        lock.lock();
        try {
            return bufferedAmountLowThreshold;
        } finally {
            lock.unlock();
        }
    }

    /// Sets the threshold [#awaitBufferedAmountLow()] waits for.
    ///
    /// @param bytes the threshold, not negative
    /// @throws IllegalArgumentException if `bytes` is negative
    public void setBufferedAmountLowThreshold(long bytes) {
        if (bytes < 0) {
            throw new IllegalArgumentException("bytes must not be negative: " + bytes);
        }
        lock.lock();
        try {
            bufferedAmountLowThreshold = bytes;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Blocks until the [#bufferedAmount()] is at or below the [#bufferedAmountLowThreshold()], or the channel
    /// closes; the W3C `bufferedamountlow` event as a blocking call, for producers that pace themselves.
    ///
    /// @throws InterruptedException if the thread is interrupted while waiting
    public void awaitBufferedAmountLow() throws InterruptedException {
        awaitBufferedAmountLow(Long.MAX_VALUE);
    }

    /// Blocks until the [#bufferedAmount()] is at or below the [#bufferedAmountLowThreshold()], the channel closes,
    /// or `timeout` elapses.
    ///
    /// @param timeout the longest wait, not negative
    /// @return whether the buffered amount is low or the channel closed, as opposed to the wait timing out
    /// @throws InterruptedException    if the thread is interrupted while waiting
    /// @throws IllegalArgumentException if `timeout` is negative
    public boolean awaitBufferedAmountLow(Duration timeout) throws InterruptedException {
        return awaitBufferedAmountLow(nanos(timeout));
    }

    /// Blocks until the channel is [DataChannelState#OPEN].
    ///
    /// @throws ClosedChannelException if the channel closes before it opens
    /// @throws InterruptedException   if the thread is interrupted while waiting
    public void awaitOpen() throws IOException, InterruptedException {
        awaitOpen(Long.MAX_VALUE);
    }

    /// Blocks until the channel is [DataChannelState#OPEN] or `timeout` elapses.
    ///
    /// @param timeout the longest wait, not negative
    /// @return whether the channel is open
    /// @throws ClosedChannelException  if the channel closes before it opens
    /// @throws InterruptedException    if the thread is interrupted while waiting
    /// @throws IllegalArgumentException if `timeout` is negative
    public boolean awaitOpen(Duration timeout) throws IOException, InterruptedException {
        return awaitOpen(nanos(timeout));
    }

    /// Blocks until the channel is [DataChannelState#CLOSED] or `timeout` elapses.
    ///
    /// @param timeout the longest wait, not negative
    /// @return whether the channel is closed
    /// @throws InterruptedException    if the thread is interrupted while waiting
    /// @throws IllegalArgumentException if `timeout` is negative
    public boolean awaitClosed(Duration timeout) throws InterruptedException {
        var remaining = nanos(timeout);
        lock.lock();
        try {
            while (state != DataChannelState.CLOSED) {
                if (remaining <= 0) {
                    return false;
                }
                remaining = changed.awaitNanos(remaining);
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    /// {@return a snapshot of the channel's counters}
    public DataChannelStatistics statistics() {
        lock.lock();
        try {
            return new DataChannelStatistics(label, init.protocol(), id < 0 ? OptionalInt.empty() : OptionalInt.of(id),
                    state, messagesSent, bytesSent, messagesReceived, bytesReceived);
        } finally {
            lock.unlock();
        }
    }

    /// Starts closing the channel: it stops accepting sends at once, and its outgoing stream is reset in the
    /// background once everything already sent has been transmitted. Idempotent; it does not wait for the
    /// channel to reach [DataChannelState#CLOSED] (see [#awaitClosed(Duration)]).
    @Override
    public void close() {
        boolean reset;
        lock.lock();
        try {
            if (state == DataChannelState.CLOSING || state == DataChannelState.CLOSED) {
                return;
            }
            if (state == DataChannelState.CONNECTING) {
                state = DataChannelState.CLOSED;
                changed.signalAll();
                reset = false;
            } else {
                state = DataChannelState.CLOSING;
                localResetStarted = true;
                changed.signalAll();
                reset = true;
            }
        } finally {
            lock.unlock();
        }
        if (reset) {
            transport.resetOutgoing(this, true);
        } else {
            transport.forget(this);
        }
    }

    @Override
    public String toString() {
        return "DataChannel[label=" + label + ", id=" + id() + ", state=" + readyState() + "]";
    }

    /// {@return the stream id, or `-1` while none is assigned}
    int currentId() {
        lock.lock();
        try {
            return id;
        } finally {
            lock.unlock();
        }
    }

    /// Assigns the stream id of a channel opened in band.
    ///
    /// @param streamId the stream id
    void assignId(int streamId) {
        lock.lock();
        try {
            id = streamId;
        } finally {
            lock.unlock();
        }
    }

    /// Opens the channel.
    ///
    /// @param acknowledged whether the peer already knows the channel, so unordered sends may start at once
    /// @return whether the channel was opened; `false` when it was closed first
    boolean markOpen(boolean acknowledged) {
        lock.lock();
        try {
            if (state != DataChannelState.CONNECTING) {
                return false;
            }
            this.acknowledged = acknowledged;
            state = DataChannelState.OPEN;
            changed.signalAll();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /// Records the peer's `DATA_CHANNEL_ACK`, or any message proving the peer opened the channel.
    void onAcknowledged() {
        lock.lock();
        try {
            acknowledged = true;
        } finally {
            lock.unlock();
        }
    }

    /// Queues a received message, blocking while the inbox is over its bound.
    ///
    /// @param message the message
    /// @throws InterruptedException if the transport's reader is interrupted while waiting for room
    void deliver(DataChannelMessage message) throws InterruptedException {
        lock.lock();
        try {
            acknowledged = true;
            while (inboxBytes >= maxInboxBytes && state != DataChannelState.CLOSED) {
                changed.await();
            }
            if (state == DataChannelState.CLOSED) {
                return;
            }
            inbox.addLast(message);
            inboxBytes += message.sizeBytes();
            messagesReceived++;
            bytesReceived += message.sizeBytes();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Records that the peer reset its outgoing stream.
    ///
    /// @return whether the caller must now reset this side's outgoing stream
    boolean onRemoteReset() {
        lock.lock();
        try {
            remoteResetSeen = true;
            if (state == DataChannelState.CLOSED) {
                return false;
            }
            if (localResetDone) {
                finishLocked();
                return false;
            }
            state = DataChannelState.CLOSING;
            changed.signalAll();
            if (localResetStarted) {
                return false;
            }
            localResetStarted = true;
            return true;
        } finally {
            lock.unlock();
        }
    }

    /// Records that this side's outgoing stream was reset (or could not be).
    ///
    /// @param success whether the reset completed; a failed one closes the channel at once
    /// @return whether the channel is now closed
    boolean onLocalResetDone(boolean success) {
        lock.lock();
        try {
            localResetDone = true;
            if (remoteResetSeen || !success) {
                finishLocked();
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    /// Closes the channel at once, as when its transport closes.
    void terminate() {
        lock.lock();
        try {
            finishLocked();
        } finally {
            lock.unlock();
        }
    }

    private void finishLocked() {
        state = DataChannelState.CLOSED;
        changed.signalAll();
    }

    private void sendPayload(long ppid, ByteBuffer payload, int messageBytes) throws IOException {
        int streamId;
        boolean ordered;
        lock.lock();
        try {
            if (state != DataChannelState.OPEN) {
                throw new IllegalStateException("data channel " + label + " is " + state);
            }
            streamId = id;
            ordered = init.ordered() || !acknowledged;
        } finally {
            lock.unlock();
        }
        var max = transport.maxMessageSize();
        if (max > 0 && messageBytes > max) {
            throw new IllegalArgumentException("message of " + messageBytes + " bytes exceeds the maximum message size "
                    + max);
        }
        transport.sendMessage(streamId, ppid, payload, ordered, init);
        lock.lock();
        try {
            messagesSent++;
            bytesSent += messageBytes;
        } finally {
            lock.unlock();
        }
    }

    private DataChannelMessage takeLocked() {
        var message = inbox.pollFirst();
        inboxBytes -= message.sizeBytes();
        changed.signalAll();
        return message;
    }

    private boolean awaitBufferedAmountLow(long timeoutNanos) throws InterruptedException {
        var deadline = timeoutNanos == Long.MAX_VALUE ? Long.MAX_VALUE : System.nanoTime() + timeoutNanos;
        while (true) {
            long threshold;
            lock.lock();
            try {
                if (state == DataChannelState.CLOSED) {
                    return true;
                }
                threshold = bufferedAmountLowThreshold;
            } finally {
                lock.unlock();
            }
            if (bufferedAmount() <= threshold) {
                return true;
            }
            var remaining = deadline == Long.MAX_VALUE ? BUFFERED_POLL_NANOS : deadline - System.nanoTime();
            if (remaining <= 0) {
                return false;
            }
            // TODO: wait on the association's buffered-amount-low event instead of sampling once the sctp socket
            //  exposes it; it currently consumes the event internally.
            lock.lock();
            try {
                changed.await(Math.min(remaining, BUFFERED_POLL_NANOS), TimeUnit.NANOSECONDS);
            } finally {
                lock.unlock();
            }
        }
    }

    private boolean awaitOpen(long timeoutNanos) throws IOException, InterruptedException {
        var remaining = timeoutNanos;
        lock.lock();
        try {
            while (state == DataChannelState.CONNECTING) {
                if (remaining <= 0) {
                    return false;
                }
                if (timeoutNanos == Long.MAX_VALUE) {
                    changed.await();
                } else {
                    remaining = changed.awaitNanos(remaining);
                }
            }
            if (state != DataChannelState.OPEN) {
                throw new ClosedChannelException();
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    private static long nanos(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must not be negative: " + timeout);
        }
        return timeout.compareTo(Duration.ofNanos(Long.MAX_VALUE - 1)) >= 0 ? Long.MAX_VALUE - 1 : timeout.toNanos();
    }
}
