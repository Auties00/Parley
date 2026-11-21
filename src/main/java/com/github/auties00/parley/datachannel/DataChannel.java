package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.event.EventSource;
import com.github.auties00.parley.event.EventStream;
import com.github.auties00.parley.media.Priority;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.List;
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
/// # Sending
///
/// [#send(DataChannelMessage)] never blocks, as the W3C `send()`: the message joins the channel's send buffer, whose
/// size is [#bufferedAmount()], or the call fails with [DataChannelBufferFullException] when it would take the buffer
/// past [SctpConfig#maxBufferedAmount()] or the association's buffer is full. A producer that would rather wait uses
/// [#send(DataChannelMessage,Duration)], or paces itself with [#awaitBufferedAmountLow(Duration)].
///
/// # Receiving
///
/// Received messages wait in the channel until [#receive()] takes them, up to [SctpConfig#maxReceiveBufferedBytes()].
/// A message that would pass that bound is dropped and the channel fails with a
/// [DataChannelReceiveOverflowException] and closes, as browsers do, so a channel the application does not read
/// never holds up the other channels of the association.
///
/// # Lifecycle
///
/// A channel created before its transport connects is [DataChannelState#CONNECTING]; it opens, and receives its
/// stream id, when the transport connects. [#close()] resets the channel's outgoing stream once everything already
/// sent has left, and the channel is [DataChannelState#CLOSED] once the peer has reset its outgoing stream too;
/// a reset started by the peer closes the channel the same way. Messages received before the channel closed can
/// still be taken with [#receive()]. Every transition is also a [DataChannelEvent].
///
/// # Threading
///
/// All methods are safe to call from any thread. [#receive()], [#awaitOpen()], [#awaitClosed(Duration)],
/// [#awaitBufferedAmountLow()] and [#send(DataChannelMessage,Duration)] block the caller; nothing else does.
///
/// @spec https://www.w3.org/TR/webrtc/#rtcdatachannel WebRTC: Real-Time Communication in Browsers, RTCDataChannel
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html RFC 8831: WebRTC Data Channels
/// @spec https://www.rfc-editor.org/rfc/rfc6525.html RFC 6525: Stream Control Transmission Protocol (SCTP) Stream Reconfiguration
public final class DataChannel implements AutoCloseable {
    /// How often a waiter samples the buffered amount.
    private static final long BUFFERED_POLL_NANOS = 5_000_000L;

    private final SctpTransport transport;
    private final String label;
    private final DataChannelInit init;
    private final ReentrantLock lock;
    private final Condition changed;
    private final ArrayDeque<DataChannelMessage> inbox;
    private final long maxInboxBytes;
    private final long maxBufferedAmount;

    /// The source of this channel's [#events()]; published to with [#lock] held, which keeps events in order.
    private final EventSource<DataChannelEvent> events = new EventSource<>();

    private int id;
    private DataChannelState state;
    private boolean acknowledged;
    private long inboxBytes;
    private long bufferedAmountLowThreshold;
    private boolean localResetStarted;
    private boolean localResetDone;
    private boolean remoteResetSeen;
    private boolean watchingBufferedAmount;
    private long messagesSent;
    private long bytesSent;
    private long messagesReceived;
    private long bytesReceived;
    private long messagesDropped;

    /// Creates a channel in the [DataChannelState#CONNECTING] state.
    ///
    /// @param transport         the owning transport
    /// @param label             the label
    /// @param init              the options; a negotiated channel takes its id from them
    /// @param maxInboxBytes     the receive bound
    /// @param maxBufferedAmount the send bound
    DataChannel(SctpTransport transport, String label, DataChannelInit init, long maxInboxBytes,
                long maxBufferedAmount) {
        this.transport = transport;
        this.label = label;
        this.init = init;
        this.maxInboxBytes = maxInboxBytes;
        this.maxBufferedAmount = maxBufferedAmount;
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
    public Priority priority() {
        return init.priority();
    }

    /// {@return the options the channel was created with; for a channel the peer opened, the options its
    /// `DATA_CHANNEL_OPEN` announced}
    public DataChannelInit init() {
        return init;
    }

    /// {@return the largest message this channel may send: the peer's `a=max-message-size`, `Long.MAX_VALUE` when the
    /// peer accepts any size, and [SctpTransport#DEFAULT_REMOTE_MAX_MESSAGE_SIZE] before the transport started}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
    public long maxMessageSize() {
        return transport.maxMessageSize();
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

    /// Sends a text message, UTF-8 encoded, without blocking.
    ///
    /// @param text the text, possibly empty
    /// @throws DataChannelBufferFullException if the message does not fit in the send buffer
    /// @throws IllegalStateException          if the channel is not [DataChannelState#OPEN]
    /// @throws IllegalArgumentException       if the encoded text is larger than [#maxMessageSize()]
    /// @throws IOException                    if the association refuses the message or fails
    public void send(String text) throws IOException {
        Objects.requireNonNull(text, "text");
        var bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0) {
            sendPayload(PayloadProtocol.STRING_EMPTY, ByteBuffer.wrap(new byte[1]), 0);
        } else {
            sendPayload(PayloadProtocol.STRING, ByteBuffer.wrap(bytes), bytes.length);
        }
    }

    /// Sends the remaining bytes of `binary` as a binary message, without blocking. The bytes are copied, so the
    /// buffer may be reused once the call returns; its position is not changed.
    ///
    /// @param binary the message, possibly empty
    /// @throws DataChannelBufferFullException if the message does not fit in the send buffer
    /// @throws IllegalStateException          if the channel is not [DataChannelState#OPEN]
    /// @throws IllegalArgumentException       if the message is larger than [#maxMessageSize()]
    /// @throws IOException                    if the association refuses the message or fails
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

    /// Sends `message`, as [#send(String)] or [#send(ByteBuffer)] would, without blocking.
    ///
    /// @param message the message
    /// @throws DataChannelBufferFullException if the message does not fit in the send buffer
    /// @throws IllegalStateException          if the channel is not [DataChannelState#OPEN]
    /// @throws IllegalArgumentException       if the message is larger than [#maxMessageSize()]
    /// @throws IOException                    if the association refuses the message or fails
    public void send(DataChannelMessage message) throws IOException {
        Objects.requireNonNull(message, "message");
        switch (message) {
            case DataChannelMessage.Text(var text) -> send(text);
            case DataChannelMessage.Binary binary -> send(binary.value());
        }
    }

    /// Sends `message`, waiting at most `timeout` for room in the send buffer.
    ///
    /// @param message the message
    /// @param timeout the longest wait, not negative
    /// @return `true` once the message is sent, `false` when the buffer had no room for it in time
    /// @throws IllegalStateException    if the channel is not [DataChannelState#OPEN], or stops being open while
    ///                                  waiting
    /// @throws IllegalArgumentException if the message is larger than [#maxMessageSize()] or `timeout` is negative
    /// @throws IOException              if the association refuses the message or fails
    /// @throws InterruptedException     if the thread is interrupted while waiting
    public boolean send(DataChannelMessage message, Duration timeout) throws IOException, InterruptedException {
        Objects.requireNonNull(message, "message");
        var deadline = System.nanoTime() + nanos(timeout);
        while (true) {
            try {
                send(message);
                return true;
            } catch (DataChannelBufferFullException full) {
                var remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    return false;
                }
                lock.lock();
                try {
                    if (state != DataChannelState.OPEN) {
                        throw new IllegalStateException("data channel " + label + " is " + state);
                    }
                    // TODO: wake on the association's acknowledgement of sent data instead of sampling once the sctp
                    //  library exposes a buffered-amount callback; it consumes the event internally.
                    changed.await(Math.min(remaining, BUFFERED_POLL_NANOS), TimeUnit.NANOSECONDS);
                } finally {
                    lock.unlock();
                }
            }
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

    /// {@return the threshold [#awaitBufferedAmountLow()] waits for and [DataChannelEvent.BufferedAmountLow] reports,
    /// `0` by default}
    public long bufferedAmountLowThreshold() {
        lock.lock();
        try {
            return bufferedAmountLowThreshold;
        } finally {
            lock.unlock();
        }
    }

    /// Sets the threshold [#awaitBufferedAmountLow()] waits for and [DataChannelEvent.BufferedAmountLow] reports.
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
                finishLocked();
                reset = false;
            } else {
                state = DataChannelState.CLOSING;
                localResetStarted = true;
                changed.signalAll();
                publishLocked(new DataChannelEvent.Closing());
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

    /// Opens a stream of this channel's events: [DataChannelEvent.Opened], [DataChannelEvent.BufferedAmountLow],
    /// [DataChannelEvent.Error], [DataChannelEvent.Closing] and [DataChannelEvent.Closed], in the order they happen.
    ///
    /// The first stream opened also gets the events raised since the channel was created, so a channel received from
    /// the peer, or created before its transport connected, still reports its opening. The stream ends after
    /// [DataChannelEvent.Closed].
    ///
    /// @return the stream, which the caller should close when done
    /// @spec https://www.w3.org/TR/webrtc/#rtcdatachannel WebRTC: Real-Time Communication in Browsers, RTCDataChannel
    public EventStream<DataChannelEvent> events() {
        return events.open();
    }

    /// {@return the received messages dropped because they would have taken the channel past its receive bound}
    long messagesDropped() {
        lock.lock();
        try {
            return messagesDropped;
        } finally {
            lock.unlock();
        }
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
            publishLocked(new DataChannelEvent.Opened());
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

    /// Queues received messages, never blocking: a message that would take the inbox past its bound is dropped, and
    /// the channel fails with a [DataChannelReceiveOverflowException] and closes.
    ///
    /// @param messages the messages, in arrival order
    void deliver(List<DataChannelMessage> messages) {
        var overflow = false;
        lock.lock();
        try {
            acknowledged = true;
            for (var message : messages) {
                if (state == DataChannelState.CLOSED || overflow) {
                    messagesDropped++;
                    continue;
                }
                if (inboxBytes + message.sizeBytes() > maxInboxBytes && !inbox.isEmpty()) {
                    messagesDropped++;
                    overflow = true;
                    publishLocked(new DataChannelEvent.Error(new DataChannelReceiveOverflowException(
                            "data channel " + label + " holds " + inboxBytes + " unread bytes, its limit is "
                                    + maxInboxBytes), OptionalInt.empty()));
                    continue;
                }
                inbox.addLast(message);
                inboxBytes += message.sizeBytes();
                messagesReceived++;
                bytesReceived += message.sizeBytes();
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        if (overflow) {
            close();
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
            if (state != DataChannelState.CLOSING) {
                state = DataChannelState.CLOSING;
                publishLocked(new DataChannelEvent.Closing());
            }
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

    /// Fails the channel with a cause, then closes it at once, as when its association is aborted.
    ///
    /// @param cause the failure
    void fail(IOException cause) {
        lock.lock();
        try {
            if (state != DataChannelState.CLOSED) {
                publishLocked(new DataChannelEvent.Error(cause, OptionalInt.empty()));
            }
            finishLocked();
        } finally {
            lock.unlock();
        }
    }

    private void finishLocked() {
        if (state == DataChannelState.CLOSED) {
            return;
        }
        state = DataChannelState.CLOSED;
        changed.signalAll();
        publishLocked(new DataChannelEvent.Closed());
    }

    /// Tells the association's listener of an event and publishes it to [#events()], ending them after
    /// [DataChannelEvent.Closed]; the caller holds [#lock], which keeps events in order.
    private void publishLocked(DataChannelEvent event) {
        try {
            transport.channelEventListener().accept(this, event);
        } catch (RuntimeException exception) {
            System.getLogger(DataChannel.class.getName()).log(System.Logger.Level.WARNING,
                    "a data channel event listener failed", exception);
        }
        events.publish(event);
        if (event instanceof DataChannelEvent.Closed) {
            events.end();
        }
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
        if (messageBytes > max) {
            throw new IllegalArgumentException("message of " + messageBytes + " bytes exceeds the maximum message size "
                    + max);
        }
        var buffered = transport.bufferedAmount(streamId);
        if (buffered + messageBytes > maxBufferedAmount) {
            throw new DataChannelBufferFullException("data channel " + label + " has " + buffered
                    + " bytes buffered; another " + messageBytes + " would pass its limit of " + maxBufferedAmount);
        }
        if (!transport.trySendMessage(streamId, ppid, payload, ordered, init)) {
            throw new DataChannelBufferFullException("the association's send buffer is full");
        }
        boolean watch;
        lock.lock();
        try {
            messagesSent++;
            bytesSent += messageBytes;
            watch = !watchingBufferedAmount && transport.bufferedAmount(streamId) > bufferedAmountLowThreshold;
            watchingBufferedAmount |= watch;
        } finally {
            lock.unlock();
        }
        if (watch) {
            transport.threadFactory().newThread(this::watchBufferedAmount).start();
        }
    }

    /// Samples the buffered amount until it falls to the threshold, then raises
    /// [DataChannelEvent.BufferedAmountLow] and wakes the threads waiting for room.
    private void watchBufferedAmount() {
        try {
            while (true) {
                long threshold;
                lock.lock();
                try {
                    if (state == DataChannelState.CLOSED) {
                        watchingBufferedAmount = false;
                        return;
                    }
                    threshold = bufferedAmountLowThreshold;
                } finally {
                    lock.unlock();
                }
                if (bufferedAmount() <= threshold) {
                    lock.lock();
                    try {
                        watchingBufferedAmount = false;
                        changed.signalAll();
                        if (state != DataChannelState.CLOSED) {
                            publishLocked(new DataChannelEvent.BufferedAmountLow());
                        }
                    } finally {
                        lock.unlock();
                    }
                    return;
                }
                // TODO: wait on the association's buffered-amount-low event instead of sampling once the sctp socket
                //  exposes it; it currently consumes the event internally.
                Thread.sleep(Duration.ofNanos(BUFFERED_POLL_NANOS));
            }
        } catch (InterruptedException exception) {
            lock.lock();
            try {
                watchingBufferedAmount = false;
            } finally {
                lock.unlock();
            }
            Thread.currentThread().interrupt();
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
