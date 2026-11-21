package com.github.auties00.parley.datachannel;

import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.sctp.PayloadProtocolId;
import com.github.auties00.sctp.SctpSocket;
import com.github.auties00.sctp.SctpStream;
import com.github.auties00.sctp.StreamId;
import com.github.auties00.sctp.exception.AssociationAbortedException;
import com.github.auties00.sctp.exception.ResetStreamsException;
import com.github.auties00.sctp.exception.SctpException;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/// The SCTP association of a peer connection, run over the application data of its DTLS transport, and the data
/// channels it carries, as the W3C `RTCSctpTransport`.
///
/// The transport is created over a DTLS transport with [#over(DtlsTransport, SctpConfig)] and started with
/// [#start(DtlsRole, int, OptionalLong, Duration)] once the DTLS handshake is done and the remote description gave the
/// peer's `a=sctp-port` and `a=max-message-size`. Both endpoints initiate the association at once, as RFC 8841
/// prescribes; the SCTP handshake resolves the collision. The DTLS role decides which stream ids this side gives
/// the channels it opens in band: even ids for the DTLS client, odd ones for the server.
///
/// Channels can be created before the transport starts; they open when it connects. Channels the peer opens are
/// taken with [#acceptDataChannel()]. Messages that arrive on a stream no channel has yet, as when the peer uses a
/// negotiated channel before this side created it, are kept (at most [#MAX_UNCLAIMED_MESSAGES] messages and
/// [#MAX_UNCLAIMED_BYTES] bytes per stream, for at most [#MAX_UNCLAIMED_STREAMS] streams) and handed to the channel
/// [#createDataChannel(String, DataChannelInit)] creates for that stream; what does not fit is dropped and counted in
/// [#unclaimedMessagesDropped()].
///
/// # Threading
///
/// Every method is safe to call from any thread, and none blocks on the association but [#start(DtlsRole, int,
/// OptionalLong, Duration)], [#acceptDataChannel()] and [#close()] (for at most [#SHUTDOWN_TIMEOUT]). One thread from
/// the configured [java.util.concurrent.ThreadFactory] reads the association and dispatches messages to their
/// channels; it never waits for a channel, so a channel the application does not read fails on its own (see
/// [DataChannel]) and never stalls the others.
///
/// @implNote This implementation runs the association on `com.github.auties00.sctp`, a pure Java port of the
/// dcSCTP library browsers use, through its blocking socket over a one-datagram-per-call adapter of the DTLS
/// application data. No type of that library appears in this API.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8261.html RFC 8261: Datagram Transport Layer Security (DTLS) Encapsulation of SCTP Packets
/// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html RFC 8831: WebRTC Data Channels
/// @spec https://www.rfc-editor.org/rfc/rfc8832.html RFC 8832: WebRTC Data Channel Establishment Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc9260.html RFC 9260: Stream Control Transmission Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc3758.html RFC 3758: Stream Control Transmission Protocol (SCTP) Partial Reliability Extension
/// @spec https://www.rfc-editor.org/rfc/rfc6525.html RFC 6525: Stream Control Transmission Protocol (SCTP) Stream Reconfiguration
/// @spec https://www.rfc-editor.org/rfc/rfc8260.html RFC 8260: Stream Schedulers and User Message Interleaving for the Stream Control Transmission Protocol
/// @spec https://www.w3.org/TR/webrtc/#rtcsctptransport-interface WebRTC: Real-Time Communication in Browsers, RTCSctpTransport
public final class SctpTransport implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(SctpTransport.class.getName());

    /// The maximum message size to assume when the remote description has no `a=max-message-size`: 64 KiB.
    public static final long DEFAULT_REMOTE_MAX_MESSAGE_SIZE = 65536;

    /// The largest SCTP packet, chosen to fit an IPv6 minimum MTU after DTLS, UDP and IP headers.
    static final int DEFAULT_MTU = 1191;

    /// The smallest SCTP packet the transport is willing to be limited to.
    static final int MIN_MTU = 500;

    /// How long a graceful shutdown may take before [#close()] aborts the association.
    static final Duration SHUTDOWN_TIMEOUT = Duration.ofMillis(500);

    /// How often a closing channel samples its buffered amount before resetting its stream.
    private static final long DRAIN_POLL_MILLIS = 5;

    /// The most messages kept for one stream that has no channel yet.
    public static final int MAX_UNCLAIMED_MESSAGES = 64;

    /// The most bytes kept for one stream that has no channel yet.
    public static final long MAX_UNCLAIMED_BYTES = 1024 * 1024;

    /// The most streams without a channel whose messages are kept at once.
    public static final int MAX_UNCLAIMED_STREAMS = 16;

    private final Supplier<DatagramTransport> lower;
    private final SctpConfig config;
    private final ReentrantLock lock;
    private final Condition changed;
    private final Map<Integer, DataChannel> channels;
    private final List<DataChannel> pending;
    private final ArrayDeque<DataChannel> incoming;
    private final Map<Integer, Unclaimed> unclaimed;
    private long unclaimedDropped;
    private SctpTransportState state;
    private boolean starting;
    private DtlsRole role;
    private long maxMessageSize;
    private volatile SctpSocket socket;
    private DatagramChannelAdapter adapter;

    private SctpTransport(Supplier<DatagramTransport> lower, SctpConfig config) {
        this.lower = lower;
        this.config = config;
        this.lock = new ReentrantLock();
        this.changed = lock.newCondition();
        this.channels = new HashMap<>();
        this.pending = new ArrayList<>();
        this.incoming = new ArrayDeque<>();
        this.unclaimed = new java.util.LinkedHashMap<>();
        this.state = SctpTransportState.CONNECTING;
    }

    /// Creates a transport over the application data of `dtls`, which is read when the transport starts.
    ///
    /// @param dtls   the DTLS transport, whose handshake completes before [#start(DtlsRole, int, OptionalLong, Duration)]
    /// @param config the configuration
    /// @return the transport, [SctpTransportState#CONNECTING] and not started
    public static SctpTransport over(DtlsTransport dtls, SctpConfig config) {
        Objects.requireNonNull(dtls, "dtls");
        Objects.requireNonNull(config, "config");
        return new SctpTransport(dtls::applicationData, config);
    }

    /// Creates a transport directly over a datagram transport that already provides DTLS, such as the application
    /// data of a [DtlsTransport] that is attached later, or (in tests) a plain datagram path.
    ///
    /// Data channels can be created before [#start(DtlsRole, int, OptionalLong, Duration)]; they open once it
    /// completes.
    ///
    /// @param applicationData the datagram transport
    /// @param config          the configuration
    /// @return the transport, [SctpTransportState#CONNECTING] and not started
    public static SctpTransport overDatagrams(DatagramTransport applicationData, SctpConfig config) {
        Objects.requireNonNull(applicationData, "applicationData");
        Objects.requireNonNull(config, "config");
        return new SctpTransport(() -> applicationData, config);
    }

    /// Establishes the association and opens the channels created so far, blocking until it is established.
    ///
    /// @param role                 this side's DTLS role, which decides the parity of in-band stream ids
    /// @param remotePort           the peer's `a=sctp-port`, `1` to `65535`
    /// @param remoteMaxMessageSize the peer's `a=max-message-size`, where `0` means the peer accepts any size; empty
    ///                             when the description has no such attribute, which RFC 8841 reads as
    ///                             [#DEFAULT_REMOTE_MAX_MESSAGE_SIZE]
    /// @param timeout              how long to wait for the association, positive
    /// @throws SctpTransportException  if the association is not established in time or is aborted; the transport
    ///                                 is then [SctpTransportState#CLOSED]
    /// @throws IOException             if the DTLS transport fails
    /// @throws InterruptedException    if the thread is interrupted while waiting; the transport is then closed
    /// @throws IllegalStateException   if the transport was already started or is closed
    /// @throws IllegalArgumentException if `remotePort` is out of range, `remoteMaxMessageSize` is negative or
    ///                                  `timeout` is not positive
    /// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
    public void start(DtlsRole role, int remotePort, OptionalLong remoteMaxMessageSize, Duration timeout)
            throws IOException, InterruptedException {
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(remoteMaxMessageSize, "remoteMaxMessageSize");
        Objects.requireNonNull(timeout, "timeout");
        var remoteMax = remoteMaxMessageSize.orElse(DEFAULT_REMOTE_MAX_MESSAGE_SIZE);
        if (remotePort < 1 || remotePort > 0xFFFF) {
            throw new IllegalArgumentException("remotePort must be in 1..65535: " + remotePort);
        }
        if (remoteMax < 0) {
            throw new IllegalArgumentException("remoteMaxMessageSize must not be negative: " + remoteMax);
        }
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive: " + timeout);
        }
        lock.lock();
        try {
            if (starting || state != SctpTransportState.CONNECTING) {
                throw new IllegalStateException("transport already started or closed");
            }
            starting = true;
            this.role = role;
        } finally {
            lock.unlock();
        }
        var effectiveMax = remoteMax == 0 ? Long.MAX_VALUE : remoteMax;
        var sendBuffer = (int) Math.min(Integer.MAX_VALUE, Math.max(config.maxSendBufferSize(), config.maxBufferedAmount()));
        var streamQueue = (int) Math.min(Integer.MAX_VALUE, config.maxBufferedAmount());
        var transport = lower.get();
        var channel = new DatagramChannelAdapter(transport);
        var mtu = transport.maxDatagramSize() > 0
                ? Math.clamp(transport.maxDatagramSize(), MIN_MTU, DEFAULT_MTU)
                : DEFAULT_MTU;
        var receiveWindow = Math.clamp(Math.max(config.maxMessageSize() * 2, 5_242_880L), 0, Integer.MAX_VALUE);
        SctpSocket connected;
        try {
            // TODO: the sctp library starts its reader, timer and writer threads with Thread.ofVirtual() instead of
            //  a caller-supplied factory; pass config.threadFactory() once its builder accepts one.
            connected = SctpSocket.builder(channel)
                    .name("parley-sctp")
                    .localPort(config.localPort())
                    .remotePort(remotePort)
                    .maxMessageSize((int) Math.min(Integer.MAX_VALUE, effectiveMax))
                    .maxSendBufferSize(sendBuffer)
                    .perStreamSendQueueLimit(streamQueue)
                    .maxReceiverWindowBufferSize(receiveWindow)
                    .maxTransmissionUnit(mtu)
                    .partialReliability(true)
                    .messageInterleaving(config.messageInterleaving())
                    .onIncomingStreamsReset(this::onIncomingStreamsReset)
                    .connect(timeout);
        } catch (SocketTimeoutException exception) {
            throw failStart("SCTP association not established within " + timeout, exception, channel);
        } catch (IOException exception) {
            throw failStart("SCTP association failed", exception, channel);
        } catch (AssociationAbortedException exception) {
            throw failStart("SCTP association aborted", exception, channel);
        } catch (InterruptedException exception) {
            failStart("interrupted", exception, channel);
            throw exception;
        }
        List<DataChannel> toOpen;
        lock.lock();
        try {
            if (state == SctpTransportState.CLOSED) {
                connected.close();
                throw new SctpTransportException("transport closed while connecting");
            }
            socket = connected;
            adapter = channel;
            maxMessageSize = effectiveMax;
            state = SctpTransportState.CONNECTED;
            toOpen = new ArrayList<>();
            for (var created : pending) {
                if (created.readyState() != DataChannelState.CONNECTING) {
                    continue;
                }
                var assigned = created.currentId() >= 0 ? created.currentId() : allocateIdLocked();
                if (assigned < 0 || channels.containsKey(assigned)) {
                    created.terminate();
                    continue;
                }
                created.assignId(assigned);
                channels.put(assigned, created);
                toOpen.add(created);
            }
            pending.clear();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        config.threadFactory().newThread(this::dispatch).start();
        for (var created : toOpen) {
            try {
                openOnWire(created);
            } catch (IOException exception) {
                LOGGER.log(System.Logger.Level.WARNING, "Could not open data channel " + created.label(), exception);
                created.terminate();
                forget(created);
            }
        }
    }

    /// Creates a data channel. On a connected transport an in-band channel gets its stream id and sends its
    /// `DATA_CHANNEL_OPEN` at once and is [DataChannelState#OPEN] when this returns; before the transport
    /// connects the channel is [DataChannelState#CONNECTING] and opens when it does.
    ///
    /// @param label the label, at most 65,535 UTF-8 bytes
    /// @param init  the options
    /// @return the channel
    /// @throws IllegalArgumentException if `label` is too long or a negotiated id is already in use
    /// @throws IllegalStateException    if the transport is closed
    /// @throws SctpTransportException   if no stream id is left or the `DATA_CHANNEL_OPEN` cannot be sent
    /// @throws IOException              if the association fails
    public DataChannel createDataChannel(String label, DataChannelInit init) throws IOException {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(init, "init");
        if (label.getBytes(StandardCharsets.UTF_8).length > 0xFFFF) {
            throw new IllegalArgumentException("label must be at most 65535 UTF-8 bytes");
        }
        var channel = newChannel(label, init);
        lock.lock();
        try {
            if (state == SctpTransportState.CLOSED) {
                throw new IllegalStateException("transport is closed");
            }
            if (init.negotiated()) {
                var id = init.id().orElseThrow();
                if (channels.containsKey(id) || pending.stream().anyMatch(other -> other.currentId() == id)) {
                    throw new IllegalArgumentException("stream id " + id + " is already in use");
                }
            }
            if (state == SctpTransportState.CONNECTING) {
                pending.add(channel);
                return channel;
            }
            var id = init.negotiated() ? init.id().orElseThrow() : allocateIdLocked();
            if (id < 0) {
                throw new SctpTransportException("no stream id left for a new data channel");
            }
            channel.assignId(id);
            channels.put(id, channel);
            var early = unclaimed.remove(id);
            if (early != null) {
                channel.deliver(early.messages);
            }
        } finally {
            lock.unlock();
        }
        try {
            openOnWire(channel);
        } catch (IOException exception) {
            channel.terminate();
            forget(channel);
            throw exception;
        }
        return channel;
    }

    /// Takes the next data channel the peer opened, blocking until one is announced.
    ///
    /// @return the channel, [DataChannelState#OPEN]
    /// @throws ClosedChannelException if the transport is closed and every channel announced before was taken
    /// @throws InterruptedException   if the thread is interrupted while waiting
    public DataChannel acceptDataChannel() throws IOException, InterruptedException {
        lock.lock();
        try {
            while (incoming.isEmpty()) {
                if (state == SctpTransportState.CLOSED) {
                    throw new ClosedChannelException();
                }
                changed.await();
            }
            return incoming.pollFirst();
        } finally {
            lock.unlock();
        }
    }

    /// Takes the next data channel the peer opened, waiting at most `timeout` for one.
    ///
    /// @param timeout the longest wait, not negative
    /// @return the channel, or empty if none was announced in time
    /// @throws ClosedChannelException  if the transport is closed and every channel announced before was taken
    /// @throws InterruptedException    if the thread is interrupted while waiting
    /// @throws IllegalArgumentException if `timeout` is negative
    public Optional<DataChannel> acceptDataChannel(Duration timeout) throws IOException, InterruptedException {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must not be negative: " + timeout);
        }
        var remaining = timeout.toNanos();
        lock.lock();
        try {
            while (incoming.isEmpty()) {
                if (state == SctpTransportState.CLOSED) {
                    throw new ClosedChannelException();
                }
                if (remaining <= 0) {
                    return Optional.empty();
                }
                remaining = changed.awaitNanos(remaining);
            }
            return Optional.of(incoming.pollFirst());
        } finally {
            lock.unlock();
        }
    }

    /// {@return the largest message a channel may send: the peer's `a=max-message-size`, `Long.MAX_VALUE` when the
    /// peer accepts any size, and [#DEFAULT_REMOTE_MAX_MESSAGE_SIZE] before the transport started}
    public long maxMessageSize() {
        lock.lock();
        try {
            return maxMessageSize == 0 ? DEFAULT_REMOTE_MAX_MESSAGE_SIZE : maxMessageSize;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the messages dropped because they arrived on a stream without a channel and its queue, or the number
    /// of such streams, was full}
    public long unclaimedMessagesDropped() {
        lock.lock();
        try {
            return unclaimedDropped;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the local SCTP port, for the local description's `a=sctp-port`}
    public int localPort() {
        return config.localPort();
    }

    /// {@return the largest message this side accepts, for the local description's `a=max-message-size`}
    public long localMaxMessageSize() {
        return config.maxMessageSize();
    }

    /// {@return the most channels that can be open at once, from the negotiated stream counts; empty until the
    /// association is established}
    public OptionalInt maxChannels() {
        var current = socket;
        if (current == null) {
            return OptionalInt.empty();
        }
        return current.capabilities()
                .map(capabilities -> OptionalInt.of(Math.min(capabilities.maximumIncomingStreams(),
                        capabilities.maximumOutgoingStreams())))
                .orElse(OptionalInt.empty());
    }

    /// {@return whether the association negotiated RFC 8260 user message interleaving}
    public boolean messageInterleaving() {
        var current = socket;
        return current != null && current.capabilities().map(capabilities -> capabilities.messageInterleaving())
                .orElse(false);
    }

    /// {@return the transport's state}
    public SctpTransportState state() {
        lock.lock();
        try {
            return state;
        } finally {
            lock.unlock();
        }
    }

    /// {@return the DTLS role the transport was started with, empty before
    /// [#start(DtlsRole, int, OptionalLong, Duration)]}
    public Optional<DtlsRole> role() {
        lock.lock();
        try {
            return Optional.ofNullable(role);
        } finally {
            lock.unlock();
        }
    }

    /// Shuts the association down (gracefully, for at most [#SHUTDOWN_TIMEOUT], then by abort) and closes every
    /// channel. The DTLS transport stays open. Idempotent, and never throws: a shutdown that fails, as when the DTLS
    /// association underneath is already gone, still closes the socket and detaches from the DTLS transport.
    @Override
    public void close() {
        SctpSocket current;
        DatagramChannelAdapter currentAdapter;
        List<DataChannel> all;
        lock.lock();
        try {
            if (state == SctpTransportState.CLOSED) {
                return;
            }
            state = SctpTransportState.CLOSED;
            current = socket;
            currentAdapter = adapter;
            all = new ArrayList<>(channels.values());
            all.addAll(pending);
            channels.clear();
            pending.clear();
            unclaimed.clear();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        all.forEach(DataChannel::terminate);
        try {
            if (current != null) {
                current.shutdown(SHUTDOWN_TIMEOUT);
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (IOException | SctpException | RuntimeException exception) {
            LOGGER.log(System.Logger.Level.DEBUG, "SCTP shutdown did not complete: {0}", exception.toString());
        } finally {
            if (current != null) {
                try {
                    current.close();
                } catch (RuntimeException exception) {
                    LOGGER.log(System.Logger.Level.DEBUG, "SCTP socket close failed: {0}", exception.toString());
                }
            }
            if (currentAdapter != null) {
                currentAdapter.close();
            }
        }
    }

    @Override
    public String toString() {
        return "SctpTransport[state=" + state() + ", localPort=" + config.localPort() + "]";
    }

    /// Queues one message on a stream without blocking.
    ///
    /// @param streamId the stream
    /// @param ppid     the payload protocol identifier
    /// @param payload  the payload, owned by the association once accepted
    /// @param ordered  whether it is delivered in order
    /// @param init     the channel options, for the partial reliability limits
    /// @return whether the association accepted the message; `false` when its send buffer is full
    /// @throws IOException if the association refuses the message or fails
    boolean trySendMessage(int streamId, long ppid, ByteBuffer payload, boolean ordered, DataChannelInit init)
            throws IOException {
        var current = requireSocket();
        var request = current.selectStream(StreamId.of(streamId))
                .prepareSend(PayloadProtocolId.of(ppid))
                .ordered(ordered);
        if (init.maxRetransmits().isPresent()) {
            request = request.maxRetransmissions(init.maxRetransmits().getAsInt());
        }
        if (init.maxPacketLifeTime().isPresent()) {
            request = request.lifetime(init.maxPacketLifeTime().get());
        }
        try {
            return request.trySend(payload);
        } catch (SctpException exception) {
            throw new SctpTransportException("SCTP refused the message on stream " + streamId, exception);
        }
    }

    /// {@return the factory of the threads the transport and its channels start}
    ThreadFactory threadFactory() {
        return config.threadFactory();
    }

    /// {@return a channel of this transport, with its bounds from the configuration}
    private DataChannel newChannel(String label, DataChannelInit init) {
        return new DataChannel(this, label, init, config.maxReceiveBufferedBytes(), config.maxBufferedAmount());
    }

    /// {@return the bytes queued for sending on a stream}
    ///
    /// @param streamId the stream
    long bufferedAmount(int streamId) {
        var current = socket;
        return current == null ? 0 : current.selectStream(StreamId.of(streamId)).bufferedAmount();
    }

    /// Resets a channel's outgoing stream on a new thread, after its queued messages left when `drainFirst`.
    ///
    /// @param channel    the channel
    /// @param drainFirst whether to wait for the buffered amount to reach zero first
    void resetOutgoing(DataChannel channel, boolean drainFirst) {
        config.threadFactory().newThread(() -> {
            var streamId = channel.currentId();
            var success = false;
            try {
                if (drainFirst) {
                    while (bufferedAmount(streamId) > 0 && state() == SctpTransportState.CONNECTED) {
                        Thread.sleep(DRAIN_POLL_MILLIS);
                    }
                }
                var current = socket;
                if (current != null && state() == SctpTransportState.CONNECTED) {
                    current.selectStream(StreamId.of(streamId)).reset();
                    success = true;
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            } catch (ResetStreamsException | AssociationAbortedException exception) {
                LOGGER.log(System.Logger.Level.DEBUG, "Stream reset of " + streamId + " failed", exception);
            }
            if (channel.onLocalResetDone(success)) {
                forget(channel);
            }
        }).start();
    }

    /// Removes a channel from the transport once it is closed, freeing its stream id.
    ///
    /// @param channel the channel
    void forget(DataChannel channel) {
        lock.lock();
        try {
            pending.remove(channel);
            var streamId = channel.currentId();
            if (streamId >= 0 && channels.get(streamId) == channel) {
                channels.remove(streamId);
            }
        } finally {
            lock.unlock();
        }
    }

    private SctpTransportException failStart(String message, Exception cause, DatagramChannelAdapter channel) {
        List<DataChannel> all;
        lock.lock();
        try {
            state = SctpTransportState.CLOSED;
            all = new ArrayList<>(pending);
            pending.clear();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        all.forEach(DataChannel::terminate);
        channel.close();
        return new SctpTransportException(message, cause);
    }

    private SctpSocket requireSocket() throws IOException {
        var current = socket;
        if (current == null) {
            throw new SctpTransportException("transport not connected");
        }
        return current;
    }

    private void openOnWire(DataChannel channel) throws IOException {
        var current = requireSocket();
        var streamId = channel.currentId();
        current.selectStream(StreamId.of(streamId)).setPriority(channel.priority().wireValue());
        if (channel.negotiated()) {
            channel.markOpen(true);
            return;
        }
        if (!channel.markOpen(false)) {
            return;
        }
        var open = DcepMessage.Open.of(channel.label(), channel.init());
        sendControl(current, streamId, open);
    }

    /// Sends a DCEP message from the dispatcher without blocking it: when the send buffer is full, the message is sent
    /// from a thread of the configured factory, which may wait for room.
    private void sendControlFromDispatcher(SctpSocket current, int streamId, DcepMessage message) {
        try {
            var accepted = current.selectStream(StreamId.of(streamId))
                    .prepareSend(PayloadProtocolId.of(PayloadProtocol.DCEP))
                    .ordered(true)
                    .trySend(message.encode());
            if (accepted) {
                return;
            }
        } catch (SctpException exception) {
            LOGGER.log(System.Logger.Level.DEBUG, "Could not send a DCEP message on stream " + streamId, exception);
            return;
        }
        config.threadFactory().newThread(() -> {
            try {
                sendControl(current, streamId, message);
            } catch (IOException exception) {
                LOGGER.log(System.Logger.Level.DEBUG, "Could not send a DCEP message on stream " + streamId, exception);
            }
        }).start();
    }

    private void sendControl(SctpSocket current, int streamId, DcepMessage message) throws IOException {
        try {
            current.selectStream(StreamId.of(streamId))
                    .prepareSend(PayloadProtocolId.of(PayloadProtocol.DCEP))
                    .ordered(true)
                    .send(message.encode());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            var interrupted = new InterruptedIOException("interrupted while sending a DCEP message");
            interrupted.initCause(exception);
            throw interrupted;
        } catch (SctpException exception) {
            throw new SctpTransportException("SCTP refused a DCEP message on stream " + streamId, exception);
        }
    }

    private int allocateIdLocked() {
        var start = role == DtlsRole.CLIENT ? 0 : 1;
        for (var id = start; id <= DataChannelInit.MAX_ID; id += 2) {
            if (!channels.containsKey(id)) {
                return id;
            }
        }
        return -1;
    }

    private void dispatch() {
        var current = socket;
        try {
            while (true) {
                var message = current.receive();
                var streamId = message.streamId().value();
                var ppid = message.payloadProtocol().value();
                var payload = message.payload();
                if (ppid == PayloadProtocol.DCEP) {
                    handleControl(current, streamId, payload);
                    continue;
                }
                var decoded = decode(ppid, payload);
                if (decoded.isEmpty()) {
                    LOGGER.log(System.Logger.Level.DEBUG, "Dropping a message with unknown PPID {0}", ppid);
                    continue;
                }
                DataChannel channel;
                lock.lock();
                try {
                    channel = channels.get(streamId);
                    if (channel == null) {
                        keepUnclaimedLocked(streamId, decoded.get());
                        continue;
                    }
                } finally {
                    lock.unlock();
                }
                channel.deliver(List.of(decoded.get()));
            }
        } catch (AssociationAbortedException exception) {
            LOGGER.log(System.Logger.Level.DEBUG, "SCTP association ended: {0}", exception.toString());
            failChannels(new SctpTransportException("the SCTP association was aborted", exception));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException exception) {
            LOGGER.log(System.Logger.Level.ERROR, "SCTP dispatcher failed", exception);
            failChannels(new SctpTransportException("the SCTP dispatcher failed", exception));
        }
        close();
    }

    /// Keeps a message that arrived on a stream without a channel, within the bounds of the class documentation;
    /// the caller holds [#lock].
    private void keepUnclaimedLocked(int streamId, DataChannelMessage message) {
        if (state != SctpTransportState.CONNECTED || streamId > DataChannelInit.MAX_ID) {
            unclaimedDropped++;
            return;
        }
        var queue = unclaimed.get(streamId);
        if (queue == null) {
            if (unclaimed.size() >= MAX_UNCLAIMED_STREAMS) {
                unclaimedDropped++;
                return;
            }
            queue = new Unclaimed();
            unclaimed.put(streamId, queue);
        }
        if (queue.messages.size() >= MAX_UNCLAIMED_MESSAGES || queue.bytes + message.sizeBytes() > MAX_UNCLAIMED_BYTES) {
            unclaimedDropped++;
            return;
        }
        queue.messages.add(message);
        queue.bytes += message.sizeBytes();
    }

    /// Fails every channel with a cause, as when the association is aborted; [#close()] follows.
    private void failChannels(IOException cause) {
        List<DataChannel> all;
        lock.lock();
        try {
            all = new ArrayList<>(channels.values());
        } finally {
            lock.unlock();
        }
        for (var channel : all) {
            // TODO: report the SCTP cause code of an ABORT in the error event once the sctp library exposes it on
            //  AssociationAbortedException.
            channel.fail(cause);
        }
    }

    /// The messages kept for a stream that has no channel yet.
    private static final class Unclaimed {
        /// The messages, in arrival order.
        private final List<DataChannelMessage> messages = new ArrayList<>();

        /// Their total size.
        private long bytes;
    }

    private void handleControl(SctpSocket current, int streamId, ByteBuffer payload) {
        var parsed = DcepMessage.parse(payload);
        if (parsed.isEmpty()) {
            LOGGER.log(System.Logger.Level.DEBUG, "Dropping a malformed DCEP message on stream {0}", streamId);
            return;
        }
        switch (parsed.get()) {
            case DcepMessage.Ack _ -> {
                DataChannel channel;
                lock.lock();
                try {
                    channel = channels.get(streamId);
                } finally {
                    lock.unlock();
                }
                if (channel != null) {
                    channel.onAcknowledged();
                }
            }
            case DcepMessage.Open open -> {
                if (streamId > DataChannelInit.MAX_ID) {
                    return;
                }
                var init = open.toInit();
                var channel = newChannel(open.label(), init);
                List<DataChannelMessage> early;
                lock.lock();
                try {
                    if (state != SctpTransportState.CONNECTED || channels.containsKey(streamId)) {
                        LOGGER.log(System.Logger.Level.DEBUG, "Ignoring DATA_CHANNEL_OPEN for stream {0} in use", streamId);
                        return;
                    }
                    if (hasLocalParity(streamId)) {
                        LOGGER.log(System.Logger.Level.DEBUG, "Ignoring DATA_CHANNEL_OPEN for stream {0}, whose parity is"
                                + " this side's", streamId);
                        return;
                    }
                    channel.assignId(streamId);
                    channels.put(streamId, channel);
                    var queued = unclaimed.remove(streamId);
                    early = queued == null ? List.of() : queued.messages;
                } finally {
                    lock.unlock();
                }
                current.selectStream(StreamId.of(streamId)).setPriority(init.priority().wireValue());
                channel.markOpen(true);
                if (!early.isEmpty()) {
                    channel.deliver(early);
                }
                sendControlFromDispatcher(current, streamId, new DcepMessage.Ack());
                lock.lock();
                try {
                    incoming.addLast(channel);
                    changed.signalAll();
                } finally {
                    lock.unlock();
                }
            }
        }
    }

    /// {@return whether a stream id has the parity this side gives its in-band channels: even for the DTLS client,
    /// odd for the server; the caller holds [#lock]}
    ///
    /// RFC 8832 section 6 gives each side half of the ids, so an `DATA_CHANNEL_OPEN` from the peer on one of this
    /// side's ids is a protocol violation, and accepting it would let the peer take ids this side is about to use.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8832.html RFC 8832: WebRTC Data Channel Establishment Protocol
    private boolean hasLocalParity(int streamId) {
        return role != null && (streamId % 2 == 0) == (role == DtlsRole.CLIENT);
    }

    private void onIncomingStreamsReset(List<SctpStream> streams) {
        List<DataChannel> affected = new ArrayList<>();
        lock.lock();
        try {
            if (streams.isEmpty()) {
                affected.addAll(channels.values());
            } else {
                for (var stream : streams) {
                    var channel = channels.get(stream.id().value());
                    if (channel != null) {
                        affected.add(channel);
                    }
                }
            }
        } finally {
            lock.unlock();
        }
        for (var channel : affected) {
            if (channel.onRemoteReset()) {
                resetOutgoing(channel, false);
            } else if (channel.readyState() == DataChannelState.CLOSED) {
                forget(channel);
            }
        }
    }

    private static Optional<DataChannelMessage> decode(long ppid, ByteBuffer payload) {
        if (ppid == PayloadProtocol.STRING || ppid == PayloadProtocol.STRING_PARTIAL) {
            var bytes = new byte[payload.remaining()];
            payload.duplicate().get(bytes);
            return Optional.of(new DataChannelMessage.Text(new String(bytes, StandardCharsets.UTF_8)));
        }
        if (ppid == PayloadProtocol.BINARY || ppid == PayloadProtocol.BINARY_PARTIAL) {
            return Optional.of(new DataChannelMessage.Binary(payload));
        }
        if (ppid == PayloadProtocol.STRING_EMPTY) {
            return Optional.of(new DataChannelMessage.Text(""));
        }
        if (ppid == PayloadProtocol.BINARY_EMPTY) {
            return Optional.of(new DataChannelMessage.Binary(ByteBuffer.allocate(0)));
        }
        return Optional.empty();
    }
}
