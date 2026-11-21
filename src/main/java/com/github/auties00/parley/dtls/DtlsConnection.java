package com.github.auties00.parley.dtls;

import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/// The implementation of [DtlsTransport]: the receive path, the flight and retransmission machinery shared by both
/// versions, the DTLS 1.3 acknowledgements and key updates, application data, alerts and statistics.
///
/// Until the handshake completes, received DTLS datagrams are queued and processed by the handshake thread; afterwards
/// the lower transport's reader thread processes them directly. All protocol state is guarded by one lock; listeners
/// and receivers are always called after it is released.
///
/// @implNote This implementation exists because the JDK's DTLS engine cannot negotiate `use_srtp` (SunJSSE registers
///           the extension id with no producer or consumer) and does not implement DTLS 1.3.
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
final class DtlsConnection implements DtlsTransport {
    /// The source of randoms of the whole package.
    static final SecureRandom RANDOM = new SecureRandom();

    private static final System.Logger LOGGER = System.getLogger(DtlsConnection.class.getName());

    /// The largest retransmission timeout, the 60 seconds RFC 6347 and RFC 9147 cap the doubling at.
    private static final long MAX_RETRANSMIT_NANOS = TimeUnit.SECONDS.toNanos(60);

    /// The retransmissions after which a post-handshake flight is abandoned.
    private static final int MAX_POST_HANDSHAKE_RETRANSMISSIONS = 10;

    /// The largest datagram a handshake flight uses, the size WebRTC stacks assume crosses any path unfragmented.
    private static final int HANDSHAKE_MTU = 1200;

    /// The datagram size flights fall back to after repeated retransmissions, which RFC 9147 section 4.4 suggests
    /// when the path MTU is unknown: the IPv4 minimum of 576 bytes less IP and UDP headers.
    private static final int REDUCED_MTU = 548;

    /// The retransmissions after which flights use [#REDUCED_MTU].
    private static final int RETRANSMISSIONS_BEFORE_REDUCING_MTU = 2;

    /// The largest per-record expansion of any protection this library negotiates, for the application data budget.
    private static final int MAX_RECORD_EXPANSION = RecordLayer.PLAINTEXT_HEADER_LENGTH
            + Dtls12RecordCipher.EXPLICIT_NONCE_LENGTH + Aead.TAG_LENGTH;

    /// The number of received datagrams queued before the handshake processes them.
    private static final int INBOUND_CAPACITY = 256;

    /// The datagram that wakes the handshake thread when the transport closes.
    private static final byte[] WAKE_UP = new byte[0];

    /// A receiver that drops everything.
    private static final PacketReceiver DISCARD = (packet, arrivalNanos) -> {
    };

    /// The lower transport.
    private final DatagramTransport lower;

    /// The settings.
    private final DtlsConfig config;

    /// The lock that guards the protocol state.
    private final ReentrantLock lock = new ReentrantLock();

    /// Signalled when the timer thread must re-evaluate its deadline.
    private final Condition timerSignal = lock.newCondition();

    /// The datagrams received before the handshake completed.
    private final LinkedBlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>(INBOUND_CAPACITY);

    /// The record encoding and keys.
    private final RecordLayer records = new RecordLayer();

    /// The reassembly of the peer's handshake messages.
    private final HandshakeReassembler reassembler = new HandshakeReassembler();

    /// The application data view.
    private final ApplicationData applicationData = new ApplicationData();

    /// The RTP and RTCP view.
    private final MediaPath mediaPath = new MediaPath();

    /// The state changes to report once the lock is released.
    private final List<DtlsState> pendingStates = new ArrayList<>();

    /// The application data payloads to deliver once the lock is released.
    private final List<byte[]> pendingData = new ArrayList<>();

    /// The application data payloads released by the lock and not delivered yet, in record order.
    private final ConcurrentLinkedQueue<byte[]> deliveries = new ConcurrentLinkedQueue<>();

    /// Whether a thread is delivering [#deliveries], so only one does at a time and payloads keep their order.
    private final AtomicBoolean delivering = new AtomicBoolean();

    /// The DTLS 1.3 record numbers of handshake records to acknowledge, as `epoch << 48 | sequence`.
    private final TreeSet<Long> pendingAcks = new TreeSet<>();

    /// The receiver of RTP and RTCP.
    private volatile PacketReceiver nonDtlsReceiver = DISCARD;

    /// The receiver of application data.
    private volatile PacketReceiver applicationReceiver = DISCARD;

    /// The listener of state changes.
    private volatile Consumer<DtlsState> stateListener = _ -> {
    };

    /// The current state.
    private volatile DtlsState state = DtlsState.NEW;

    /// The handshake role.
    private volatile DtlsRole role;

    /// The negotiated version.
    private volatile DtlsVersion version;

    /// The negotiated cipher suite.
    private volatile CipherSuite suite;

    /// The negotiated SRTP profile.
    private volatile SrtpProfile srtpProfile;

    /// The peer's certificate.
    private volatile X509Certificate remoteCertificate;

    /// The exported SRTP keys.
    private volatile DtlsSrtpKeys srtpKeys;

    /// The handshake, `null` before it started; guarded by [#lock].
    private Handshake handshake;

    /// Whether the handshake completed; guarded by [#lock].
    private boolean established;

    /// Whether the transport closed or failed; guarded by [#lock].
    private boolean closed;

    /// The epoch of outgoing alerts, acknowledgements and application data; guarded by [#lock].
    private long writeEpoch;

    /// The current DTLS 1.3 read epoch of application data; guarded by [#lock].
    private long readEpoch = 3;

    /// The flight that may need retransmission, or `null`; guarded by [#lock].
    private Flight flight;

    /// The post-handshake timer thread, or `null`; guarded by [#lock].
    private Thread timerThread;

    /// Whether an acknowledgement of a partially received DTLS 1.3 handshake flight is scheduled; guarded by [#lock].
    private boolean ackScheduled;

    /// The clock time the scheduled acknowledgement is sent; guarded by [#lock].
    private long ackDeadline;

    /// The clock time a flight was last sent again because the peer repeated itself; guarded by [#lock].
    private long lastDuplicateRetransmit = Long.MIN_VALUE / 2;

    /// The counters; guarded by [#lock].
    private long bytesSent;

    /// The bytes of DTLS datagrams received; guarded by [#lock].
    private long bytesReceived;

    /// The DTLS datagrams sent; guarded by [#lock].
    private long packetsSent;

    /// The DTLS datagrams received; guarded by [#lock].
    private long packetsReceived;

    /// The flights sent again; guarded by [#lock].
    private long retransmissions;

    /// Creates a transport and takes over the lower transport's receiver.
    ///
    /// @param lower  the lower transport
    /// @param config the settings
    DtlsConnection(DatagramTransport lower, DtlsConfig config) {
        this.lower = Objects.requireNonNull(lower, "lower cannot be null");
        this.config = Objects.requireNonNull(config, "config cannot be null");
        lower.setReceiver(this::onLowerPacket);
    }

    @Override
    public DtlsSrtpKeys handshake(DtlsRole role, List<DtlsFingerprint> remoteFingerprints, Duration timeout)
            throws DtlsException, InterruptedException {
        runHandshake(role, remoteFingerprints, timeout, true);
        return srtpKeys;
    }

    @Override
    public void handshakeWithoutSrtp(DtlsRole role, List<DtlsFingerprint> remoteFingerprints, Duration timeout)
            throws DtlsException, InterruptedException {
        runHandshake(role, remoteFingerprints, timeout, false);
    }

    @Override
    public DtlsState state() {
        return state;
    }

    @Override
    public Optional<DtlsRole> role() {
        return Optional.ofNullable(role);
    }

    @Override
    public Optional<DtlsVersion> negotiatedVersion() {
        return Optional.ofNullable(version);
    }

    @Override
    public Optional<SrtpProfile> srtpProfile() {
        return Optional.ofNullable(srtpProfile);
    }

    @Override
    public Optional<DtlsSrtpKeys> srtpKeys() {
        return Optional.ofNullable(srtpKeys);
    }

    @Override
    public Optional<X509Certificate> remoteCertificate() {
        return Optional.ofNullable(remoteCertificate);
    }

    @Override
    public DatagramTransport applicationData() {
        return applicationData;
    }

    @Override
    public DatagramTransport mediaPath() {
        return mediaPath;
    }

    @Override
    public void setNonDtlsReceiver(PacketReceiver receiver) {
        this.nonDtlsReceiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    @Override
    public void setStateListener(Consumer<DtlsState> listener) {
        this.stateListener = Objects.requireNonNull(listener, "listener cannot be null");
    }

    @Override
    public void updateKeys(boolean requestPeerUpdate) throws IOException {
        lock.lock();
        try {
            if (!established || closed || version != DtlsVersion.DTLS_1_3) {
                throw new IllegalStateException("key updates need a connected DTLS 1.3 transport");
            }
            if (flight != null && flight.retransmitOnTimer) {
                throw new IllegalStateException("an earlier flight is not acknowledged yet");
            }
            sendKeyUpdate(requestPeerUpdate);
        } finally {
            unlock();
        }
    }

    @Override
    public DtlsTransport restart() {
        close();
        return new DtlsConnection(lower, config);
    }

    @Override
    public DtlsTransportStatistics statistics() {
        lock.lock();
        try {
            return new DtlsTransportStatistics(state, Optional.ofNullable(role), Optional.ofNullable(version),
                    Optional.ofNullable(suite).map(Enum::name), Optional.ofNullable(srtpProfile), bytesSent,
                    bytesReceived, packetsSent, packetsReceived, retransmissions, records.dropped(),
                    records.authenticationFailures());
        } finally {
            unlock();
        }
    }

    @Override
    public void close() {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            if (established) {
                sendAlertQuietly(DtlsAlert.CLOSE_NOTIFY);
            }
            transition(DtlsState.CLOSED);
            flight = null;
            timerSignal.signalAll();
            inbound.clear();
            inbound.offer(WAKE_UP);
            lower.setReceiver(DISCARD);
        } finally {
            unlock();
        }
    }

    /// {@return whether no flight awaits acknowledgement, so a key update may start}
    boolean isIdle() {
        lock.lock();
        try {
            return flight == null || !flight.retransmitOnTimer;
        } finally {
            unlock();
        }
    }

    /// {@return the settings}
    DtlsConfig config() {
        return config;
    }

    /// {@return the record layer, used by the handshake under the lock}
    RecordLayer records() {
        return records;
    }

    /// Sets the epoch of outgoing alerts, acknowledgements and application data; the caller holds the lock.
    ///
    /// @param epoch the epoch, which must be installed
    void setWriteEpoch(long epoch) {
        writeEpoch = epoch;
    }

    /// Records the version and suite the hellos settled; the caller holds the lock.
    ///
    /// @param version the version
    /// @param suite   the suite
    void onVersionNegotiated(DtlsVersion version, CipherSuite suite) {
        this.version = version;
        this.suite = suite;
        records.setVersion(version);
    }

    /// Sends a new flight, replacing the previous one, which the new flight implicitly acknowledges; the caller holds
    /// the lock.
    ///
    /// @param items             the flight
    /// @param retransmitOnTimer whether the flight is sent again when the retransmission timer expires; a flight that
    ///                          is not (a `HelloVerifyRequest`, a stateless `HelloRetryRequest`, the DTLS 1.2
    ///                          server's last flight) is sent again only when the peer repeats its own
    /// @throws IOException if encoding or the lower transport fails
    void sendFlight(List<Outgoing> items, boolean retransmitOnTimer) throws IOException {
        pendingAcks.clear();
        ackScheduled = false;
        flight = new Flight(items, retransmitOnTimer, config.initialRetransmit().toNanos(), config.clock().nanos());
        transmit(flight);
        if (established) {
            ensureTimer();
        }
    }

    /// Runs a handshake on the calling thread.
    private void runHandshake(DtlsRole role, List<DtlsFingerprint> remoteFingerprints, Duration timeout,
                              boolean requireSrtp) throws DtlsException, InterruptedException {
        Objects.requireNonNull(role, "role cannot be null");
        Objects.requireNonNull(timeout, "timeout cannot be null");
        if (remoteFingerprints.isEmpty()) {
            throw new IllegalArgumentException("remoteFingerprints cannot be empty");
        }
        lock.lock();
        try {
            if (handshake != null || closed) {
                throw new IllegalStateException(closed ? "transport is closed" : "a handshake already ran");
            }
            this.role = role;
            handshake = role == DtlsRole.CLIENT
                    ? new ClientHandshake(this, remoteFingerprints, requireSrtp)
                    : new ServerHandshake(this, remoteFingerprints, requireSrtp);
            transition(DtlsState.CONNECTING);
        } finally {
            unlock();
        }
        var clock = config.clock();
        var deadline = clock.nanos() + timeout.toNanos();
        try {
            lock.lock();
            try {
                handshake.start();
            } finally {
                unlock();
            }
            while (true) {
                long wait;
                lock.lock();
                try {
                    if (established) {
                        break;
                    }
                    if (closed) {
                        throw new DtlsException("the transport was closed during the handshake");
                    }
                    var now = clock.nanos();
                    if (now - deadline >= 0) {
                        throw new DtlsException("the DTLS handshake did not complete within " + timeout.toMillis() + " ms");
                    }
                    wait = deadline - now;
                    if (flight != null && flight.retransmitOnTimer) {
                        wait = Math.min(wait, flight.deadline - now);
                    }
                    if (ackScheduled) {
                        wait = Math.min(wait, ackDeadline - now);
                    }
                } finally {
                    unlock();
                }
                var datagram = inbound.poll(Math.max(1, wait), TimeUnit.NANOSECONDS);
                lock.lock();
                try {
                    if (datagram == null) {
                        if (ackScheduled && clock.nanos() - ackDeadline >= 0) {
                            ackScheduled = false;
                            sendAck();
                        }
                        if (flight != null && flight.retransmitOnTimer && clock.nanos() - flight.deadline >= 0) {
                            retransmit(flight);
                        }
                    } else if (datagram != WAKE_UP) {
                        processDatagram(datagram);
                    }
                } finally {
                    unlock();
                }
            }
            lock.lock();
            try {
                byte[] queued;
                while ((queued = inbound.poll()) != null) {
                    if (queued != WAKE_UP) {
                        processDatagram(queued);
                    }
                }
                ensureTimer();
            } finally {
                unlock();
            }
        } catch (DtlsException exception) {
            failHandshake(exception);
            throw exception;
        } catch (IOException exception) {
            var failure = new DtlsException("the lower transport failed", exception);
            failHandshake(failure);
            throw failure;
        } catch (InterruptedException exception) {
            failHandshake(new DtlsException("interrupted"));
            throw exception;
        }
    }

    /// Ends a failed handshake: sends this side's alert, best effort, and moves to [DtlsState#FAILED].
    private void failHandshake(DtlsException exception) {
        lock.lock();
        try {
            if (exception.alert().isPresent() && !exception.isRemote() && !closed) {
                sendAlertQuietly(exception.alert().get());
            }
            if (!closed) {
                closed = true;
                transition(DtlsState.FAILED);
                flight = null;
                timerSignal.signalAll();
                lower.setReceiver(DISCARD);
            }
        } finally {
            unlock();
        }
        if (LOGGER.isLoggable(Level.DEBUG)) {
            LOGGER.log(Level.DEBUG, "DTLS handshake failed", exception);
        }
    }

    /// Classifies a datagram from the lower transport.
    private void onLowerPacket(ByteBuffer packet, long arrivalNanos) {
        if (!packet.hasRemaining()) {
            return;
        }
        var first = packet.get(packet.position()) & 0xFF;
        if (first >= 128 && first <= 191) {
            nonDtlsReceiver.receive(packet, arrivalNanos);
            return;
        }
        if (first < 20 || first > 63) {
            return;
        }
        var datagram = new byte[packet.remaining()];
        packet.duplicate().get(datagram);
        lock.lock();
        try {
            if (closed) {
                return;
            }
            if (!established) {
                inbound.offer(datagram);
                return;
            }
            processDatagram(datagram);
        } catch (DtlsException exception) {
            failConnected(exception);
        } catch (IOException exception) {
            if (LOGGER.isLoggable(Level.DEBUG)) {
                LOGGER.log(Level.DEBUG, "DTLS send failed", exception);
            }
        } finally {
            unlock();
        }
    }

    /// Ends a connected association after a fatal error; the caller holds the lock.
    private void failConnected(DtlsException exception) {
        if (exception.alert().isPresent() && !exception.isRemote()) {
            sendAlertQuietly(exception.alert().get());
        }
        closed = true;
        transition(DtlsState.FAILED);
        flight = null;
        timerSignal.signalAll();
        if (LOGGER.isLoggable(Level.DEBUG)) {
            LOGGER.log(Level.DEBUG, "DTLS association failed", exception);
        }
    }

    /// Processes one DTLS datagram; the caller holds the lock.
    ///
    /// @throws IOException if the handshake rejects a message or a send fails
    private void processDatagram(byte[] datagram) throws IOException {
        packetsReceived++;
        bytesReceived += datagram.length;
        var peerRepeated = new boolean[1];
        records.decode(datagram, record -> {
            if (closed) {
                return;
            }
            switch (record.type()) {
                case RecordLayer.HANDSHAKE -> peerRepeated[0] |= onHandshakeRecord(record);
                case RecordLayer.ALERT -> onAlert(record);
                case RecordLayer.ACK -> onAck(record);
                case RecordLayer.APPLICATION_DATA -> onApplicationData(record);
                default -> {
                }
            }
        });
        if (closed) {
            return;
        }
        if (version == DtlsVersion.DTLS_1_3 && !pendingAcks.isEmpty()) {
            if (established) {
                sendAck();
            } else if (!ackScheduled && writeEpoch >= 2) {
                ackScheduled = true;
                ackDeadline = config.clock().nanos() + config.initialRetransmit().toNanos() / 4;
            }
        }
        if (peerRepeated[0] && flight != null && !(established && version == DtlsVersion.DTLS_1_3 && role == DtlsRole.SERVER)) {
            var now = config.clock().nanos();
            if (now - lastDuplicateRetransmit >= config.initialRetransmit().toNanos() / 2) {
                lastDuplicateRetransmit = now;
                retransmit(flight);
            }
        }
    }

    /// Processes the handshake fragments of one record.
    ///
    /// Once a DTLS 1.3 handshake completed, records of the handshake epochs never reach the reassembler: epoch 0
    /// carries no authentication (the record layer already drops it) and epoch 2 only repeats the peer's final
    /// flight, which is acknowledged again. A malformed fragment in epoch 0 is dropped and counted, never fatal,
    /// because anyone on the path can forge one.
    ///
    /// @return whether the record repeated messages already processed, a sign that the peer missed this side's flight
    private boolean onHandshakeRecord(RecordLayer.Record record) throws IOException {
        if (established && version == DtlsVersion.DTLS_1_3 && record.epoch() < 3) {
            if (record.epoch() > 0) {
                pendingAcks.add(record.epoch() << 48 | record.sequence());
            }
            return role == DtlsRole.CLIENT;
        }
        var unkeyed = record.epoch() == 0;
        var reader = new TlsReader(record.payload());
        var repeated = false;
        while (reader.remaining() >= HandshakeMessage.DTLS_HEADER_LENGTH) {
            int type;
            int messageSeq;
            HandshakeReassembler.Result result;
            try {
                type = reader.u8();
                var length = reader.u24();
                messageSeq = reader.u16();
                var fragmentOffset = reader.u24();
                var fragment = reader.vector24();
                if (established && version == DtlsVersion.DTLS_1_2) {
                    repeated |= onHandshakeAfterEstablished12(record, type, messageSeq);
                    continue;
                }
                result = reassembler.offer(type, length, messageSeq, fragmentOffset, fragment, record.epoch());
            } catch (DtlsException exception) {
                if (!unkeyed) {
                    throw exception;
                }
                records.countDropped();
                return repeated;
            }
            if (result == HandshakeReassembler.Result.DROPPED && unkeyed) {
                records.countDropped();
            }
            if (version == DtlsVersion.DTLS_1_3 && !unkeyed && result != HandshakeReassembler.Result.DROPPED) {
                pendingAcks.add(record.epoch() << 48 | record.sequence());
            }
            if (result == HandshakeReassembler.Result.OLD) {
                repeated = true;
                continue;
            }
            Optional<HandshakeReassembler.Received> received;
            while ((received = reassembler.poll()).isPresent()) {
                var message = received.get();
                if (established) {
                    onPostHandshakeMessage13(message.message(), message.epoch());
                } else {
                    handshake.onMessage(message.message(), message.epoch());
                    if (handshake.helloAccepted()) {
                        reassembler.relax();
                    }
                    if (handshake.complete) {
                        onHandshakeComplete();
                    }
                }
            }
        }
        return repeated;
    }

    /// Handles a handshake fragment after a DTLS 1.2 handshake completed.
    ///
    /// @return whether it repeats the peer's final flight
    private boolean onHandshakeAfterEstablished12(RecordLayer.Record record, int type, int messageSeq) {
        if (record.epoch() == 0 || messageSeq < reassembler.nextReceiveSeq()) {
            return true;
        }
        if (type == HandshakeMessage.HELLO_REQUEST || type == HandshakeMessage.CLIENT_HELLO) {
            sendAlertQuietly(DtlsAlert.NO_RENEGOTIATION, 1);
        }
        return false;
    }

    /// Handles a DTLS 1.3 post-handshake message.
    private void onPostHandshakeMessage13(HandshakeMessage message, long epoch) throws IOException {
        if (epoch < 3) {
            return;
        }
        switch (message.type()) {
            case HandshakeMessage.KEY_UPDATE -> {
                var reader = new TlsReader(message.body());
                var request = reader.u8();
                reader.expectEnd();
                if (request > 1) {
                    throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "invalid KeyUpdate");
                }
                var peerIsClient = role == DtlsRole.SERVER;
                var current = peerIsClient ? handshake.clientApplicationSecret : handshake.serverApplicationSecret;
                var next = handshake.nextApplicationSecret(current);
                if (peerIsClient) {
                    handshake.clientApplicationSecret = next;
                } else {
                    handshake.serverApplicationSecret = next;
                }
                readEpoch++;
                records.installRead(readEpoch, Dtls13RecordCipher.fromSecret(suite, next));
                records.dropReadEpochsBelow(readEpoch - 1);
                if (request == 1 && (flight == null || !flight.retransmitOnTimer)) {
                    sendKeyUpdate(false);
                }
            }
            case HandshakeMessage.NEW_SESSION_TICKET -> {
            }
            default -> throw new DtlsException(DtlsAlert.UNEXPECTED_MESSAGE,
                    "unexpected post-handshake message " + message.type());
        }
    }

    /// Sends this side's `KeyUpdate`; the new write keys take effect when it is acknowledged. The caller holds the
    /// lock.
    private void sendKeyUpdate(boolean requestPeerUpdate) throws IOException {
        var update = handshake.newMessage(HandshakeMessage.KEY_UPDATE, new byte[]{(byte) (requestPeerUpdate ? 1 : 0)});
        var items = List.<Outgoing>of(new Outgoing.Message(update, writeEpoch));
        var keepAcks = new TreeSet<>(pendingAcks);
        sendFlight(items, true);
        pendingAcks.addAll(keepAcks);
        flight.onAcknowledged = () -> {
            var ownIsClient = role == DtlsRole.CLIENT;
            var current = ownIsClient ? handshake.clientApplicationSecret : handshake.serverApplicationSecret;
            var next = handshake.nextApplicationSecret(current);
            if (ownIsClient) {
                handshake.clientApplicationSecret = next;
            } else {
                handshake.serverApplicationSecret = next;
            }
            writeEpoch++;
            records.installWrite(writeEpoch, Dtls13RecordCipher.fromSecret(suite, next));
        };
    }

    /// Marks the handshake complete; the caller holds the lock.
    private void onHandshakeComplete() throws IOException {
        established = true;
        srtpProfile = handshake.profile;
        if (srtpProfile != null) {
            srtpKeys = handshake.srtpKeys();
        }
        remoteCertificate = handshake.peerCertificate;
        ackScheduled = false;
        records.restrictEpochZero(version == DtlsVersion.DTLS_1_2
                ? RecordLayer.EpochZero.HANDSHAKE_ONLY
                : RecordLayer.EpochZero.NONE);
        if (version == DtlsVersion.DTLS_1_3 && role == DtlsRole.SERVER) {
            flight = null;
            sendAck();
        } else if (version == DtlsVersion.DTLS_1_2 && role == DtlsRole.CLIENT) {
            flight = null;
        }
        transition(DtlsState.CONNECTED);
    }

    /// Handles an alert; once the handshake completed, an alert in epoch 0 is unauthenticated and ignored.
    private void onAlert(RecordLayer.Record record) throws DtlsException {
        if (established && record.epoch() == 0) {
            return;
        }
        var payload = record.payload();
        if (payload.length != 2) {
            return;
        }
        var level = payload[0] & 0xFF;
        var code = payload[1] & 0xFF;
        var alert = DtlsAlert.ofCode(code).orElse(null);
        if (code == DtlsAlert.CLOSE_NOTIFY.code()) {
            if (!established) {
                throw new DtlsException(DtlsAlert.CLOSE_NOTIFY, true, "the peer closed during the handshake", null);
            }
            closed = true;
            flight = null;
            timerSignal.signalAll();
            transition(DtlsState.CLOSED);
            return;
        }
        var warning = version == DtlsVersion.DTLS_1_3 ? code == DtlsAlert.USER_CANCELED.code() : level == 1;
        if (warning) {
            return;
        }
        var exception = new DtlsException(alert, true, "the peer sent fatal alert " + code, null);
        if (!established) {
            throw exception;
        }
        closed = true;
        flight = null;
        timerSignal.signalAll();
        transition(DtlsState.FAILED);
    }

    /// Handles a DTLS 1.3 acknowledgement.
    private void onAck(RecordLayer.Record record) throws IOException {
        if (version != DtlsVersion.DTLS_1_3 || flight == null) {
            return;
        }
        var reader = new TlsReader(record.payload());
        var list = reader.sub16();
        while (list.remaining() >= 16) {
            var epoch = list.u64();
            var sequence = list.u64();
            flight.acknowledge(epoch << 48 | sequence);
        }
        if (flight.isAcknowledged()) {
            var done = flight;
            flight = null;
            timerSignal.signalAll();
            if (done.onAcknowledged != null) {
                done.onAcknowledged.run();
            }
        }
    }

    /// Handles application data.
    private void onApplicationData(RecordLayer.Record record) {
        if (!established) {
            return;
        }
        var valid = version == DtlsVersion.DTLS_1_3 ? record.epoch() >= 3 : record.epoch() == 1;
        if (valid) {
            if (version == DtlsVersion.DTLS_1_3 && record.epoch() >= 4) {
                records.dropReadEpochsBelow(record.epoch() - 1);
            }
            pendingData.add(record.payload());
        }
    }

    /// Sends the pending DTLS 1.3 acknowledgements; the caller holds the lock.
    private void sendAck() throws IOException {
        if (pendingAcks.isEmpty() || !records.hasWriteEpoch(writeEpoch) || writeEpoch < 2) {
            return;
        }
        var body = new TlsWriter(2 + 16 * pendingAcks.size());
        var list = body.open16();
        for (var number : pendingAcks) {
            body.u64(number >>> 48).u64(number & 0xFFFF_FFFF_FFFFL);
        }
        body.close(list);
        pendingAcks.clear();
        send(records.encode(RecordLayer.ACK, writeEpoch, body.toByteArray(), DtlsVersion.DTLS_1_2.wireValue()).bytes());
    }

    /// Sends the unacknowledged part of a flight again and doubles its timeout; the caller holds the lock.
    private void retransmit(Flight target) throws IOException {
        target.retransmissions++;
        retransmissions++;
        target.rto = Math.min(target.rto * 2, MAX_RETRANSMIT_NANOS);
        target.deadline = config.clock().nanos() + target.rto;
        transmit(target);
    }

    /// Encodes a flight into records, fragmenting handshake messages, and sends them packed into datagrams.
    private void transmit(Flight target) throws IOException {
        var mtu = Math.min(lower.maxDatagramSize(), HANDSHAKE_MTU);
        if (target.retransmissions >= RETRANSMISSIONS_BEFORE_REDUCING_MTU) {
            mtu = Math.min(mtu, REDUCED_MTU);
        }
        var datagram = new ByteArrayOutputStream(mtu);
        for (var index = 0; index < target.items.size(); index++) {
            if (target.isItemAcknowledged(index)) {
                continue;
            }
            switch (target.items.get(index)) {
                case Outgoing.Record item -> append(datagram, records.encode(item.contentType(), item.epoch(),
                        item.payload(), item.recordVersion()).bytes(), mtu);
                case Outgoing.Message item -> {
                    var message = item.message();
                    var body = message.body();
                    var room = Math.max(16, mtu - records.overhead(item.epoch()) - HandshakeMessage.DTLS_HEADER_LENGTH);
                    var offset = 0;
                    do {
                        var count = Math.min(room, body.length - offset);
                        var fragment = new TlsWriter(HandshakeMessage.DTLS_HEADER_LENGTH + count)
                                .u8(message.type()).u24(body.length).u16(message.messageSeq()).u24(offset).u24(count)
                                .bytes(body, offset, count).toByteArray();
                        var encoded = records.encode(RecordLayer.HANDSHAKE, item.epoch(), fragment,
                                DtlsVersion.DTLS_1_2.wireValue());
                        target.sentRecords.put(encoded.epoch() << 48 | encoded.sequence(), new int[]{index, offset, count});
                        append(datagram, encoded.bytes(), mtu);
                        offset += count;
                    } while (offset < body.length);
                }
            }
        }
        if (datagram.size() > 0) {
            send(datagram.toByteArray());
        }
    }

    /// Appends a record to the datagram being built, sending the datagram first when the record does not fit.
    private void append(ByteArrayOutputStream datagram, byte[] record, int mtu) throws IOException {
        if (datagram.size() > 0 && datagram.size() + record.length > mtu) {
            send(datagram.toByteArray());
            datagram.reset();
        }
        datagram.writeBytes(record);
    }

    /// Sends one datagram on the lower transport; the caller holds the lock.
    private void send(byte[] datagram) throws IOException {
        lower.send(ByteBuffer.wrap(datagram));
        packetsSent++;
        bytesSent += datagram.length;
    }

    /// Sends a fatal alert, or a warning for `close_notify`, ignoring failures; the caller holds the lock.
    private void sendAlertQuietly(DtlsAlert alert) {
        sendAlertQuietly(alert, alert == DtlsAlert.CLOSE_NOTIFY ? 1 : 2);
    }

    /// Sends an alert with a level, ignoring failures; the caller holds the lock.
    private void sendAlertQuietly(DtlsAlert alert, int level) {
        try {
            var epoch = records.hasWriteEpoch(writeEpoch) ? writeEpoch : 0;
            send(records.encode(RecordLayer.ALERT, epoch, new byte[]{(byte) level, (byte) alert.code()},
                    DtlsVersion.DTLS_1_2.wireValue()).bytes());
        } catch (IOException | RuntimeException exception) {
            if (LOGGER.isLoggable(Level.DEBUG)) {
                LOGGER.log(Level.DEBUG, "could not send the DTLS alert " + alert, exception);
            }
        }
    }

    /// Starts the post-handshake timer thread when a flight awaits acknowledgement; the caller holds the lock.
    private void ensureTimer() {
        if (timerThread == null && !closed && flight != null && flight.retransmitOnTimer) {
            timerThread = config.threadFactory().newThread(this::timerLoop);
            timerThread.start();
        } else {
            timerSignal.signalAll();
        }
    }

    /// Retransmits the post-handshake flight on its timer until it is acknowledged, abandoned or the transport closes.
    private void timerLoop() {
        lock.lock();
        try {
            while (!closed && flight != null && flight.retransmitOnTimer) {
                var wait = flight.deadline - config.clock().nanos();
                if (wait > 0) {
                    timerSignal.awaitNanos(wait);
                    continue;
                }
                if (flight.retransmissions >= MAX_POST_HANDSHAKE_RETRANSMISSIONS) {
                    flight = null;
                    break;
                }
                retransmit(flight);
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (IOException exception) {
            if (LOGGER.isLoggable(Level.DEBUG)) {
                LOGGER.log(Level.DEBUG, "DTLS retransmission failed", exception);
            }
        } finally {
            timerThread = null;
            unlock();
        }
    }

    /// Records a state change to report once the lock is released; the caller holds the lock.
    private void transition(DtlsState next) {
        if (state != next) {
            state = next;
            pendingStates.add(next);
        }
    }

    /// Releases the lock, then reports the state changes and delivers the application data that queued under it.
    ///
    /// Only a thread that queued application data delivers: a thread that only sent (an SCTP writer, a media
    /// sender) never calls the application receiver, which would re-enter the layer above on its own sending thread.
    private void unlock() {
        List<DtlsState> states = List.of();
        var queued = false;
        if (lock.getHoldCount() == 1) {
            if (!pendingStates.isEmpty()) {
                states = List.copyOf(pendingStates);
                pendingStates.clear();
            }
            if (!pendingData.isEmpty()) {
                deliveries.addAll(pendingData);
                pendingData.clear();
                queued = true;
            }
        }
        lock.unlock();
        for (var next : states) {
            try {
                stateListener.accept(next);
            } catch (RuntimeException exception) {
                LOGGER.log(Level.WARNING, "a DTLS state listener failed", exception);
            }
        }
        if (queued) {
            drainApplicationData();
        }
    }

    /// Delivers the released application data, one thread at a time and in record order: a thread that finds another
    /// delivering leaves its payloads to it.
    private void drainApplicationData() {
        while (!deliveries.isEmpty() && delivering.compareAndSet(false, true)) {
            try {
                var receiver = applicationReceiver;
                var now = config.clock().nanos();
                byte[] payload;
                while ((payload = deliveries.poll()) != null) {
                    try {
                        receiver.receive(ByteBuffer.wrap(payload), now);
                    } catch (RuntimeException exception) {
                        LOGGER.log(Level.WARNING, "a DTLS application data receiver failed", exception);
                    }
                }
            } finally {
                delivering.set(false);
            }
        }
    }

    /// A flight in flight: what it carries, which records carried which bytes, what the peer acknowledged, and its
    /// retransmission timer.
    private static final class Flight {
        /// The elements, in order.
        private final List<Outgoing> items;

        /// Whether the timer resends the flight.
        private final boolean retransmitOnTimer;

        /// The record numbers sent, mapped to the item index, fragment offset and length they carried.
        private final Map<Long, int[]> sentRecords = new HashMap<>();

        /// The acknowledged byte ranges of each item.
        private final BitSet[] acknowledged;

        /// Whether each item was acknowledged as a whole.
        private final boolean[] complete;

        /// The current timeout.
        private long rto;

        /// The clock time the timer expires.
        private long deadline;

        /// The retransmissions so far.
        private int retransmissions;

        /// What to run once every item is acknowledged, or `null`.
        private Runnable onAcknowledged;

        /// Creates a flight and arms its timer.
        private Flight(List<Outgoing> items, boolean retransmitOnTimer, long rto, long now) {
            this.items = List.copyOf(items);
            this.retransmitOnTimer = retransmitOnTimer;
            this.acknowledged = new BitSet[items.size()];
            this.complete = new boolean[items.size()];
            for (var index = 0; index < acknowledged.length; index++) {
                acknowledged[index] = new BitSet();
            }
            this.rto = rto;
            this.deadline = now + rto;
        }

        /// Marks the bytes a record carried as acknowledged.
        private void acknowledge(long recordNumber) {
            var range = sentRecords.get(recordNumber);
            if (range == null) {
                return;
            }
            var index = range[0];
            acknowledged[index].set(range[1], range[1] + range[2]);
            if (items.get(index) instanceof Outgoing.Message message
                    && acknowledged[index].cardinality() >= message.message().body().length) {
                complete[index] = true;
            }
        }

        /// {@return whether an item was acknowledged}
        private boolean isItemAcknowledged(int index) {
            return complete[index];
        }

        /// {@return whether every handshake message of the flight was acknowledged}
        private boolean isAcknowledged() {
            for (var index = 0; index < items.size(); index++) {
                if (items.get(index) instanceof Outgoing.Message && !complete[index]) {
                    return false;
                }
            }
            return true;
        }
    }

    /// The application data view of the association.
    private final class ApplicationData implements DatagramTransport {
        @Override
        public void send(ByteBuffer datagram) throws IOException {
            var payload = new byte[datagram.remaining()];
            datagram.duplicate().get(payload);
            if (payload.length > RecordLayer.MAX_PLAINTEXT) {
                throw new IllegalArgumentException("application data of " + payload.length + " bytes exceeds a record");
            }
            byte[] record;
            lock.lock();
            try {
                if (!established || closed) {
                    throw new ClosedChannelException();
                }
                record = records.encode(RecordLayer.APPLICATION_DATA, writeEpoch, payload,
                        DtlsVersion.DTLS_1_2.wireValue()).bytes();
                packetsSent++;
                bytesSent += record.length;
            } finally {
                unlock();
            }
            lower.send(ByteBuffer.wrap(record));
        }

        @Override
        public void setReceiver(PacketReceiver receiver) {
            applicationReceiver = Objects.requireNonNull(receiver, "receiver cannot be null");
        }

        @Override
        public int maxDatagramSize() {
            return lower.maxDatagramSize() - MAX_RECORD_EXPANSION;
        }

        @Override
        public void close() {
            applicationReceiver = DISCARD;
        }
    }

    /// The path RTP and RTCP share with the association.
    private final class MediaPath implements DatagramTransport {
        @Override
        public void send(ByteBuffer datagram) throws IOException {
            lower.send(datagram);
        }

        @Override
        public void setReceiver(PacketReceiver receiver) {
            setNonDtlsReceiver(receiver);
        }

        @Override
        public int maxDatagramSize() {
            return lower.maxDatagramSize();
        }

        @Override
        public void close() {
            nonDtlsReceiver = DISCARD;
        }
    }
}
