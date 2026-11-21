package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsSrtpKeys;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.sdp.SdesCrypto;
import com.github.auties00.srtp.SrtpContextFactory;
import com.github.auties00.srtp.SrtpCryptoSuite;
import com.github.auties00.srtp.SrtpErrorStatus;
import com.github.auties00.srtp.SrtpPacket;
import com.github.auties00.srtp.SrtpPolicy;
import com.github.auties00.srtp.SrtpTransformer;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.ReentrantLock;

/// The [RtpTransport] of this library: SRTP and SRTCP protection with per-SSRC contexts, keyed either by a DTLS-SRTP
/// handshake or by SDES keys exchanged in the session descriptions.
///
/// - [#dtlsSrtp(DtlsTransport)] receives the RTP and RTCP that share the DTLS transport's path, and keys itself with
///   the [exported keys][DtlsTransport#srtpKeys()] once the handshake completes; until then sends fail and received
///   packets are dropped as unkeyed. This is the keying of `UDP/TLS/RTP/SAVPF`.
/// - [#sdes(DatagramTransport,SdesCrypto,SdesCrypto)] is keyed at once with the master keys of the two `a=crypto`
///   lines, the keying of `RTP/SAVP` and `RTP/SAVPF` without DTLS.
///
/// {@snippet lang = java :
/// var srtp = SrtpTransport.dtlsSrtp(dtls);
/// srtp.setRtpReceiver((packet, arrival) -> jitterBuffer.insert(packet));
/// dtls.handshake(DtlsRole.CLIENT, remoteFingerprints, Duration.ofSeconds(10));
/// var buffer = ByteBuffer.allocate(1500);          // leave srtp.protectionOverhead() spare bytes
/// writeRtp(buffer.limit(rtpLength));
/// srtp.sendRtp(buffer);
/// }
///
/// Each SSRC gets its own SRTP context on first use, with its own rollover counter and replay window; contexts share
/// the session keys derived once per direction. Cryptex, when [SrtpOptions#cryptex()] turns it on, applies to every
/// stream of the transport: RFC 9335 requires every RTP section of one BUNDLE group, and so of one transport, to agree
/// on it.
///
/// # Threading
///
/// Every method may be called from any thread. Protection is serialized: one lock is held from protecting a packet
/// until the path accepted it, so the packets of every stream reach the wire in the order of their SRTP indexes even
/// when several threads send. Unprotection is serialized per stream, under one of 16 locks chosen by the low bits of
/// the SSRC, so packets of different streams that arrive on different reader threads are still processed in
/// parallel. Receivers are called after the lock is released, on the thread that delivered the packet.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3711.html RFC 3711: The Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc7714.html RFC 7714: AES-GCM Authenticated Encryption in the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc6188.html RFC 6188: The Use of AES-192 and AES-256 in Secure RTP
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
/// @spec https://www.rfc-editor.org/rfc/rfc9335.html RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources
/// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
public final class SrtpTransport implements RtpTransport {
    private static final System.Logger LOGGER = System.getLogger(SrtpTransport.class.getName());

    /// The RTP header length below which a packet is malformed.
    private static final int MIN_RTP_LENGTH = 12;

    /// The RTCP header length below which a packet is malformed.
    private static final int MIN_RTCP_LENGTH = 8;

    /// The largest SRTCP expansion: a 16-byte tag plus the 4-byte index.
    private static final int MAX_RTCP_OVERHEAD = 20;

    /// The largest SRTP expansion: a 16-byte tag plus the 4 bytes cryptex may add.
    private static final int MAX_RTP_OVERHEAD = 20;

    /// A receiver that drops everything.
    private static final PacketReceiver DISCARD = (packet, arrivalNanos) -> {
    };

    /// The path packets are sent on.
    private final DatagramTransport sendPath;

    /// The DTLS transport whose keys key this transport, or `null` for SDES.
    private final DtlsTransport dtls;

    /// The settings.
    private final SrtpOptions options;

    /// The number of locks the unprotection of received packets is striped over, by SSRC.
    private static final int UNPROTECT_STRIPES = 16;

    /// The lock that serializes keying.
    private final Object keyLock = new Object();

    /// The lock held from protecting an outgoing packet until the path accepted it.
    private final ReentrantLock protectLock = new ReentrantLock();

    /// The array a packet without tailroom is copied into and protected in, grown on demand and reused; guarded by
    /// [#protectLock].
    private byte[] protectScratch = new byte[0];

    /// The buffer over [#protectScratch] handed to the path; guarded by [#protectLock].
    private ByteBuffer protectScratchBuffer = ByteBuffer.wrap(protectScratch);

    /// The locks that serialize unprotection, indexed by `ssrc & 15`.
    private final ReentrantLock[] unprotectLocks = new ReentrantLock[UNPROTECT_STRIPES];

    /// The counters.
    private final LongAdder rtpPacketsSent = new LongAdder();

    /// The bytes of RTP packets sent.
    private final LongAdder rtpBytesSent = new LongAdder();

    /// The RTCP packets sent.
    private final LongAdder rtcpPacketsSent = new LongAdder();

    /// The bytes of RTCP packets sent.
    private final LongAdder rtcpBytesSent = new LongAdder();

    /// The RTP packets received.
    private final LongAdder rtpPacketsReceived = new LongAdder();

    /// The bytes of RTP packets received.
    private final LongAdder rtpBytesReceived = new LongAdder();

    /// The RTCP packets received.
    private final LongAdder rtcpPacketsReceived = new LongAdder();

    /// The bytes of RTCP packets received.
    private final LongAdder rtcpBytesReceived = new LongAdder();

    /// The authentication failures.
    private final LongAdder authenticationFailures = new LongAdder();

    /// The replays.
    private final LongAdder replayedPackets = new LongAdder();

    /// The malformed packets.
    private final LongAdder malformedPackets = new LongAdder();

    /// The packets received before keying.
    private final LongAdder unkeyedPackets = new LongAdder();

    /// The authentication failures since the last authenticated packet.
    private final AtomicLong failuresSinceAuthenticated = new AtomicLong();

    /// The receiver of RTP.
    private volatile PacketReceiver rtpReceiver = DISCARD;

    /// The receiver of RTCP.
    private volatile PacketReceiver rtcpReceiver = DISCARD;

    /// The protection of outgoing packets, `null` before keying.
    private volatile SrtpTransformer outbound;

    /// The protection of incoming packets, `null` before keying.
    private volatile SrtpTransformer inbound;

    /// The suite, `null` before keying.
    private volatile SrtpCryptoSuite suite;

    /// The protection overhead of the keyed suite.
    private volatile int overhead = Math.max(MAX_RTP_OVERHEAD, MAX_RTCP_OVERHEAD);

    /// Whether the transport is closed.
    private volatile boolean closed;

    /// Creates a transport.
    private SrtpTransport(DatagramTransport sendPath, DtlsTransport dtls, SrtpOptions options) {
        this.sendPath = sendPath;
        this.dtls = dtls;
        this.options = options;
        for (var index = 0; index < UNPROTECT_STRIPES; index++) {
            unprotectLocks[index] = new ReentrantLock();
        }
    }

    /// {@return a transport keyed by a DTLS-SRTP handshake}
    ///
    /// The transport becomes the DTLS transport's [non-DTLS receiver][DtlsTransport#setNonDtlsReceiver(PacketReceiver)]
    /// at once and keys itself from [DtlsTransport#srtpKeys()] as soon as they exist.
    ///
    /// @param dtls the DTLS transport
    public static SrtpTransport dtlsSrtp(DtlsTransport dtls) {
        return dtlsSrtp(dtls, SrtpOptions.DEFAULT);
    }

    /// {@return a transport keyed by a DTLS-SRTP handshake, with options}
    ///
    /// @param dtls    the DTLS transport
    /// @param options the SRTP settings
    public static SrtpTransport dtlsSrtp(DtlsTransport dtls, SrtpOptions options) {
        Objects.requireNonNull(dtls, "dtls cannot be null");
        Objects.requireNonNull(options, "options cannot be null");
        var transport = new SrtpTransport(dtls.mediaPath(), dtls, options);
        dtls.setNonDtlsReceiver(transport::onPacket);
        dtls.srtpKeys().ifPresent(transport::key);
        return transport;
    }

    /// {@return a transport keyed with the master keys of two SDES `a=crypto` lines}
    ///
    /// The transport becomes the receiver of `lower`.
    ///
    /// @param lower  the path to the peer
    /// @param local  this side's `a=crypto` line, whose key protects the media this side sends
    /// @param remote the peer's `a=crypto` line, whose key protects the media the peer sends
    /// @throws IllegalArgumentException if the two lines name different suites
    public static SrtpTransport sdes(DatagramTransport lower, SdesCrypto local, SdesCrypto remote) {
        return sdes(lower, local, remote, SrtpOptions.DEFAULT);
    }

    /// {@return a transport keyed with the master keys of two SDES `a=crypto` lines, with options}
    ///
    /// @param lower   the path to the peer
    /// @param local   this side's `a=crypto` line, whose key protects the media this side sends
    /// @param remote  the peer's `a=crypto` line, whose key protects the media the peer sends
    /// @param options the SRTP settings
    /// @throws IllegalArgumentException if the two lines name different suites, or cryptex is asked for a suite
    ///                                  without encryption
    /// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
    public static SrtpTransport sdes(DatagramTransport lower, SdesCrypto local, SdesCrypto remote,
                                     SrtpOptions options) {
        Objects.requireNonNull(lower, "lower cannot be null");
        Objects.requireNonNull(local, "local cannot be null");
        Objects.requireNonNull(remote, "remote cannot be null");
        Objects.requireNonNull(options, "options cannot be null");
        if (local.suite() != remote.suite()) {
            throw new IllegalArgumentException("the local line uses " + local.suite() + " and the remote one "
                    + remote.suite());
        }
        var transport = new SrtpTransport(lower, null, options);
        transport.key(local.suite(), local.masterKey(), local.masterSalt(), remote.masterKey(), remote.masterSalt());
        lower.setReceiver(transport::onPacket);
        return transport;
    }

    @Override
    public void sendRtp(ByteBuffer plainRtp) throws IOException {
        protectAndSend(plainRtp, false);
    }

    @Override
    public void sendRtcp(ByteBuffer plainCompoundRtcp) throws IOException {
        protectAndSend(plainCompoundRtcp, true);
    }

    @Override
    public void setRtpReceiver(PacketReceiver receiver) {
        this.rtpReceiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    @Override
    public void setRtcpReceiver(PacketReceiver receiver) {
        this.rtcpReceiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    @Override
    public int protectionOverhead() {
        return overhead;
    }

    /// {@return whether the transport is keyed and can send}
    public boolean isKeyed() {
        return outbound != null || tryKeyFromDtls() != null;
    }

    @Override
    public RtpTransportStatistics statistics() {
        return new RtpTransportStatistics(Optional.ofNullable(suite), rtpPacketsSent.sum(), rtpBytesSent.sum(),
                rtcpPacketsSent.sum(), rtcpBytesSent.sum(), rtpPacketsReceived.sum(), rtpBytesReceived.sum(),
                rtcpPacketsReceived.sum(), rtcpBytesReceived.sum(), authenticationFailures.sum(),
                replayedPackets.sum(), malformedPackets.sum(), unkeyedPackets.sum());
    }

    /// {@inheritDoc}
    ///
    /// Waits for a packet being protected or unprotected on another thread to finish before wiping the keys.
    @Override
    public void close() {
        for (var lock : unprotectLocks) {
            lock.lock();
        }
        protectLock.lock();
        try {
            synchronized (keyLock) {
                if (closed) {
                    return;
                }
                closed = true;
                if (outbound != null) {
                    outbound.close();
                }
                if (inbound != null) {
                    inbound.close();
                }
            }
        } finally {
            protectLock.unlock();
            for (var index = unprotectLocks.length - 1; index >= 0; index--) {
                unprotectLocks[index].unlock();
            }
        }
    }

    /// {@return the packets that failed authentication since the last one that authenticated}
    long failuresSinceAuthenticated() {
        return failuresSinceAuthenticated.get();
    }

    /// Keys the transport from DTLS-SRTP keys.
    private void key(DtlsSrtpKeys keys) {
        key(keys.profile().suite(), keys.localKey(), keys.localSalt(), keys.remoteKey(), keys.remoteSalt());
    }

    /// Keys both directions; a second call has no effect.
    private void key(SrtpCryptoSuite suite, byte[] localKey, byte[] localSalt, byte[] remoteKey, byte[] remoteSalt) {
        synchronized (keyLock) {
            if (outbound != null || closed) {
                return;
            }
            var rtpPolicy = suite.policy().withReplayProtection(true, options.replayProtection())
                    .withCryptex(options.cryptex());
            var rtcpPolicy = suite.policy().withReplayProtection(true, options.replayProtection());
            SrtpContextFactory outboundFactory;
            SrtpContextFactory inboundFactory;
            try {
                outboundFactory = new SrtpContextFactory(localKey, localSalt, rtpPolicy, rtcpPolicy);
                inboundFactory = new SrtpContextFactory(remoteKey, remoteSalt, rtpPolicy, rtcpPolicy);
            } catch (RuntimeException exception) {
                throw new IllegalArgumentException("invalid SRTP keys for " + suite, exception);
            }
            if (localKey.length != suite.masterKeyLength() || localSalt.length != suite.masterSaltLength()
                    || remoteKey.length != suite.masterKeyLength() || remoteSalt.length != suite.masterSaltLength()) {
                outboundFactory.close();
                inboundFactory.close();
                throw new IllegalArgumentException(suite + " needs a " + suite.masterKeyLength() + "-byte key and a "
                        + suite.masterSaltLength() + "-byte salt");
            }
            this.overhead = Math.max(outboundFactory.rtpProtectionOverhead() + (options.cryptex() ? 4 : 0),
                    outboundFactory.rtcpProtectionOverhead());
            this.suite = suite;
            this.inbound = new SrtpTransformer(inboundFactory);
            this.outbound = new SrtpTransformer(outboundFactory);
        }
    }

    /// {@return the outbound protection, keying from DTLS first if needed}
    ///
    /// @throws ClosedChannelException if the transport is closed or not keyed yet
    private SrtpTransformer requireOutbound() throws ClosedChannelException {
        if (closed) {
            throw new ClosedChannelException();
        }
        var transformer = outbound;
        if (transformer == null) {
            transformer = tryKeyFromDtls();
        }
        if (transformer == null) {
            throw new ClosedChannelException();
        }
        return transformer;
    }

    /// {@return the outbound protection after keying from the DTLS transport's exported keys, or `null` before they
    /// exist}
    private SrtpTransformer tryKeyFromDtls() {
        if (dtls == null) {
            return outbound;
        }
        var keys = dtls.srtpKeys();
        keys.ifPresent(this::key);
        return outbound;
    }

    /// Protects a packet, in place when the buffer allows it and otherwise in a reused array, and sends it, under
    /// [#protectLock] so the wire order is the index order.
    private void protectAndSend(ByteBuffer packet, boolean rtcp) throws IOException {
        var length = packet.remaining();
        if (length < (rtcp ? MIN_RTCP_LENGTH : MIN_RTP_LENGTH)) {
            throw new IllegalArgumentException("packet of " + length + " bytes is too short");
        }
        protectLock.lock();
        try {
            var transformer = requireOutbound();
            byte[] array;
            int offset;
            ByteBuffer datagram;
            if (packet.hasArray() && !packet.isReadOnly()
                    && packet.capacity() - packet.limit() >= overhead) {
                array = packet.array();
                offset = packet.arrayOffset() + packet.position();
                datagram = null;
            } else {
                if (protectScratch.length < length + overhead) {
                    protectScratch = new byte[Math.max(length + overhead, 1500)];
                    protectScratchBuffer = ByteBuffer.wrap(protectScratch);
                }
                array = protectScratch;
                packet.get(packet.position(), array, 0, length);
                offset = 0;
                datagram = protectScratchBuffer;
            }
            var srtp = new SrtpPacket(array, offset, length);
            var status = rtcp ? transformer.protectRtcp(srtp) : transformer.protectRtp(srtp);
            if (status != SrtpErrorStatus.OK) {
                throw new IOException((rtcp ? "SRTCP" : "SRTP") + " protection failed: " + status);
            }
            sendPath.send(datagram == null ? ByteBuffer.wrap(array, offset, srtp.length())
                    : datagram.limit(srtp.length()).position(0));
            if (rtcp) {
                rtcpPacketsSent.increment();
                rtcpBytesSent.add(srtp.length());
            } else {
                rtpPacketsSent.increment();
                rtpBytesSent.add(srtp.length());
            }
        } finally {
            protectLock.unlock();
        }
    }

    /// Unprotects one received packet under the lock of its stream, then hands it to its receiver.
    private void onPacket(ByteBuffer packet, long arrivalNanos) {
        if (closed) {
            return;
        }
        var length = packet.remaining();
        var rtcp = length >= 2 && isRtcp(packet.get(packet.position() + 1) & 0xFF);
        if (length < (rtcp ? MIN_RTCP_LENGTH : MIN_RTP_LENGTH)) {
            malformedPackets.increment();
            return;
        }
        if (inbound == null) {
            tryKeyFromDtls();
        }
        byte[] array;
        int offset;
        if (packet.hasArray() && !packet.isReadOnly()) {
            array = packet.array();
            offset = packet.arrayOffset() + packet.position();
        } else {
            array = new byte[length];
            packet.duplicate().get(array);
            offset = 0;
        }
        var lastSsrcByte = offset + (rtcp ? 7 : 11);
        var lock = unprotectLocks[array[lastSsrcByte] & (UNPROTECT_STRIPES - 1)];
        var srtp = new SrtpPacket(array, offset, length);
        SrtpErrorStatus status;
        lock.lock();
        try {
            var transformer = inbound;
            if (closed) {
                return;
            }
            if (transformer == null) {
                unkeyedPackets.increment();
                return;
            }
            status = rtcp ? transformer.unprotectRtcp(srtp) : transformer.unprotectRtp(srtp);
        } finally {
            lock.unlock();
        }
        switch (status) {
            case OK -> {
                failuresSinceAuthenticated.set(0);
                if (rtcp) {
                    rtcpPacketsReceived.increment();
                    rtcpBytesReceived.add(length);
                } else {
                    rtpPacketsReceived.increment();
                    rtpBytesReceived.add(length);
                }
                var receiver = rtcp ? rtcpReceiver : rtpReceiver;
                try {
                    // A packet at the start of its array needs no slice to start at index 0
                    var plain = ByteBuffer.wrap(array, offset, srtp.length());
                    receiver.receive(offset == 0 ? plain : plain.slice(), arrivalNanos);
                } catch (RuntimeException exception) {
                    if (LOGGER.isLoggable(Level.WARNING)) {
                        LOGGER.log(Level.WARNING, "an RTP receiver failed", exception);
                    }
                }
            }
            case REPLAY_FAIL, REPLAY_OLD -> replayedPackets.increment();
            case INVALID_PACKET -> malformedPackets.increment();
            case AUTH_FAIL, FAIL -> {
                authenticationFailures.increment();
                failuresSinceAuthenticated.incrementAndGet();
            }
        }
    }

    /// {@return whether the second byte of a packet makes it RTCP: an RTCP packet type from 192 to 223}
    ///
    /// @param secondByte the second byte
    static boolean isRtcp(int secondByte) {
        return secondByte >= 192 && secondByte <= 223;
    }
}
