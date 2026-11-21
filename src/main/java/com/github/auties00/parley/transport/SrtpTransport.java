package com.github.auties00.parley.transport;

import com.github.auties00.parley.dtls.DtlsSrtpKeys;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.srtp.SrtpContextFactory;
import com.github.auties00.srtp.SrtpCryptoSuite;
import com.github.auties00.srtp.SrtpErrorStatus;
import com.github.auties00.srtp.SrtpPacket;
import com.github.auties00.srtp.SrtpPolicy;
import com.github.auties00.srtp.SrtpTransformer;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

/// The [RtpTransport] of this library: SRTP and SRTCP protection with per-SSRC contexts, keyed either by a DTLS-SRTP
/// handshake or by SDES keys exchanged in the session descriptions.
///
/// - [#dtlsSrtp(DtlsTransport)] receives the RTP and RTCP that share the DTLS transport's path, and keys itself with
///   the [exported keys][DtlsTransport#srtpKeys()] once the handshake completes; until then sends fail and received
///   packets are dropped as unkeyed. This is the keying of `UDP/TLS/RTP/SAVPF`.
/// - [#sdes(DatagramTransport,SrtpCryptoSuite,byte\[\],byte\[\],byte\[\],byte\[\])] is keyed at once with the master
///   keys of `a=crypto` lines, the keying of `RTP/SAVP` and `RTP/SAVPF` without DTLS.
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
/// the session keys derived once per direction.
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

    /// The lock that serializes keying.
    private final Object keyLock = new Object();

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
    private final AtomicInteger consecutiveFailures = new AtomicInteger();

    /// The receiver of RTP.
    private volatile PacketReceiver rtpReceiver = DISCARD;

    /// The receiver of RTCP.
    private volatile PacketReceiver rtcpReceiver = DISCARD;

    /// The listener of authentication failure runs, for [MediaTransport]; `null` for none.
    private volatile FailureListener failureListener;

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

    /// {@return a transport keyed with SDES master keys and salts}
    ///
    /// The transport becomes the receiver of `lower`.
    ///
    /// @param lower      the path to the peer
    /// @param suite      the crypto suite both `a=crypto` lines agreed
    /// @param localKey   the master key of the media this side sends
    /// @param localSalt  the master salt of the media this side sends
    /// @param remoteKey  the master key of the media the peer sends
    /// @param remoteSalt the master salt of the media the peer sends
    /// @throws IllegalArgumentException if a key or salt has the wrong length for the suite
    public static SrtpTransport sdes(DatagramTransport lower, SrtpCryptoSuite suite, byte[] localKey, byte[] localSalt,
                                     byte[] remoteKey, byte[] remoteSalt) {
        return sdes(lower, suite, localKey, localSalt, remoteKey, remoteSalt, SrtpOptions.DEFAULT);
    }

    /// {@return a transport keyed with SDES master keys and salts, with options}
    ///
    /// @param lower      the path to the peer
    /// @param suite      the crypto suite
    /// @param localKey   the master key of the media this side sends
    /// @param localSalt  the master salt of the media this side sends
    /// @param remoteKey  the master key of the media the peer sends
    /// @param remoteSalt the master salt of the media the peer sends
    /// @param options    the SRTP settings
    /// @throws IllegalArgumentException if a key or salt has the wrong length for the suite, or cryptex is asked for a
    ///                                  suite without encryption
    public static SrtpTransport sdes(DatagramTransport lower, SrtpCryptoSuite suite, byte[] localKey, byte[] localSalt,
                                     byte[] remoteKey, byte[] remoteSalt, SrtpOptions options) {
        Objects.requireNonNull(lower, "lower cannot be null");
        Objects.requireNonNull(suite, "suite cannot be null");
        Objects.requireNonNull(options, "options cannot be null");
        var transport = new SrtpTransport(lower, null, options);
        transport.key(suite, localKey, localSalt, remoteKey, remoteSalt);
        lower.setReceiver(transport::onPacket);
        return transport;
    }

    @Override
    public void sendRtp(ByteBuffer plainRtp) throws IOException {
        var transformer = requireOutbound();
        protectAndSend(plainRtp, false, transformer);
    }

    @Override
    public void sendRtcp(ByteBuffer plainCompoundRtcp) throws IOException {
        var transformer = requireOutbound();
        protectAndSend(plainCompoundRtcp, true, transformer);
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

    @Override
    public void close() {
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
    }

    /// Sets the listener of authentication failures, used by [MediaTransport] to fail on a long run of them.
    ///
    /// @param listener the listener, or `null` for none
    void setFailureListener(FailureListener listener) {
        this.failureListener = listener;
    }

    /// Receives the number of consecutive authentication failures after each failure.
    @FunctionalInterface
    interface FailureListener {
        /// Called after a packet failed authentication.
        ///
        /// @param consecutive the failures since the last authenticated packet
        void onAuthenticationFailure(int consecutive);
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
    private SrtpTransformer requireOutbound() {
        if (closed) {
            throw new IllegalStateException("the SRTP transport is closed");
        }
        var transformer = outbound;
        if (transformer == null) {
            transformer = tryKeyFromDtls();
        }
        if (transformer == null) {
            throw new IllegalStateException("the SRTP transport is not keyed yet");
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

    /// Protects a packet, in place when the buffer allows it, and sends it.
    private void protectAndSend(ByteBuffer packet, boolean rtcp, SrtpTransformer transformer) throws IOException {
        var length = packet.remaining();
        if (length < (rtcp ? MIN_RTCP_LENGTH : MIN_RTP_LENGTH)) {
            throw new IllegalArgumentException("packet of " + length + " bytes is too short");
        }
        byte[] array;
        int offset;
        if (packet.hasArray() && !packet.isReadOnly()
                && packet.capacity() - packet.limit() >= overhead) {
            array = packet.array();
            offset = packet.arrayOffset() + packet.position();
        } else {
            array = new byte[length + overhead];
            packet.duplicate().get(array, 0, length);
            offset = 0;
        }
        var srtp = new SrtpPacket(array, offset, length);
        var status = rtcp ? transformer.protectRtcp(srtp) : transformer.protectRtp(srtp);
        if (status != SrtpErrorStatus.OK) {
            throw new IOException((rtcp ? "SRTCP" : "SRTP") + " protection failed: " + status);
        }
        sendPath.send(ByteBuffer.wrap(array, offset, srtp.length()));
        if (rtcp) {
            rtcpPacketsSent.increment();
            rtcpBytesSent.add(srtp.length());
        } else {
            rtpPacketsSent.increment();
            rtpBytesSent.add(srtp.length());
        }
    }

    /// Unprotects one received packet and hands it to its receiver.
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
        var transformer = inbound;
        if (transformer == null) {
            tryKeyFromDtls();
            transformer = inbound;
            if (transformer == null) {
                unkeyedPackets.increment();
                return;
            }
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
        var srtp = new SrtpPacket(array, offset, length);
        var status = rtcp ? transformer.unprotectRtcp(srtp) : transformer.unprotectRtp(srtp);
        switch (status) {
            case OK -> {
                consecutiveFailures.set(0);
                if (rtcp) {
                    rtcpPacketsReceived.increment();
                    rtcpBytesReceived.add(length);
                } else {
                    rtpPacketsReceived.increment();
                    rtpBytesReceived.add(length);
                }
                var receiver = rtcp ? rtcpReceiver : rtpReceiver;
                try {
                    receiver.receive(ByteBuffer.wrap(array, offset, srtp.length()).slice(), arrivalNanos);
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
                var listener = failureListener;
                var count = consecutiveFailures.incrementAndGet();
                if (listener != null) {
                    listener.onAuthenticationFailure(count);
                }
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
