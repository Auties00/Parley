package com.github.auties00.parley.dtls;

import com.github.auties00.parley.net.DatagramTransport;
import com.github.auties00.parley.net.PacketReceiver;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/// A DTLS association over a [DatagramTransport]: it runs a DTLS 1.2 or 1.3 handshake that negotiates SRTP keys with
/// `use_srtp`, then carries application data (SCTP for data channels) and passes RTP and RTCP that share the lower
/// transport to a separate receiver.
///
/// [#over(DatagramTransport,DtlsConfig)] takes over the lower transport's receiver at once, so a peer's first flight
/// that arrives before [#handshake(DtlsRole,List,Duration)] is called is kept, not lost:
///
/// {@snippet lang = java :
/// var certificate = DtlsCertificate.generateEcdsa();
/// // signal certificate.fingerprints() in a=fingerprint, read the peer's
/// var dtls = DtlsTransport.over(iceTransport, DtlsConfig.of(certificate));
/// dtls.setNonDtlsReceiver(srtpReceiver);
/// DtlsSrtpKeys keys = dtls.handshake(DtlsRole.CLIENT, remoteFingerprints, Duration.ofSeconds(10));
/// }
///
/// # Demultiplexing
///
/// Every datagram the lower transport delivers is classified by its first byte: 20 to 63 is DTLS and handled here,
/// 128 to 191 is RTP or RTCP and goes, as it is and on the lower transport's reader thread, to the
/// [non-DTLS receiver][#setNonDtlsReceiver(PacketReceiver)]; anything else is dropped.
///
/// # Versions and keys
///
/// A client offers every version in [DtlsConfig#versions()] and a server picks DTLS 1.3 when both sides support it, so
/// two endpoints of this library always agree on DTLS 1.3 and still interoperate with DTLS 1.2-only peers. Each side
/// authenticates with a [DtlsCertificate] and accepts the peer only if its certificate matches one of the
/// `a=fingerprint` values passed to the handshake. The handshake returns the SRTP keys of both directions, exported with
/// `EXTRACTOR-dtls_srtp`.
///
/// # Lifecycle
///
/// A transport runs one handshake. Afterwards [#applicationData()] carries application data, a DTLS 1.3 transport
/// can [update its keys][#updateKeys(boolean)], and [#close()] sends `close_notify`. A new association with the same
/// peer (new fingerprints or `a=tls-id`, see [DtlsParameters]) is a new transport: [#restart()].
/// [#setStateListener(Consumer)] reports every [DtlsState] change.
///
/// # Threading
///
/// [#handshake(DtlsRole,List,Duration)] blocks the calling thread and runs the handshake's timers on it. Received
/// records are processed on the lower transport's reader thread, which also calls the application data and non-DTLS
/// receivers; a slow receiver delays every datagram behind it. After the handshake a transport may start one timer
/// thread, from [DtlsConfig#threadFactory()], to retransmit a flight the peer has not acknowledged. Every method may
/// be called from any thread.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public sealed interface DtlsTransport extends AutoCloseable permits DtlsConnection {
    /// {@return a transport over a lower datagram transport; the handshake has not started}
    ///
    /// The transport replaces the lower transport's receiver at once and keeps the DTLS records that arrive before the
    /// handshake starts. It never closes the lower transport.
    ///
    /// @param lower  the lower transport, typically the selected ICE pair
    /// @param config the settings
    static DtlsTransport over(DatagramTransport lower, DtlsConfig config) {
        return new DtlsConnection(lower, config);
    }

    /// Runs the handshake and returns the SRTP keys.
    ///
    /// Blocks until the handshake completes. The current flight is sent again whenever the peer is silent for the
    /// retransmission timeout, which starts at [DtlsConfig#initialRetransmit()] and doubles up to 60 seconds, or
    /// shows that it missed the flight. When this side rejects the handshake it sends the peer a fatal alert first.
    ///
    /// @param role               the role of this endpoint, from `a=setup`
    /// @param remoteFingerprints the peer's `a=fingerprint` values; its certificate must match one of those of the
    ///                           strongest hash function listed
    /// @param timeout            the longest time the whole handshake may take
    /// @return the SRTP keys of both directions, assigned to this endpoint's role
    /// @throws DtlsException            if the handshake fails: the certificate matches no fingerprint, no common
    ///                                  version, cipher suite or SRTP profile exists, a message does not verify, the
    ///                                  peer sends a fatal alert, the lower transport fails, or the timeout elapses
    /// @throws InterruptedException     if the calling thread is interrupted
    /// @throws IllegalArgumentException if `remoteFingerprints` is empty
    /// @throws IllegalStateException    if a handshake already ran or the transport is closed
    DtlsSrtpKeys handshake(DtlsRole role, List<DtlsFingerprint> remoteFingerprints, Duration timeout)
            throws DtlsException, InterruptedException;

    /// Runs the handshake without requiring SRTP, for a transport that carries only application data.
    ///
    /// Behaves as [#handshake(DtlsRole,List,Duration)] except that a handshake in which no SRTP profile is agreed
    /// succeeds; the profiles of [DtlsConfig#srtpProfiles()] are still offered, and [#srtpProfile()] tells whether one
    /// was agreed.
    ///
    /// @param role               the role of this endpoint
    /// @param remoteFingerprints the peer's `a=fingerprint` values
    /// @param timeout            the longest time the handshake may take
    /// @throws DtlsException            if the handshake fails
    /// @throws InterruptedException     if the calling thread is interrupted
    /// @throws IllegalArgumentException if `remoteFingerprints` is empty
    /// @throws IllegalStateException    if a handshake already ran or the transport is closed
    void handshakeWithoutSrtp(DtlsRole role, List<DtlsFingerprint> remoteFingerprints, Duration timeout)
            throws DtlsException, InterruptedException;

    /// {@return the current state}
    DtlsState state();

    /// {@return the handshake role, absent before the handshake started}
    Optional<DtlsRole> role();

    /// {@return the negotiated version, absent before the peer's hello settled it}
    Optional<DtlsVersion> negotiatedVersion();

    /// {@return the negotiated SRTP profile, absent before it was agreed or when none was}
    Optional<SrtpProfile> srtpProfile();

    /// {@return the SRTP keys the handshake exported, absent before it completed or when no SRTP profile was agreed}
    ///
    /// They equal those [#handshake(DtlsRole,List,Duration)] returned; an SRTP layer created before the handshake
    /// reads them here once it completes.
    Optional<DtlsSrtpKeys> srtpKeys();

    /// {@return the peer's certificate, absent before it was received and verified}
    Optional<X509Certificate> remoteCertificate();

    /// {@return the transport of DTLS application data, which an SCTP association runs over}
    ///
    /// Sending fails with an [IllegalStateException] before the handshake completed or after the association ended.
    /// Its receiver is called on the lower transport's reader thread with the plaintext of each application data
    /// record. Closing it only detaches its receiver; the association stays open.
    DatagramTransport applicationData();

    /// {@return the path RTP and RTCP share with this association on the lower transport}
    ///
    /// Sending passes the datagram to the lower transport unchanged, at any time; the receiver is the
    /// [non-DTLS receiver][#setNonDtlsReceiver(PacketReceiver)]; the size budget is the lower transport's. Closing it
    /// only detaches its receiver.
    DatagramTransport mediaPath();

    /// Sets the receiver of the RTP and RTCP datagrams (first byte 128 to 191) that arrive on the lower transport,
    /// replacing the previous one; they are passed on unmodified and still protected.
    ///
    /// @param receiver the receiver
    void setNonDtlsReceiver(PacketReceiver receiver);

    /// Sets the listener of state changes, replacing the previous one.
    ///
    /// The listener is called after each change, on the thread that caused it, with no lock held.
    ///
    /// @param listener the listener
    void setStateListener(Consumer<DtlsState> listener);

    /// Updates this side's DTLS 1.3 sending keys with a `KeyUpdate` message.
    ///
    /// The new keys take effect once the peer acknowledges the message; until then records keep the current keys.
    ///
    /// @param requestPeerUpdate whether to ask the peer to update its sending keys as well
    /// @throws IOException           if the lower transport fails
    /// @throws IllegalStateException if the transport is not connected with DTLS 1.3, or an earlier update is not
    ///                               acknowledged yet
    /// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
    void updateKeys(boolean requestPeerUpdate) throws IOException;

    /// {@return a new transport over the same lower transport and settings, for a new association with the peer}
    ///
    /// This transport is closed with `close_notify` first; the new one owns the lower transport's receiver and has not
    /// started its handshake. RFC 8842 requires a new association when the peer's `a=tls-id` or fingerprints change.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
    DtlsTransport restart();

    /// {@return a snapshot of the state and counters}
    DtlsTransportStatistics statistics();

    /// Closes the association: sends `close_notify` when connected, moves to [DtlsState#CLOSED], stops the timer
    /// thread and detaches from the lower transport, which stays open.
    ///
    /// A thread blocked in the handshake fails with a [DtlsException]. Calling this method again has no effect.
    @Override
    void close();
}
