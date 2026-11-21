package com.github.auties00.parley.dtls;

import com.github.auties00.parley.net.MonotonicClock;

import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ThreadFactory;

/// The settings of a [DtlsTransport]: the certificates it authenticates with, the SRTP profiles and versions it
/// negotiates, its retransmission timer, its clock and threads, and whether a server demands a cookie exchange.
///
/// [#of(DtlsCertificate)] gives the defaults WebRTC needs; the `with` methods change one setting:
///
/// {@snippet lang = java :
/// var config = DtlsConfig.of(DtlsCertificate.generateEcdsa())
///         .withVersions(Set.of(DtlsVersion.DTLS_1_2))
///         .withSrtpProfiles(List.of(SrtpProfile.AES128_CM_HMAC_SHA1_80));
/// }
///
/// @param certificates      the certificates, in preference order; a server picks the first whose key type suits a
///                          cipher suite the client offers, a client the first whose key type the server accepts.
///                          Unmodifiable, not empty
/// @param srtpProfiles      the SRTP profiles to negotiate with `use_srtp`, in preference order; empty negotiates no
///                          SRTP, for a transport that carries only application data
/// @param versions          the versions to negotiate, unmodifiable, not empty
/// @param initialRetransmit the first handshake retransmission timeout, doubled on each retransmission up to 60
///                          seconds; positive
/// @param clock             the clock of the retransmission timers and statistics
/// @param threadFactory     the factory of the one timer thread a transport starts when it must retransmit after its
///                          handshake returned (the final DTLS 1.3 flight, a key update)
/// @param cookieExchange    whether a server demands a cookie (`HelloVerifyRequest` in DTLS 1.2, a
///                          `HelloRetryRequest` cookie in DTLS 1.3) before it commits state, which costs one round trip
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
public record DtlsConfig(List<DtlsCertificate> certificates, List<SrtpProfile> srtpProfiles, Set<DtlsVersion> versions,
                         Duration initialRetransmit, MonotonicClock clock, ThreadFactory threadFactory,
                         boolean cookieExchange) {
    /// The default first retransmission timeout, the 400 ms RFC 9147 recommends for DTLS-SRTP.
    public static final Duration DEFAULT_INITIAL_RETRANSMIT = Duration.ofMillis(400);

    /// Creates a configuration, copying the collections.
    ///
    /// @param certificates      the certificates
    /// @param srtpProfiles      the SRTP profiles
    /// @param versions          the versions
    /// @param initialRetransmit the first retransmission timeout
    /// @param clock             the clock
    /// @param threadFactory     the timer thread factory
    /// @param cookieExchange    whether a server demands a cookie exchange
    /// @throws IllegalArgumentException if `certificates` or `versions` is empty, or `initialRetransmit` is not
    ///                                  positive
    public DtlsConfig {
        certificates = List.copyOf(certificates);
        srtpProfiles = List.copyOf(srtpProfiles);
        versions = Set.copyOf(versions);
        Objects.requireNonNull(initialRetransmit, "initialRetransmit cannot be null");
        Objects.requireNonNull(clock, "clock cannot be null");
        Objects.requireNonNull(threadFactory, "threadFactory cannot be null");
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("certificates cannot be empty");
        }
        if (versions.isEmpty()) {
            throw new IllegalArgumentException("versions cannot be empty");
        }
        if (initialRetransmit.isNegative() || initialRetransmit.isZero()) {
            throw new IllegalArgumentException("initialRetransmit must be positive");
        }
    }

    /// Creates a configuration with virtual timer threads and the cookie exchange on.
    ///
    /// @param certificates      the certificates
    /// @param srtpProfiles      the SRTP profiles
    /// @param versions          the versions
    /// @param initialRetransmit the first retransmission timeout
    /// @param clock             the clock
    public DtlsConfig(List<DtlsCertificate> certificates, List<SrtpProfile> srtpProfiles, Set<DtlsVersion> versions,
                      Duration initialRetransmit, MonotonicClock clock) {
        this(certificates, srtpProfiles, versions, initialRetransmit, clock, defaultThreadFactory(), true);
    }

    /// {@return the WebRTC defaults for one certificate}
    ///
    /// Every SRTP profile in [SrtpProfile] order, DTLS 1.2 and 1.3, a 400 ms first retransmission timeout, the system
    /// clock, virtual timer threads named `parley-dtls-<n>`, and the cookie exchange on.
    ///
    /// @param certificate the certificate
    public static DtlsConfig of(DtlsCertificate certificate) {
        return new DtlsConfig(List.of(certificate), List.of(SrtpProfile.values()), EnumSet.allOf(DtlsVersion.class),
                DEFAULT_INITIAL_RETRANSMIT, MonotonicClock.system(), defaultThreadFactory(), true);
    }

    /// {@return a copy with other certificates}
    ///
    /// @param certificates the certificates
    public DtlsConfig withCertificates(List<DtlsCertificate> certificates) {
        return new DtlsConfig(certificates, srtpProfiles, versions, initialRetransmit, clock, threadFactory, cookieExchange);
    }

    /// {@return a copy with other SRTP profiles}
    ///
    /// @param srtpProfiles the profiles, in preference order
    public DtlsConfig withSrtpProfiles(List<SrtpProfile> srtpProfiles) {
        return new DtlsConfig(certificates, srtpProfiles, versions, initialRetransmit, clock, threadFactory, cookieExchange);
    }

    /// {@return a copy with other versions}
    ///
    /// @param versions the versions
    public DtlsConfig withVersions(Set<DtlsVersion> versions) {
        return new DtlsConfig(certificates, srtpProfiles, versions, initialRetransmit, clock, threadFactory, cookieExchange);
    }

    /// {@return a copy with another first retransmission timeout}
    ///
    /// @param initialRetransmit the timeout, positive; 1.5 times an RTT known from ICE is a good value
    public DtlsConfig withInitialRetransmit(Duration initialRetransmit) {
        return new DtlsConfig(certificates, srtpProfiles, versions, initialRetransmit, clock, threadFactory, cookieExchange);
    }

    /// {@return a copy with another clock}
    ///
    /// @param clock the clock
    public DtlsConfig withClock(MonotonicClock clock) {
        return new DtlsConfig(certificates, srtpProfiles, versions, initialRetransmit, clock, threadFactory, cookieExchange);
    }

    /// {@return a copy with another timer thread factory}
    ///
    /// @param threadFactory the factory
    public DtlsConfig withThreadFactory(ThreadFactory threadFactory) {
        return new DtlsConfig(certificates, srtpProfiles, versions, initialRetransmit, clock, threadFactory, cookieExchange);
    }

    /// {@return a copy that demands, or not, a cookie exchange as a server}
    ///
    /// Turning it off saves a round trip where ICE already proved that the client receives at its address, as RFC 9147
    /// allows.
    ///
    /// @param cookieExchange whether a server demands a cookie exchange
    public DtlsConfig withCookieExchange(boolean cookieExchange) {
        return new DtlsConfig(certificates, srtpProfiles, versions, initialRetransmit, clock, threadFactory, cookieExchange);
    }

    /// {@return the default timer thread factory}
    private static ThreadFactory defaultThreadFactory() {
        return Thread.ofVirtual().name("parley-dtls-", 0).factory();
    }
}
