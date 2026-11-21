package com.github.auties00.parley.peer;

import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelState;
import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.dtls.DtlsVersion;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.ice.IceTransport;
import com.github.auties00.parley.rtp.session.RtpReceiveStream;
import com.github.auties00.parley.rtp.session.RtpSendStream;
import com.github.auties00.parley.stats.CertificateStats;
import com.github.auties00.parley.stats.DataChannelStats;
import com.github.auties00.parley.stats.IceCandidatePairStats;
import com.github.auties00.parley.stats.IceCandidateStats;
import com.github.auties00.parley.stats.InboundRtpStreamStats;
import com.github.auties00.parley.stats.OutboundRtpStreamStats;
import com.github.auties00.parley.stats.RemoteInboundRtpStreamStats;
import com.github.auties00.parley.stats.RtcStats;
import com.github.auties00.parley.stats.TransportStats;
import com.github.auties00.parley.transport.SrtpTransport;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// Maps the statistics records of the lower layers to the W3C statistics objects.
///
/// Ids are stable across reports: `T<transport>` for a transport, `CP<transport>-<local>-<remote>` for a pair,
/// `I<foundation><address><port>` for a candidate, `OT<ssrc>`, `IT<ssrc>`, `RI<ssrc>` for the RTP streams and
/// `CF<fingerprint>` for a certificate.
///
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
final class StatsMapper {
    /// What the mapper reads from one transport.
    record TransportView(String id, IceTransport ice, Optional<DtlsTransport> dtls, Optional<SrtpTransport> srtp,
                         Map<Long, RtpSendStream> sendStreams, Map<String, RtpReceiveStream> receiveStreams) {
    }

    private StatsMapper() {
    }

    /// {@return the statistics objects of the transports, streams, channels and certificates}
    static List<RtcStats> map(Instant now, List<TransportView> transports, List<DataChannel> channels,
                              List<DtlsCertificate> certificates) {
        var result = new ArrayList<RtcStats>();
        var localCertificate = Optional.<String>empty();
        for (var certificate : certificates) {
            var stats = certificate(now, certificate);
            stats.ifPresent(result::add);
            if (localCertificate.isEmpty()) {
                localCertificate = stats.map(RtcStats::id);
            }
        }
        for (var view : transports) {
            result.addAll(transport(now, view, localCertificate));
        }
        for (var channel : channels) {
            var statistics = channel.statistics();
            result.add(new DataChannelStats("D" + channel.id().orElse(-1) + channel.label().hashCode(), now,
                    channel.label(), channel.protocol(), channel.id(), channelState(channel.readyState()),
                    statistics.messagesSent(), statistics.bytesSent(), statistics.messagesReceived(),
                    statistics.bytesReceived()));
        }
        return result;
    }

    /// {@return the statistics of one transport: the transport, its pairs and candidates, its streams}
    private static List<RtcStats> transport(Instant now, TransportView view, Optional<String> localCertificate) {
        var result = new ArrayList<RtcStats>();
        var transportId = "T" + view.id();
        var ice = view.ice();
        var iceStatistics = ice.statistics();
        String selectedPair = null;
        var packetsSent = 0L;
        var packetsReceived = 0L;
        var bytesSent = 0L;
        var bytesReceived = 0L;
        var selected = ice.selectedPair();
        for (var pair : iceStatistics.pairs()) {
            var localId = candidateId(pair.pair().local());
            var remoteId = candidateId(pair.pair().remote());
            result.add(candidate(now, transportId, pair.pair().local(), false));
            result.add(candidate(now, transportId, pair.pair().remote(), true));
            var pairId = "CP" + view.id() + "-" + localId + "-" + remoteId;
            if (selected.isPresent() && selected.get().equals(pair.pair())) {
                selectedPair = pairId;
                packetsSent = pair.packetsSent();
                packetsReceived = pair.packetsReceived();
                bytesSent = pair.bytesSent();
                bytesReceived = pair.bytesReceived();
            }
            result.add(new IceCandidatePairStats(pairId, now, transportId, localId, remoteId,
                    pairState(pair.state()), pair.nominated(), pair.packetsSent(), pair.packetsReceived(),
                    pair.bytesSent(), pair.bytesReceived(), Optional.empty(), Optional.empty(),
                    seconds(pair.totalRoundTripTime().toNanos()),
                    pair.currentRoundTripTime().map(rtt -> OptionalDouble.of(seconds(rtt.toNanos())))
                            .orElse(OptionalDouble.empty()),
                    OptionalDouble.empty(), pair.requestsSent(), pair.requestsReceived(), pair.responsesSent(),
                    pair.responsesReceived(), pair.consentRequestsSent()));
        }
        var dtls = view.dtls();
        var dtlsStatistics = dtls.map(DtlsTransport::statistics);
        var remoteCertificate = dtls.flatMap(DtlsTransport::remoteCertificate).flatMap(certificate -> {
            try {
                var stats = certificateStats(now, certificate.getEncoded());
                result.add(stats);
                return Optional.of(stats.id());
            } catch (CertificateEncodingException exception) {
                return Optional.empty();
            }
        });
        result.add(new TransportStats(transportId, now, packetsSent, packetsReceived, bytesSent, bytesReceived,
                ice.role() == IceRole.CONTROLLING ? TransportStats.IceRole.CONTROLLING
                        : TransportStats.IceRole.CONTROLLED,
                Optional.of(ice.localParameters().usernameFragment()), iceState(ice.state()),
                dtls.map(value -> dtlsState(value.state())).orElse(TransportStats.DtlsState.NEW),
                Optional.ofNullable(selectedPair), iceStatistics.selectedPairChanges(), localCertificate,
                remoteCertificate,
                dtlsStatistics.flatMap(statistics -> statistics.version())
                        .map(version -> version == DtlsVersion.DTLS_1_3 ? "FEFC" : "FEFD"),
                dtlsStatistics.flatMap(statistics -> statistics.cipherSuite()),
                dtlsStatistics.flatMap(statistics -> statistics.role())
                        .map(role -> role == DtlsRole.CLIENT ? TransportStats.DtlsRole.CLIENT
                                : TransportStats.DtlsRole.SERVER),
                dtlsStatistics.flatMap(statistics -> statistics.srtpProfile()).map(Enum::name)));
        for (var entry : view.sendStreams().entrySet()) {
            var ssrc = entry.getKey();
            var statistics = entry.getValue().statistics();
            var outboundId = "OT" + ssrc;
            var remoteReport = statistics.remoteReports().stream().filter(report -> report.ssrc() == ssrc)
                    .findFirst();
            var remoteId = remoteReport.map(report -> "RI" + ssrc);
            result.add(new OutboundRtpStreamStats(outboundId, now, ssrc, "video", transportId, Optional.empty(),
                    Optional.empty(), Optional.empty(), remoteId, Optional.empty(), 0, statistics.packetsSent(),
                    statistics.bytesSent(), statistics.headerBytesSent(), statistics.retransmittedPacketsSent(),
                    statistics.retransmittedBytesSent(), OptionalLong.empty(), OptionalLong.empty(), 0,
                    statistics.framesSent(), 0, statistics.framesSent(), OptionalInt.empty(), OptionalInt.empty(),
                    OptionalDouble.empty(), statistics.nackCount(), statistics.firCount(), statistics.pliCount(), true,
                    Optional.empty()));
            remoteReport.ifPresent(report -> result.add(new RemoteInboundRtpStreamStats("RI" + ssrc, now, ssrc,
                    "video", transportId, Optional.empty(), outboundId, report.cumulativeLost(),
                    report.jitter() / 90_000.0, report.fractionLost() / 256.0,
                    statistics.roundTripTime().map(rtt -> OptionalDouble.of(seconds(rtt.toNanos())))
                            .orElse(OptionalDouble.empty()),
                    statistics.roundTripTime().map(rtt -> seconds(rtt.toNanos())).orElse(0.0),
                    statistics.roundTripTime().isPresent() ? 1 : 0)));
        }
        for (var entry : view.receiveStreams().entrySet()) {
            var statistics = entry.getValue().statistics();
            var key = entry.getKey();
            var mid = key.substring(0, key.indexOf('/'));
            result.add(new InboundRtpStreamStats("IT" + key, now, 0, "video", transportId, Optional.empty(),
                    Optional.empty(), Optional.of(mid), Optional.empty(), statistics.packetsReceived(),
                    statistics.packetsLost(), statistics.jitterRtpUnits() / 90_000.0, statistics.bytesReceived(),
                    statistics.headerBytesReceived(), 0, statistics.fecPacketsReceived(), 0, 0,
                    statistics.retransmittedPacketsReceived(), statistics.retransmittedBytesReceived(),
                    OptionalLong.empty(), OptionalLong.empty(), statistics.nackCount(), statistics.firCount(),
                    statistics.pliCount(), 0, 0, 0, OptionalInt.empty(), OptionalInt.empty(), OptionalDouble.empty(),
                    Optional.empty(), Optional.empty(), 0, 0, 0, 0));
        }
        return result;
    }

    /// {@return the statistics of a candidate}
    private static IceCandidateStats candidate(Instant now, String transportId, IceCandidate candidate,
                                               boolean remote) {
        return new IceCandidateStats(candidateId(candidate), now, remote, transportId,
                Optional.of(candidate.address()), candidate.port(),
                candidate.protocol().name().toLowerCase(Locale.ROOT), candidateType(candidate.type()),
                candidate.priority(), Optional.empty(), Optional.empty(), candidate.foundation(),
                candidate.relatedAddress().map(address -> address.getHostString()),
                candidate.relatedAddress().map(address -> OptionalInt.of(address.getPort()))
                        .orElse(OptionalInt.empty()),
                candidate.usernameFragment(),
                candidate.tcpType().map(type -> type.name().toLowerCase(Locale.ROOT)));
    }

    /// {@return the stable id of a candidate}
    private static String candidateId(IceCandidate candidate) {
        return "I" + candidate.foundation() + candidate.address() + candidate.port();
    }

    /// {@return the statistics of a local certificate, or an empty optional when it cannot be encoded}
    private static Optional<CertificateStats> certificate(Instant now, DtlsCertificate certificate) {
        try {
            return Optional.of(certificateStats(now, certificate.certificate().getEncoded()));
        } catch (CertificateEncodingException exception) {
            return Optional.empty();
        }
    }

    /// {@return the statistics of a DER-encoded certificate}
    private static CertificateStats certificateStats(Instant now, byte[] encoded) {
        try {
            var digest = MessageDigest.getInstance("SHA-256").digest(encoded);
            var fingerprint = HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
            return new CertificateStats("CF" + fingerprint, now, fingerprint, "sha-256",
                    Base64.getEncoder().encodeToString(encoded), Optional.empty());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    /// {@return the W3C pair state of an ICE pair state name}
    private static IceCandidatePairStats.State pairState(String state) {
        return switch (state.toLowerCase(Locale.ROOT).replace('_', '-')) {
            case "frozen" -> IceCandidatePairStats.State.FROZEN;
            case "waiting" -> IceCandidatePairStats.State.WAITING;
            case "in-progress" -> IceCandidatePairStats.State.IN_PROGRESS;
            case "failed" -> IceCandidatePairStats.State.FAILED;
            default -> IceCandidatePairStats.State.SUCCEEDED;
        };
    }

    /// {@return the W3C candidate type of an ICE candidate type}
    private static IceCandidateStats.CandidateType candidateType(IceCandidate.Type type) {
        return switch (type) {
            case HOST -> IceCandidateStats.CandidateType.HOST;
            case SRFLX -> IceCandidateStats.CandidateType.SRFLX;
            case PRFLX -> IceCandidateStats.CandidateType.PRFLX;
            case RELAY -> IceCandidateStats.CandidateType.RELAY;
        };
    }

    /// {@return the W3C ICE state of an ICE transport state}
    private static TransportStats.IceState iceState(com.github.auties00.parley.ice.IceTransportState state) {
        return TransportStats.IceState.valueOf(state.name());
    }

    /// {@return the W3C DTLS state of a DTLS state}
    private static TransportStats.DtlsState dtlsState(com.github.auties00.parley.dtls.DtlsState state) {
        return TransportStats.DtlsState.valueOf(state.name());
    }

    /// {@return the W3C state of a data channel state}
    private static DataChannelStats.State channelState(DataChannelState state) {
        return DataChannelStats.State.valueOf(state.name());
    }

    /// {@return nanoseconds as seconds}
    private static double seconds(long nanos) {
        return nanos / 1e9;
    }
}
