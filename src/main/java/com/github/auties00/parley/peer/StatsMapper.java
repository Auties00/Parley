package com.github.auties00.parley.peer;

import com.github.auties00.parley.cc.CongestionController;
import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelState;
import com.github.auties00.parley.dtls.DtlsCertificate;
import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.dtls.DtlsState;
import com.github.auties00.parley.dtls.DtlsTransport;
import com.github.auties00.parley.dtls.DtlsVersion;
import com.github.auties00.parley.ice.IceCandidate;
import com.github.auties00.parley.ice.IceCandidatePairState;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.ice.IceTransport;
import com.github.auties00.parley.ice.IceTransportState;
import com.github.auties00.parley.jitter.AudioPlayoutBuffer;
import com.github.auties00.parley.jitter.VideoFrameAssembler;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.session.RtpReceiveStream;
import com.github.auties00.parley.rtp.session.RtpSendStream;
import com.github.auties00.parley.stats.AudioPlayoutStats;
import com.github.auties00.parley.stats.CertificateStats;
import com.github.auties00.parley.stats.CodecStats;
import com.github.auties00.parley.stats.DataChannelStats;
import com.github.auties00.parley.stats.IceCandidatePairStats;
import com.github.auties00.parley.stats.IceCandidateStats;
import com.github.auties00.parley.stats.InboundRtpStreamStats;
import com.github.auties00.parley.stats.MediaSourceStats;
import com.github.auties00.parley.stats.OutboundRtpStreamStats;
import com.github.auties00.parley.stats.RemoteInboundRtpStreamStats;
import com.github.auties00.parley.stats.RemoteOutboundRtpStreamStats;
import com.github.auties00.parley.stats.RtcStats;
import com.github.auties00.parley.stats.TransportStats;
import com.github.auties00.parley.transport.SrtpTransport;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// Maps the statistics records of the lower layers to the W3C statistics objects.
///
/// Ids are stable across reports: `T<transport>` for a transport, `CP<transport>-<local>-<remote>` for a pair,
/// `I<foundation><address><port>` for a candidate, `CO<transport>_<pt>` for a codec, `OT<ssrc>`, `IT<mid>_<rid>`,
/// `RI<ssrc>`, `RO<mid>_<rid>` for the RTP streams, `MS<track>` for a media source, `AP<mid>` for an audio playout,
/// `D<label>` for a data channel and `CF<fingerprint>` for a certificate.
///
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
final class StatsMapper {
    /// What the mapper reads from one transport.
    ///
    /// @param id         the transport id
    /// @param ice        the ICE agent
    /// @param dtls       the DTLS transport
    /// @param srtp       the SRTP transport
    /// @param congestion the congestion controller, when media is negotiated
    record TransportView(String id, IceTransport ice, DtlsTransport dtls, SrtpTransport srtp,
                         Optional<CongestionController> congestion) {
    }

    /// What the mapper reads from one send stream.
    ///
    /// @param mid           the section
    /// @param transportId   the transport
    /// @param kind          the media kind
    /// @param payloadType   the payload type sent
    /// @param stream        the stream
    /// @param track         the track feeding it
    /// @param encodingIndex the index of its encoding
    record SendView(String mid, String transportId, MediaKind kind, int payloadType, RtpSendStream stream,
                    Optional<LocalTrack> track, int encodingIndex) {
    }

    /// What the mapper reads from one receive stream.
    ///
    /// @param mid         the section
    /// @param transportId the transport
    /// @param kind        the media kind
    /// @param payloadType the first negotiated payload type
    /// @param stream      the stream
    /// @param track       the track it feeds
    /// @param playout     the audio playout buffer, if any
    /// @param assembler   the video frame assembler, if any
    record ReceiveView(String mid, String transportId, MediaKind kind, int payloadType, RtpReceiveStream stream,
                       RemoteTrack track, Optional<AudioPlayoutBuffer> playout,
                       Optional<VideoFrameAssembler> assembler) {
    }

    private StatsMapper() {
    }

    /// {@return the statistics objects of the transports, streams, codecs, channels and certificates}
    static List<RtcStats> map(Instant now, List<TransportView> transports, List<SendView> sends,
                              List<ReceiveView> receives, Optional<Negotiated> negotiated, List<DataChannel> channels,
                              List<DtlsCertificate> certificates) {
        var nowNanos = System.nanoTime();
        var result = new ArrayList<RtcStats>();
        Optional<String> localCertificate = Optional.empty();
        for (var certificate : certificates) {
            try {
                var stats = certificateStats(now, certificate.certificate().getEncoded());
                result.add(stats);
                if (localCertificate.isEmpty()) {
                    localCertificate = Optional.of(stats.id());
                }
            } catch (CertificateEncodingException exception) {
                // a certificate that cannot be encoded has no fingerprint to report
            }
        }
        for (var view : transports) {
            result.addAll(transport(now, nowNanos, view, localCertificate));
        }
        negotiated.ifPresent(outcome -> result.addAll(codecs(now, outcome)));
        var sources = new HashSet<String>();
        for (var view : sends) {
            result.addAll(outbound(now, view, sources));
        }
        for (var view : receives) {
            result.addAll(inbound(now, nowNanos, view));
        }
        for (var channel : channels) {
            var statistics = channel.statistics();
            result.add(new DataChannelStats("D" + channel.label() + "_" + channel.id().orElse(-1), now,
                    statistics.label(), statistics.protocol(), statistics.id(), channelState(statistics.state()),
                    statistics.messagesSent(), statistics.bytesSent(), statistics.messagesReceived(),
                    statistics.bytesReceived()));
        }
        return result;
    }

    /// {@return the statistics of one transport: the transport, its pairs and its candidates}
    private static List<RtcStats> transport(Instant now, long nowNanos, TransportView view,
                                            Optional<String> localCertificate) {
        var result = new ArrayList<RtcStats>();
        var transportId = "T" + view.id();
        var ice = view.ice().statistics();
        var candidates = new HashSet<String>();
        for (var candidate : ice.localCandidates()) {
            if (candidates.add(candidateId(candidate))) {
                result.add(candidate(now, transportId, candidate, false));
            }
        }
        for (var candidate : ice.remoteCandidates()) {
            if (candidates.add(candidateId(candidate))) {
                result.add(candidate(now, transportId, candidate, true));
            }
        }
        String selectedPair = null;
        for (var pair : ice.pairs()) {
            var localId = candidateId(pair.pair().local());
            var remoteId = candidateId(pair.pair().remote());
            for (var candidate : List.of(pair.pair().local(), pair.pair().remote())) {
                if (candidates.add(candidateId(candidate))) {
                    result.add(candidate(now, transportId, candidate, candidate == pair.pair().remote()));
                }
            }
            var pairId = "CP" + view.id() + "-" + localId + "-" + remoteId;
            if (pair.selected()) {
                selectedPair = pairId;
            }
            var outgoing = pair.selected() ? view.congestion().map(controller -> OptionalDouble.of(
                    controller.currentTarget().bitsPerSecond())).orElse(OptionalDouble.empty()) : OptionalDouble.empty();
            result.add(new IceCandidatePairStats(pairId, now, transportId, localId, remoteId, pairState(pair.state()),
                    pair.nominated(), pair.packetsSent(), pair.packetsReceived(), pair.bytesSent(),
                    pair.bytesReceived(), instant(now, nowNanos, pair.lastPacketSentNanos()),
                    instant(now, nowNanos, pair.lastPacketReceivedNanos()), seconds(pair.totalRoundTripTime()),
                    pair.currentRoundTripTime().map(rtt -> OptionalDouble.of(seconds(rtt)))
                            .orElse(OptionalDouble.empty()),
                    outgoing, pair.requestsSent(), pair.requestsReceived(), pair.responsesSent(),
                    pair.responsesReceived(), pair.consentRequestsSent()));
        }
        var dtls = view.dtls().statistics();
        var remoteCertificate = view.dtls().remoteCertificate().flatMap(certificate -> {
            try {
                var stats = certificateStats(now, certificate.getEncoded());
                result.add(stats);
                return Optional.of(stats.id());
            } catch (CertificateEncodingException exception) {
                return Optional.empty();
            }
        });
        result.add(new TransportStats(transportId, now, ice.packetsSent(), ice.packetsReceived(), ice.bytesSent(),
                ice.bytesReceived(), ice.role() == IceRole.CONTROLLING ? TransportStats.IceRole.CONTROLLING
                : TransportStats.IceRole.CONTROLLED,
                Optional.of(view.ice().localParameters().usernameFragment()), iceState(ice.state()),
                dtlsState(dtls.state()), Optional.ofNullable(selectedPair), ice.selectedCandidatePairChanges(),
                localCertificate, remoteCertificate,
                dtls.version().map(version -> version == DtlsVersion.DTLS_1_3 ? "FEFC" : "FEFD"),
                dtls.cipherSuite(),
                dtls.role().map(role -> role == DtlsRole.CLIENT ? TransportStats.DtlsRole.CLIENT
                        : TransportStats.DtlsRole.SERVER),
                dtls.srtpProfile().map(profile -> profile.name())));
        return result;
    }

    /// {@return the codec statistics of every negotiated codec}
    private static List<RtcStats> codecs(Instant now, Negotiated negotiated) {
        var result = new ArrayList<RtcStats>();
        var seen = new HashSet<String>();
        for (var media : negotiated.media()) {
            for (var entry : media.codecs()) {
                var id = codecId(media.transportId(), entry.payloadType());
                if (!seen.add(id)) {
                    continue;
                }
                var codec = entry.codec();
                result.add(new CodecStats(id, now, entry.payloadType(), "T" + media.transportId(), codec.mimeType(),
                        OptionalLong.of(codec.clockRate()), codec.channels(), CodecCatalog.fmtpLine(codec)));
            }
        }
        return result;
    }

    /// {@return the outbound, remote inbound and media source statistics of one send stream}
    private static List<RtcStats> outbound(Instant now, SendView view, java.util.Set<String> sources) {
        var result = new ArrayList<RtcStats>();
        var statistics = view.stream().statistics();
        var ssrc = statistics.ssrc();
        var outboundId = "OT" + ssrc;
        var transportId = "T" + view.transportId();
        var kind = view.kind() == MediaKind.AUDIO ? "audio" : "video";
        var codecId = Optional.of(codecId(view.transportId(), view.payloadType()));
        var remote = statistics.remote();
        var remoteId = remote.map(ignored -> "RI" + ssrc);
        var sourceId = view.track().map(track -> "MS" + track.id());
        var frames = view.track().map(LocalTrack::framesWritten).orElse(0L);
        var keyFrames = view.track().map(LocalTrack::keyFramesWritten).orElse(0L);
        var target = view.track().flatMap(track -> statistics.rid().isPresent()
                ? boxed(track.targetBitrate(statistics.rid().get())) : boxed(track.targetBitrate()));
        result.add(new OutboundRtpStreamStats(outboundId, now, ssrc, kind, transportId, codecId,
                Optional.of(view.mid()), sourceId, remoteId, statistics.rid(), view.encodingIndex(),
                statistics.packetsSent(), statistics.bytesSent(), statistics.headerBytesSent(),
                statistics.retransmittedPacketsSent(), statistics.retransmittedBytesSent(), statistics.rtxSsrc(),
                target.map(OptionalLong::of).orElse(OptionalLong.empty()), 0, frames, keyFrames, frames,
                OptionalInt.empty(), OptionalInt.empty(), OptionalDouble.empty(), statistics.nackCount(),
                statistics.firCount(), statistics.pliCount(), true, Optional.empty()));
        remote.ifPresent(reception -> result.add(new RemoteInboundRtpStreamStats("RI" + ssrc, now, ssrc, kind,
                transportId, codecId, outboundId, reception.packetsLost(), seconds(reception.jitter()),
                reception.fractionLost() / 256.0,
                reception.roundTripTime().map(rtt -> OptionalDouble.of(seconds(rtt))).orElse(OptionalDouble.empty()),
                seconds(reception.totalRoundTripTime()), reception.roundTripTimeMeasurements())));
        view.track().ifPresent(track -> {
            if (sources.add(track.id())) {
                result.add(new MediaSourceStats("MS" + track.id(), now, track.id(), kind, OptionalDouble.empty(),
                        OptionalInt.empty(), OptionalInt.empty(), track.framesWritten(), OptionalDouble.empty()));
            }
        });
        return result;
    }

    /// {@return the inbound, remote outbound and playout statistics of one receive stream}
    private static List<RtcStats> inbound(Instant now, long nowNanos, ReceiveView view) {
        var result = new ArrayList<RtcStats>();
        var statistics = view.stream().statistics();
        var key = view.mid() + "_" + statistics.rid().orElse("");
        var inboundId = "IT" + key;
        var transportId = "T" + view.transportId();
        var kind = view.kind() == MediaKind.AUDIO ? "audio" : "video";
        var codecId = Optional.of(codecId(view.transportId(), view.payloadType()));
        var remoteId = statistics.remoteSender().map(ignored -> "RO" + key);
        var playout = view.playout().map(AudioPlayoutBuffer::statistics);
        var assembler = view.assembler().map(VideoFrameAssembler::statistics);
        var jitterBufferDelay = playout.map(value -> seconds(value.jitterBufferDelay()))
                .or(() -> assembler.map(value -> seconds(value.jitterBufferDelay()))).orElse(0.0);
        var emitted = playout.map(value -> value.jitterBufferEmittedCount())
                .or(() -> assembler.map(value -> value.jitterBufferEmittedCount())).orElse(0L);
        result.add(new InboundRtpStreamStats(inboundId, now, statistics.ssrc().orElse(0), kind, transportId, codecId,
                Optional.of(view.track().id()), Optional.of(view.mid()), remoteId, statistics.packetsReceived(),
                statistics.packetsLost(), seconds(statistics.jitter()), statistics.bytesReceived(),
                statistics.headerBytesReceived(), statistics.packetsDiscarded()
                + playout.map(value -> value.packetsDiscarded()).orElse(0L),
                statistics.fecPacketsReceived(), Math.max(0, statistics.fecPacketsReceived()
                - statistics.packetsRecovered()), 0, statistics.retransmittedPacketsReceived(),
                statistics.retransmittedBytesReceived(), statistics.rtxSsrc(), OptionalLong.empty(),
                statistics.nackCount(), statistics.firCount(), statistics.pliCount(),
                assembler.map(value -> value.framesReceived()).orElse(0L),
                assembler.map(value -> value.keyframesReleased()).orElse(0L),
                assembler.map(value -> value.framesDropped()).orElse(0L), OptionalInt.empty(), OptionalInt.empty(),
                OptionalDouble.empty(), instant(now, nowNanos, statistics.lastPacketReceivedNanos()), Optional.empty(),
                jitterBufferDelay, playout.map(value -> seconds(value.jitterBufferTargetDelay())).orElse(0.0),
                playout.map(value -> seconds(value.jitterBufferMinimumDelay())).orElse(0.0), emitted));
        statistics.remoteSender().ifPresent(sender -> result.add(new RemoteOutboundRtpStreamStats("RO" + key, now,
                statistics.ssrc().orElse(0), kind, transportId, codecId, inboundId, sender.packetsSent(),
                sender.bytesSent(), sender.remoteTimestamp(), sender.reportsReceived(),
                statistics.roundTripTime().map(rtt -> OptionalDouble.of(seconds(rtt))).orElse(OptionalDouble.empty()),
                statistics.roundTripTime().map(StatsMapper::seconds).orElse(0.0),
                statistics.roundTripTime().isPresent() ? 1 : 0)));
        playout.ifPresent(value -> result.add(new AudioPlayoutStats("AP" + view.mid(), now, "audio",
                value.concealedSamples() / 48_000.0, value.concealmentEvents(),
                value.totalSamplesReceived() / 48_000.0, seconds(value.jitterBufferDelay()),
                value.jitterBufferEmittedCount())));
        return result;
    }

    /// {@return an optional long boxed into an optional, for chaining}
    private static Optional<Long> boxed(OptionalLong value) {
        return value.isPresent() ? Optional.of(value.getAsLong()) : Optional.empty();
    }

    /// {@return the id of a codec on a transport}
    private static String codecId(String transportId, int payloadType) {
        return "CO" + transportId + "_" + payloadType;
    }

    /// {@return the wall-clock time of a monotonic instant, or an empty optional}
    private static Optional<Instant> instant(Instant now, long nowNanos, OptionalLong nanos) {
        return nanos.isPresent() ? Optional.of(now.minusNanos(nowNanos - nanos.getAsLong())) : Optional.empty();
    }

    /// {@return the statistics of a candidate}
    private static IceCandidateStats candidate(Instant now, String transportId, IceCandidate candidate,
                                               boolean remote) {
        return new IceCandidateStats(candidateId(candidate), now, remote, transportId,
                Optional.of(candidate.address()), candidate.port(),
                candidate.protocol().name().toLowerCase(Locale.ROOT), candidateType(candidate),
                candidate.priority(), Optional.empty(), Optional.empty(), candidate.foundation(),
                candidate.relatedAddress().map(address -> address.getHostString()),
                candidate.relatedAddress().map(address -> OptionalInt.of(address.getPort()))
                        .orElse(OptionalInt.empty()),
                candidate.usernameFragment(),
                candidate.tcpType().map(type -> type.name().toLowerCase(Locale.ROOT)));
    }

    /// {@return the stable id of a candidate}
    private static String candidateId(IceCandidate candidate) {
        return "I" + candidate.foundation() + candidate.address().replace(':', '.') + "_" + candidate.port();
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

    /// {@return the W3C pair state of an ICE pair state}
    private static IceCandidatePairStats.State pairState(IceCandidatePairState state) {
        return switch (state) {
            case FROZEN -> IceCandidatePairStats.State.FROZEN;
            case WAITING -> IceCandidatePairStats.State.WAITING;
            case IN_PROGRESS -> IceCandidatePairStats.State.IN_PROGRESS;
            case SUCCEEDED -> IceCandidatePairStats.State.SUCCEEDED;
            default -> IceCandidatePairStats.State.FAILED;
        };
    }

    /// {@return the W3C candidate type of an ICE candidate}
    private static IceCandidateStats.CandidateType candidateType(IceCandidate candidate) {
        return switch (candidate.type()) {
            case HOST -> IceCandidateStats.CandidateType.HOST;
            case SERVER_REFLEXIVE -> IceCandidateStats.CandidateType.SRFLX;
            case PEER_REFLEXIVE -> IceCandidateStats.CandidateType.PRFLX;
            case RELAY -> IceCandidateStats.CandidateType.RELAY;
        };
    }

    /// {@return the W3C ICE state of an ICE transport state}
    private static TransportStats.IceState iceState(IceTransportState state) {
        return TransportStats.IceState.valueOf(state.name());
    }

    /// {@return the W3C DTLS state of a DTLS state}
    private static TransportStats.DtlsState dtlsState(DtlsState state) {
        return TransportStats.DtlsState.valueOf(state.name());
    }

    /// {@return the W3C state of a data channel state}
    private static DataChannelStats.State channelState(DataChannelState state) {
        return DataChannelStats.State.valueOf(state.name());
    }

    /// {@return a duration in seconds}
    private static double seconds(Duration duration) {
        return duration.toNanos() / 1e9;
    }
}
