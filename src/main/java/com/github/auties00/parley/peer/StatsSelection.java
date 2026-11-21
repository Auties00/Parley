package com.github.auties00.parley.peer;

import com.github.auties00.parley.stats.CertificateStats;
import com.github.auties00.parley.stats.CodecStats;
import com.github.auties00.parley.stats.IceCandidatePairStats;
import com.github.auties00.parley.stats.InboundRtpStreamStats;
import com.github.auties00.parley.stats.MediaSourceStats;
import com.github.auties00.parley.stats.OutboundRtpStreamStats;
import com.github.auties00.parley.stats.RemoteInboundRtpStreamStats;
import com.github.auties00.parley.stats.RemoteOutboundRtpStreamStats;
import com.github.auties00.parley.stats.RtcStats;
import com.github.auties00.parley.stats.StatsReport;
import com.github.auties00.parley.stats.TransportStats;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

/// The W3C stats selection algorithm: the RTP stream statistics of one sender or receiver and every object they
/// reference, transitively.
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
final class StatsSelection {
    private StatsSelection() {
    }

    /// {@return the objects of `report` reachable from the outbound (`sending`) or inbound RTP streams of `ssrcs`}
    static StatsReport select(StatsReport report, List<Long> ssrcs, boolean sending) {
        var selected = new LinkedHashSet<String>();
        var queue = new ArrayDeque<String>();
        for (var object : report) {
            var root = switch (object) {
                case OutboundRtpStreamStats outbound -> sending && ssrcs.contains(outbound.ssrc());
                case InboundRtpStreamStats inbound -> !sending && ssrcs.contains(inbound.ssrc());
                default -> false;
            };
            if (root) {
                queue.add(object.id());
            }
        }
        while (!queue.isEmpty()) {
            var id = queue.removeFirst();
            if (!selected.add(id)) {
                continue;
            }
            report.get(id).ifPresent(object -> queue.addAll(references(object)));
        }
        var result = new ArrayList<RtcStats>();
        for (var id : selected) {
            report.get(id).ifPresent(result::add);
        }
        return StatsReport.of(result);
    }

    /// {@return the ids an object references}
    private static List<String> references(RtcStats object) {
        var result = new ArrayList<String>();
        switch (object) {
            case OutboundRtpStreamStats outbound -> {
                result.add(outbound.transportId());
                outbound.codecId().ifPresent(result::add);
                outbound.remoteId().ifPresent(result::add);
                outbound.mediaSourceId().ifPresent(result::add);
            }
            case InboundRtpStreamStats inbound -> {
                result.add(inbound.transportId());
                inbound.codecId().ifPresent(result::add);
                inbound.remoteId().ifPresent(result::add);
            }
            case RemoteInboundRtpStreamStats remote -> {
                result.add(remote.transportId());
                remote.codecId().ifPresent(result::add);
            }
            case RemoteOutboundRtpStreamStats remote -> {
                result.add(remote.transportId());
                remote.codecId().ifPresent(result::add);
            }
            case CodecStats codec -> result.add(codec.transportId());
            case TransportStats transport -> {
                transport.selectedCandidatePairId().ifPresent(result::add);
                transport.localCertificateId().ifPresent(result::add);
                transport.remoteCertificateId().ifPresent(result::add);
            }
            case IceCandidatePairStats pair -> {
                result.add(pair.localCandidateId());
                result.add(pair.remoteCandidateId());
            }
            case CertificateStats certificate -> certificate.issuerCertificateId().ifPresent(result::add);
            case MediaSourceStats ignored -> {
            }
            default -> {
            }
        }
        return result;
    }

    /// {@return an optional of `value` when it is not blank}
    static Optional<String> nonBlank(String value) {
        return value == null || value.isBlank() ? Optional.empty() : Optional.of(value);
    }
}
