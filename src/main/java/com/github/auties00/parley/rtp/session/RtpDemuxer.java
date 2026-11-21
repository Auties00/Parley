package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import com.github.auties00.parley.rtp.extension.Mid;
import com.github.auties00.parley.rtp.extension.RepairedRtpStreamId;
import com.github.auties00.parley.rtp.extension.RtpStreamId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;

/// Routes the RTP packets of a BUNDLE group to the stream each belongs to, as RFC 8843 section 9.2 and RFC 9429
/// section 5.2 prescribe.
///
/// For each packet, in order:
///
/// 1. A packet with a MID header extension goes to the route of that MID; when the MID has several routes
///    (simulcast), the RID or repaired RID header extension picks one, else the SSRC's earlier binding. The SSRC is
///    then bound to the route, replacing any earlier binding.
/// 2. Otherwise a packet whose SSRC is bound, or signaled by a route, goes to that route.
/// 3. Otherwise a packet whose payload type belongs to exactly one route goes there, and its SSRC is bound.
/// 4. Otherwise the packet is unmatched, reported with what it carried ([UnsignaledStream]).
///
/// A packet whose MID names no route is unmatched even when its SSRC is bound: the MID is authoritative. Learned
/// bindings are bounded ([#MAX_BINDINGS]), oldest first out.
///
/// The demuxer is generic so an SFU can route to its own targets. It is not thread-safe; the session confines it to
/// the transport's reader thread.
///
/// @param <T> the routing target
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.rfc-editor.org/rfc/rfc8852.html RFC 8852: RTP Stream Identifier Source Description (SDES)
public final class RtpDemuxer<T> {
    /// The most SSRC bindings learned from packets.
    public static final int MAX_BINDINGS = 4096;

    private final OptionalInt midId;
    private final OptionalInt ridId;
    private final OptionalInt repairedRidId;
    private final List<Route<T>> routes;
    private final Map<Long, Route<T>> bindings = new LinkedHashMap<>(16, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, Route<T>> eldest) {
            return size() > MAX_BINDINGS;
        }
    };

    /// One destination and the identifiers that lead to it.
    ///
    /// @param target       the destination
    /// @param mid          the MID of its m-section, if any
    /// @param rid          the RID of its encoding, if any; matched against both the RID and the repaired RID
    ///                     header extensions
    /// @param ssrcs        the SSRCs signaled for it (media, RTX, FEC)
    /// @param payloadTypes the payload types of its m-section (media, RTX, RED, FEC)
    /// @param <T>          the routing target
    public record Route<T>(T target, Optional<String> mid, Optional<String> rid, Set<Long> ssrcs,
                           Set<Integer> payloadTypes) {
        /// Checks the fields and copies the sets.
        public Route {
            Objects.requireNonNull(target, "target cannot be null");
            Objects.requireNonNull(mid, "mid cannot be null");
            Objects.requireNonNull(rid, "rid cannot be null");
            ssrcs = Set.copyOf(ssrcs);
            payloadTypes = Set.copyOf(payloadTypes);
        }
    }

    /// The outcome of routing one packet.
    ///
    /// @param <T> the routing target
    public sealed interface Result<T> {
        /// The packet belongs to a route.
        ///
        /// @param target the route's target
        /// @param <T>    the routing target
        record Matched<T>(T target) implements Result<T> {
        }

        /// No route claims the packet.
        ///
        /// @param stream what the packet carried
        /// @param <T>    the routing target
        record Unmatched<T>(UnsignaledStream stream) implements Result<T> {
        }
    }

    private RtpDemuxer(HeaderExtensionMap extensions, List<Route<T>> routes) {
        this.midId = extensions.idOf(HeaderExtensionUris.MID);
        this.ridId = extensions.idOf(HeaderExtensionUris.RTP_STREAM_ID);
        this.repairedRidId = extensions.idOf(HeaderExtensionUris.REPAIRED_RTP_STREAM_ID);
        this.routes = List.copyOf(routes);
    }

    /// Creates a demuxer.
    ///
    /// @param extensions the header extension ids of the BUNDLE group, which locate the MID, RID and repaired RID
    /// @param routes     the routes
    /// @param <T>        the routing target
    /// @return the demuxer, with no learned binding
    public static <T> RtpDemuxer<T> create(HeaderExtensionMap extensions, List<Route<T>> routes) {
        Objects.requireNonNull(extensions, "extensions cannot be null");
        Objects.requireNonNull(routes, "routes cannot be null");
        return new RtpDemuxer<>(extensions, routes);
    }

    /// {@return a demuxer with new routes that keeps the bindings whose target is still routed}
    ///
    /// @param extensions the header extension ids of the BUNDLE group
    /// @param routes     the new routes
    public RtpDemuxer<T> withRoutes(HeaderExtensionMap extensions, List<Route<T>> routes) {
        var next = create(extensions, routes);
        for (var entry : bindings.entrySet()) {
            for (var route : next.routes) {
                if (route.target().equals(entry.getValue().target())) {
                    next.bindings.put(entry.getKey(), route);
                    break;
                }
            }
        }
        return next;
    }

    /// {@return the routes}
    public List<Route<T>> routes() {
        return routes;
    }

    /// Routes a packet, learning its SSRC binding when the packet identifies its route.
    ///
    /// @param packet the packet
    /// @return the target, or what the packet carried when no route claims it
    public Result<T> route(RtpPacket packet) {
        Objects.requireNonNull(packet, "packet cannot be null");
        var ssrc = packet.ssrc();
        var mid = identifier(packet, midId, "mid");
        var rid = identifier(packet, ridId, "rid");
        var repairedRid = identifier(packet, repairedRidId, "repaired rid");
        if (mid.isPresent()) {
            var candidates = new ArrayList<Route<T>>(2);
            for (var route : routes) {
                if (route.mid().equals(mid)) {
                    candidates.add(route);
                }
            }
            var chosen = pick(candidates, rid.or(() -> repairedRid), ssrc);
            if (chosen.isEmpty()) {
                return new Result.Unmatched<>(new UnsignaledStream(ssrc, packet.payloadType(), mid, rid, repairedRid));
            }
            bindings.put(ssrc, chosen.get());
            return new Result.Matched<>(chosen.get().target());
        }
        var bound = bindings.get(ssrc);
        if (bound != null) {
            return new Result.Matched<>(bound.target());
        }
        for (var route : routes) {
            if (route.ssrcs().contains(ssrc)) {
                bindings.put(ssrc, route);
                return new Result.Matched<>(route.target());
            }
        }
        if (rid.isPresent() || repairedRid.isPresent()) {
            var byRid = new ArrayList<Route<T>>(1);
            for (var route : routes) {
                if (route.rid().equals(rid) || route.rid().equals(repairedRid)) {
                    byRid.add(route);
                }
            }
            if (byRid.size() == 1) {
                bindings.put(ssrc, byRid.getFirst());
                return new Result.Matched<>(byRid.getFirst().target());
            }
        }
        Route<T> byType = null;
        for (var route : routes) {
            if (route.payloadTypes().contains(packet.payloadType())) {
                if (byType != null) {
                    byType = null;
                    break;
                }
                byType = route;
            }
        }
        if (byType != null) {
            bindings.put(ssrc, byType);
            return new Result.Matched<>(byType.target());
        }
        return new Result.Unmatched<>(new UnsignaledStream(ssrc, packet.payloadType(), mid, rid, repairedRid));
    }

    private Optional<Route<T>> pick(List<Route<T>> candidates, Optional<String> rid, long ssrc) {
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        if (rid.isPresent()) {
            for (var route : candidates) {
                if (route.rid().equals(rid)) {
                    return Optional.of(route);
                }
            }
            return Optional.empty();
        }
        var bound = bindings.get(ssrc);
        if (bound != null && candidates.contains(bound)) {
            return Optional.of(bound);
        }
        for (var route : candidates) {
            if (route.ssrcs().contains(ssrc)) {
                return Optional.of(route);
            }
        }
        if (candidates.size() == 1) {
            return Optional.of(candidates.getFirst());
        }
        return Optional.empty();
    }

    /// Binds an SSRC to the route of a target, as when signaling announces it after the first packets.
    ///
    /// @param ssrc   the SSRC
    /// @param target the target, which must be routed
    /// @throws IllegalArgumentException if no route leads to `target`
    public void bind(long ssrc, T target) {
        for (var route : routes) {
            if (route.target().equals(target)) {
                bindings.put(ssrc, route);
                return;
            }
        }
        throw new IllegalArgumentException("no route leads to " + target);
    }

    /// Forgets the binding of an SSRC, as after a BYE.
    ///
    /// @param ssrc the SSRC
    public void unbind(long ssrc) {
        bindings.remove(ssrc);
    }

    /// {@return the target an SSRC is bound to}
    ///
    /// @param ssrc the SSRC
    public Optional<T> boundTarget(long ssrc) {
        var route = bindings.get(ssrc);
        return route == null ? Optional.empty() : Optional.of(route.target());
    }

    private static Optional<String> identifier(RtpPacket packet, OptionalInt id, String name) {
        if (id.isEmpty()) {
            return Optional.empty();
        }
        var value = packet.extension(id.getAsInt());
        if (value.isEmpty()) {
            return Optional.empty();
        }
        try {
            ByteBuffer buffer = value.get();
            return Optional.of(switch (name) {
                case "mid" -> Mid.parse(buffer).value();
                case "rid" -> RtpStreamId.parse(buffer).value();
                default -> RepairedRtpStreamId.parse(buffer).value();
            });
        } catch (RtpFormatException exception) {
            return Optional.empty();
        }
    }
}
