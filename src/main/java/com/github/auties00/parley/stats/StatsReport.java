package com.github.auties00.parley.stats;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

/// An immutable snapshot of statistics objects keyed by id, the W3C `RTCStatsReport`.
///
/// The objects reference one another by id: an [InboundRtpStreamStats] names its [TransportStats] through
/// `transportId` and its [CodecStats] through `codecId`, which [#get(String, Class)] resolves.
///
/// {@snippet lang = java :
/// var report = peerConnection.getStats();
/// for (var outbound : report.all(OutboundRtpStreamStats.class)) {
///     var remote = outbound.remoteId().flatMap(id -> report.get(id, RemoteInboundRtpStreamStats.class));
///     remote.flatMap(RemoteInboundRtpStreamStats::roundTripTime)
///             .ifPresent(rtt -> System.out.println(outbound.rid() + " rtt " + rtt));
/// }
/// }
///
/// @param stats the objects by id, in insertion order
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public record StatsReport(Map<String, RtcStats> stats) implements Iterable<RtcStats> {
    /// Creates a report, copying the map.
    ///
    /// @param stats the objects by id
    /// @throws IllegalArgumentException if a key differs from the id of its object
    public StatsReport {
        var copy = new LinkedHashMap<String, RtcStats>();
        stats.forEach((id, object) -> {
            Objects.requireNonNull(object, "stats object cannot be null");
            if (!id.equals(object.id())) {
                throw new IllegalArgumentException("key " + id + " differs from the object id " + object.id());
            }
            copy.put(id, object);
        });
        stats = Collections.unmodifiableMap(copy);
    }

    /// {@return a report of `objects` keyed by their ids, a later object replacing an earlier one with the same id}
    ///
    /// @param objects the objects
    public static StatsReport of(List<? extends RtcStats> objects) {
        var map = new LinkedHashMap<String, RtcStats>();
        for (var object : objects) {
            map.put(object.id(), object);
        }
        return new StatsReport(map);
    }

    /// {@return the object with id `id`, or an empty optional when the report has none}
    ///
    /// @param id the object id
    public Optional<RtcStats> get(String id) {
        return Optional.ofNullable(stats.get(Objects.requireNonNull(id, "id cannot be null")));
    }

    /// {@return the object with id `id` when it is an instance of `type`, or an empty optional otherwise}
    ///
    /// @param id   the object id
    /// @param type the record class
    /// @param <T>  the record type
    public <T extends RtcStats> Optional<T> get(String id, Class<T> type) {
        Objects.requireNonNull(type, "type cannot be null");
        return get(id).filter(type::isInstance).map(type::cast);
    }

    /// {@return the objects that are instances of `type`, in report order}
    ///
    /// @param type the record class, such as `InboundRtpStreamStats.class`
    /// @param <T>  the record type
    public <T extends RtcStats> Stream<T> stream(Class<T> type) {
        Objects.requireNonNull(type, "type cannot be null");
        return stats.values().stream().filter(type::isInstance).map(type::cast);
    }

    /// {@return the unmodifiable objects that are instances of `type`, in report order}
    ///
    /// @param type the record class
    /// @param <T>  the record type
    public <T extends RtcStats> List<T> all(Class<T> type) {
        return stream(type).toList();
    }

    /// {@return the objects of a W3C type, in report order}
    ///
    /// @param type the statistics type
    public Stream<RtcStats> stream(RtcStatsType type) {
        Objects.requireNonNull(type, "type cannot be null");
        return stats.values().stream().filter(object -> object.type() == type);
    }

    /// {@return the number of objects}
    public int size() {
        return stats.size();
    }

    /// {@return an iterator over the objects in report order; it does not support removal}
    @Override
    public Iterator<RtcStats> iterator() {
        return stats.values().iterator();
    }
}
