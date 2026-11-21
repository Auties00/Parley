package com.github.auties00.parley.stats;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the report container and the W3C type names of the statistics records.
@DisplayName("StatsReport")
class StatsReportTest {
    static CodecStats codec(String id) {
        return new CodecStats(id, Instant.EPOCH, 111, "T0", "audio/opus", java.util.OptionalLong.of(48000),
                OptionalInt.of(2), Optional.of("minptime=10"));
    }

    @Test
    @DisplayName("looks objects up by id and type, in insertion order")
    void lookup() {
        var report = StatsReport.of(List.of(codec("C1"), new PeerConnectionStats("P", Instant.EPOCH, 1, 0),
                codec("C2")));
        assertEquals(3, report.size());
        assertEquals(Optional.of(codec("C1")), report.get("C1", CodecStats.class));
        assertTrue(report.get("C1", PeerConnectionStats.class).isEmpty());
        assertTrue(report.get("missing").isEmpty());
        assertEquals(List.of("C1", "C2"), report.all(CodecStats.class).stream().map(RtcStats::id).toList());
        assertEquals(1, report.stream(RtcStatsType.PEER_CONNECTION).count());
        var iterated = new ArrayList<String>();
        report.forEach(object -> iterated.add(object.id()));
        assertEquals(List.of("C1", "P", "C2"), iterated);
    }

    @Test
    @DisplayName("refuses a key that differs from its object's id")
    void mismatchedKey() {
        assertThrows(IllegalArgumentException.class, () -> new StatsReport(Map.of("X", codec("C1"))));
    }

    @Test
    @DisplayName("maps every type to its W3C name and back")
    void types() {
        for (var type : RtcStatsType.values()) {
            assertEquals(Optional.of(type), RtcStatsType.of(type.value()));
        }
        assertEquals("inbound-rtp", RtcStatsType.INBOUND_RTP.value());
        assertTrue(RtcStatsType.of("track").isEmpty());
        assertEquals(RtcStatsType.CODEC, codec("C").type());
        var local = new IceCandidateStats("L", Instant.EPOCH, false, "T0", Optional.of("192.0.2.1"), 1, "udp",
                IceCandidateStats.CandidateType.HOST, 1, Optional.empty(), Optional.empty(), "f", Optional.empty(),
                OptionalInt.empty(), Optional.empty(), Optional.empty());
        assertEquals(RtcStatsType.LOCAL_CANDIDATE, local.type());
        assertEquals("in-progress", IceCandidatePairStats.State.IN_PROGRESS.value());
    }
}
