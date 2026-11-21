package com.github.auties00.parley.rtp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Duration;
import java.time.Instant;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers serial number arithmetic, the counter unwrapper and the NTP conversions.
@DisplayName("sequence numbers and NTP time")
class SequenceAndTimeTest {
    @ParameterizedTest
    @CsvSource({"1,0,true", "0,1,false", "0,65535,true", "65535,0,false", "32767,0,true", "32768,0,true",
            "0,32768,false", "5,5,false"})
    @DisplayName("orders sequence numbers across the wrap")
    void isNewer(int sequence, int reference, boolean newer) {
        assertEquals(newer, SequenceNumbers.isNewer(sequence, reference));
    }

    @Test
    @DisplayName("computes signed differences and wrapped sums")
    void arithmetic() {
        assertEquals(1, SequenceNumbers.difference(0, 65535));
        assertEquals(-1, SequenceNumbers.difference(65535, 0));
        assertEquals(2, SequenceNumbers.add(65535, 3));
        assertEquals(65535, SequenceNumbers.add(0, -1));
        assertTrue(SequenceNumbers.isNewerTimestamp(5, 0xFFFFFFF0L));
        assertFalse(SequenceNumbers.isNewerTimestamp(0xFFFFFFF0L, 5));
        assertEquals(21, SequenceNumbers.timestampDifference(5, 0xFFFFFFF0L));
    }

    @Test
    @DisplayName("unwraps sequence numbers forward and backward across wraps")
    void unwrapSequences() {
        var unwrapper = SequenceUnwrapper.forSequenceNumbers();
        assertEquals(65534, unwrapper.unwrap(65534));
        assertEquals(65535, unwrapper.unwrap(65535));
        assertEquals(65536, unwrapper.unwrap(0));
        assertEquals(65535, unwrapper.unwrap(65535));
        assertEquals(65536 + 100, unwrapper.unwrap(100));
        assertEquals(65536 + 5, unwrapper.peek(5));
        assertEquals(65536 + 100, unwrapper.last().orElseThrow());
    }

    @Test
    @DisplayName("never unwraps below zero")
    void unwrapFloor() {
        var unwrapper = SequenceUnwrapper.forSequenceNumbers();
        unwrapper.unwrap(2);
        assertEquals(65535, unwrapper.unwrap(65535));
    }

    @RepeatedTest(20)
    @DisplayName("unwraps a random walk of timestamps back to the walk")
    void unwrapWalk() {
        var random = new Random();
        var unwrapper = SequenceUnwrapper.forTimestamps();
        var position = 3_000_000_000L;
        assertEquals(position, unwrapper.unwrap(position));
        for (var i = 0; i < 1000; i++) {
            position += random.nextLong(-500_000_000L, 1_000_000_000L);
            assertEquals(position, unwrapper.unwrap(position & 0xFFFFFFFFL));
        }
    }

    @Test
    @DisplayName("converts instants to NTP and back within the fraction resolution")
    void ntp() {
        var instant = Instant.parse("2026-11-21T10:15:30.123456789Z");
        var ntp = NtpTime.fromInstant(instant);
        assertEquals(instant.getEpochSecond() + NtpTime.UNIX_EPOCH_OFFSET_SECONDS, ntp >>> 32);
        var back = NtpTime.toInstant(ntp);
        assertTrue(Duration.between(back, instant).abs().toNanos() <= 1);
        assertEquals((ntp >>> 16) & 0xFFFFFFFFL, NtpTime.compact(ntp));
    }

    @Test
    @DisplayName("converts durations to the compact format and back")
    void compact() {
        assertEquals(0x00018000L, NtpTime.compactOf(Duration.ofMillis(1500)));
        assertEquals(1_500_000_000L, NtpTime.compactToNanos(0x00018000L));
        assertEquals(0xFFFFFFFFL, NtpTime.compactOfNanos(Long.MAX_VALUE));
        assertEquals(0, NtpTime.compactOfNanos(-5));
    }
}
