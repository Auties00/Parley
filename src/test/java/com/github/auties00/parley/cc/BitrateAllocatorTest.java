package com.github.auties00.parley.cc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers how a target is split across senders and simulcast encodings.
@DisplayName("BitrateAllocator")
class BitrateAllocatorTest {
    private static EncodingDemand demand(String sender, String rid, long min, long max, double priority, double scale) {
        var key = rid == null ? AllocationKey.of(sender) : AllocationKey.of(sender, rid);
        return new EncodingDemand(key, true, min, max, priority, scale);
    }

    @Test
    @DisplayName("gives a single sender everything up to its maximum")
    void single() {
        var allocator = new BitrateAllocator();
        var audio = demand("audio", null, 6_000, 64_000, 1, 1);
        assertEquals(64_000, allocator.allocate(1_000_000, List.of(audio)).get(audio.key()));
        assertEquals(30_000, allocator.allocate(30_000, List.of(audio)).get(audio.key()));
    }

    @Test
    @DisplayName("shares spare bandwidth in proportion to priority")
    void priorities() {
        var allocator = new BitrateAllocator();
        var high = demand("a", null, 0, 10_000_000, 4, 1);
        var low = demand("b", null, 0, 10_000_000, 1, 1);
        var result = allocator.allocate(1_000_000, List.of(high, low));
        assertEquals(800_000, result.get(high.key()), 1);
        assertEquals(200_000, result.get(low.key()), 1);
    }

    @Test
    @DisplayName("redistributes what a capped sender cannot use")
    void redistribution() {
        var allocator = new BitrateAllocator();
        var capped = demand("audio", null, 0, 50_000, 1, 1);
        var video = demand("video", null, 0, 10_000_000, 1, 1);
        var result = allocator.allocate(1_000_000, List.of(capped, video));
        assertEquals(50_000, result.get(capped.key()));
        assertEquals(950_000, result.get(video.key()), 1);
    }

    @Test
    @DisplayName("fills simulcast encodings from the smallest picture up")
    void simulcast() {
        var allocator = new BitrateAllocator();
        var low = demand("cam", "q", 50_000, 150_000, 1, 4);
        var mid = demand("cam", "h", 150_000, 500_000, 1, 2);
        var high = demand("cam", "f", 500_000, 2_500_000, 1, 1);
        var demands = List.of(high, mid, low);
        var small = allocator.allocate(300_000, demands);
        assertEquals(150_000, small.get(low.key()));
        assertEquals(0, small.get(mid.key()), "the middle layer needs 150 kbit/s plus hysteresis");
        assertEquals(0, small.get(high.key()));
        var medium = allocator.allocate(400_000, demands);
        assertEquals(150_000, medium.get(low.key()));
        assertEquals(250_000, medium.get(mid.key()));
        assertEquals(0, medium.get(high.key()));
        var large = allocator.allocate(3_000_000, demands);
        assertEquals(150_000, large.get(low.key()));
        assertEquals(500_000, large.get(mid.key()));
        assertEquals(2_350_000, large.get(high.key()));
        assertEquals(List.of(high.key(), mid.key(), low.key()), List.copyOf(large.keySet()));
    }

    @Test
    @DisplayName("needs a margin to enable an encoding but keeps an enabled one down to its minimum")
    void hysteresis() {
        var allocator = new BitrateAllocator();
        var video = demand("v", null, 100_000, 1_000_000, 1, 1);
        assertEquals(0, allocator.allocate(110_000, List.of(video)).get(video.key()));
        assertEquals(115_000, allocator.allocate(115_000, List.of(video)).get(video.key()));
        assertEquals(100_000, allocator.allocate(100_000, List.of(video)).get(video.key()));
        assertEquals(0, allocator.allocate(99_999, List.of(video)).get(video.key()));
        assertEquals(0, allocator.allocate(110_000, List.of(video)).get(video.key()));
    }

    @Test
    @DisplayName("suspends lower priority senders first when even minimums do not fit")
    void suspension() {
        var allocator = new BitrateAllocator();
        var important = demand("a", null, 300_000, 1_000_000, 2, 1);
        var other = demand("b", null, 300_000, 1_000_000, 1, 1);
        var result = allocator.allocate(500_000, List.of(other, important));
        assertEquals(500_000, result.get(important.key()));
        assertEquals(0, result.get(other.key()));
    }

    @Test
    @DisplayName("gives inactive encodings nothing and rejects duplicate keys and negative targets")
    void inactiveAndValidation() {
        var allocator = new BitrateAllocator();
        var off = new EncodingDemand(AllocationKey.of("x"), false, 0, 1_000_000, 1, 1);
        assertEquals(0, allocator.allocate(1_000_000, List.of(off)).get(off.key()));
        assertThrows(IllegalArgumentException.class, () -> allocator.allocate(1, List.of(off, off)));
        assertThrows(IllegalArgumentException.class, () -> allocator.allocate(-1, List.of(off)));
        assertThrows(IllegalArgumentException.class, () -> new EncodingDemand(AllocationKey.of("y"), true, 10, 5, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new EncodingDemand(AllocationKey.of("y"), true, 0, 5, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new EncodingDemand(AllocationKey.of("y"), true, 0, 5, 1, 0.5));
    }

    @RepeatedTest(10)
    @DisplayName("never exceeds the target or an encoding's maximum, and meets every enabled minimum")
    void invariants(RepetitionInfo repetition) {
        var random = new Random(repetition.getCurrentRepetition() * 31L);
        var allocator = new BitrateAllocator();
        for (var round = 0; round < 200; round++) {
            var demands = new ArrayList<EncodingDemand>();
            var senders = random.nextInt(1, 5);
            for (var sender = 0; sender < senders; sender++) {
                var layers = random.nextInt(1, 4);
                for (var layer = 0; layer < layers; layer++) {
                    var min = random.nextLong(0, 300_000);
                    var max = min + random.nextLong(0, 2_000_000);
                    demands.add(new EncodingDemand(layers == 1 ? AllocationKey.of("s" + sender)
                            : AllocationKey.of("s" + sender, "r" + layer), random.nextInt(10) > 0, min, max,
                            random.nextDouble(0.5, 4), 1 << (layers - 1 - layer)));
                }
            }
            var target = random.nextLong(0, 5_000_000);
            var result = allocator.allocate(target, demands);
            assertEquals(demands.size(), result.size());
            var total = result.values().stream().mapToLong(Long::longValue).sum();
            assertTrue(total <= target, total + " > " + target);
            for (var demand : demands) {
                var allocated = result.get(demand.key());
                assertTrue(allocated >= 0 && allocated <= demand.maxBitrateBps());
                if (!demand.active()) {
                    assertEquals(0, allocated);
                } else if (allocated > 0) {
                    assertTrue(allocated >= demand.minBitrateBps() - 1, allocated + " < " + demand.minBitrateBps());
                }
            }
        }
    }
}
