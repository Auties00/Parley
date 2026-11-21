package com.github.auties00.parley.event;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the event package: the backlog the first stream receives, bounded drop-oldest queues, coalescing, the end
/// of a source, listeners and closing.
@DisplayName("event streams")
class EventSourceTest {
    @Test
    @DisplayName("the first stream receives the events published before it, later ones start empty")
    void backlog() throws InterruptedException {
        var source = new EventSource<Integer>();
        source.publish(1);
        source.publish(2);
        var first = source.open();
        var second = source.open();
        source.publish(3);
        assertEquals(1, first.next());
        assertEquals(2, first.next());
        assertEquals(3, first.next());
        assertEquals(3, second.next());
        assertTrue(second.next(Duration.ZERO).isEmpty());
    }

    @Test
    @DisplayName("a stream drops its oldest events past the capacity and counts them")
    void bounded() throws InterruptedException {
        var source = new EventSource<Integer>(4);
        try (var stream = source.open()) {
            for (var index = 0; index < 10; index++) {
                source.publish(index);
            }
            assertEquals(6, stream.dropped());
            assertEquals(List.of(6, 7, 8, 9), List.of(stream.next(), stream.next(), stream.next(), stream.next()));
        }
        var unread = new EventSource<Integer>(4);
        for (var index = 0; index < 1000; index++) {
            unread.publish(index);
        }
        try (var late = unread.open()) {
            assertEquals(996, late.dropped(), "an unopened source keeps a bounded backlog");
        }
    }

    @Test
    @DisplayName("a coalesced event replaces the queued one with the same key")
    void coalescing() {
        var source = new EventSource<String>(16, event -> event.startsWith("rate:")
                ? Optional.of(event.substring(5, 6)) : Optional.empty());
        source.publish("rate:a=1");
        source.publish("other");
        source.publish("rate:b=1");
        source.publish("rate:a=2");
        try (var stream = source.open()) {
            assertEquals(List.of("other", "rate:b=1", "rate:a=2"), stream.stream().limit(3).toList());
        }
    }

    @Test
    @DisplayName("ending the source delivers the queued events, then ends every stream")
    void end() throws InterruptedException {
        var source = new EventSource<Integer>();
        var stream = source.open();
        source.publish(1);
        source.end();
        source.publish(2);
        assertFalse(stream.isEnded(), "a queued event is still to be taken");
        assertEquals(1, stream.next());
        assertTrue(stream.isEnded());
        assertThrows(NoSuchElementException.class, stream::next);
        assertTrue(stream.next(Duration.ofSeconds(1)).isEmpty());
        assertTrue(source.open().isEnded(), "a stream opened after the end is ended");
        assertEquals(List.of(), source.open().stream().toList());
    }

    @Test
    @DisplayName("the end wakes a consumer blocked in next and in the iterator")
    void wakes() throws InterruptedException {
        var source = new EventSource<Integer>();
        var stream = source.open();
        var done = new CountDownLatch(1);
        var seen = new CopyOnWriteArrayList<Integer>();
        Thread.ofVirtual().start(() -> {
            for (var event : stream) {
                seen.add(event);
            }
            done.countDown();
        });
        source.publish(7);
        Thread.sleep(20);
        source.end();
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(List.of(7), seen);
    }

    @Test
    @DisplayName("closing a stream discards its events and stops publishing to it")
    void close() throws InterruptedException {
        var source = new EventSource<Integer>();
        var stream = source.open();
        source.publish(1);
        stream.close();
        source.publish(2);
        assertTrue(stream.isEnded());
        assertTrue(stream.next(Duration.ZERO).isEmpty());
        stream.close();
    }

    @Test
    @DisplayName("listeners run in order on a thread of the given factory and survive a throwing call")
    void listener() throws InterruptedException {
        var source = new EventSource<Integer>();
        source.publish(1);
        var threads = new AtomicInteger();
        var seen = new CopyOnWriteArrayList<Integer>();
        var done = new CountDownLatch(3);
        var subscription = source.addListener(event -> {
            seen.add(event);
            done.countDown();
            if (event == 2) {
                throw new IllegalStateException("listener failure");
            }
        }, runnable -> {
            threads.incrementAndGet();
            return Thread.ofVirtual().unstarted(runnable);
        });
        source.publish(2);
        source.publish(3);
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertEquals(List.of(1, 2, 3), seen, "the first listener gets the backlog");
        assertEquals(1, threads.get());
        subscription.close();
        source.publish(4);
        Thread.sleep(20);
        assertEquals(3, seen.size());
        assertThrows(IllegalArgumentException.class, () -> new EventSource<Integer>(0));
    }

    @Test
    @DisplayName("an interrupt ends the iteration and keeps the interrupt status")
    void interrupt() throws InterruptedException {
        var source = new EventSource<Integer>();
        var stream = source.open();
        var interrupted = new CountDownLatch(1);
        var thread = Thread.ofVirtual().start(() -> {
            var iterator = stream.iterator();
            assertFalse(iterator.hasNext());
            if (Thread.currentThread().isInterrupted()) {
                interrupted.countDown();
            }
        });
        Thread.sleep(20);
        thread.interrupt();
        assertTrue(interrupted.await(5, TimeUnit.SECONDS));
    }
}
