package com.github.auties00.parley.event;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/// A bounded, blocking stream of one source's events for one consumer.
///
/// An [EventSource] opens the stream; every event the source publishes while the stream is open is queued for it
/// once, in publication order, whatever other streams and listeners do. The queue holds at most the source's
/// capacity: when the consumer falls behind, the oldest queued event is dropped and counted in [#dropped()], so a
/// stream that is opened and never read costs bounded memory. The stream ends when its source ends (a closed peer
/// connection, a stopped track) or when it is closed; the events queued before the source ended are still delivered,
/// then [#next()] throws and the iteration stops.
///
/// {@snippet lang = java :
/// try (var events = peerConnection.events()) {
///     for (var event : events) {
///         switch (event) {
///             case PeerConnectionEvent.IceCandidate candidate -> signaling.send(candidate.candidate());
///             case PeerConnectionEvent.ConnectionStateChanged(var state) -> log(state);
///             default -> { }
///         }
///     }
/// }
/// }
///
/// # Threading
///
/// A stream is meant for one consuming thread at a time; [#close()] may be called from any thread and wakes the
/// consumer.
///
/// @param <E> the event type
public final class EventStream<E> implements Iterable<E>, AutoCloseable {
    /// Guards [#queue], [#dropped] and [#ended].
    private final ReentrantLock lock = new ReentrantLock();
    /// Signals a queued event or the end.
    private final Condition available = lock.newCondition();
    /// The undelivered events, oldest first.
    private final ArrayDeque<E> queue = new ArrayDeque<>();
    /// The most events [#queue] holds.
    private final int capacity;
    /// The key under which a newer event replaces a queued, undelivered one; empty for events that are never
    /// replaced.
    private final Function<? super E, Optional<?>> coalescingKey;
    /// Unregisters the stream from its source when it is closed.
    private final Consumer<EventStream<E>> onClose;
    /// The events dropped because the queue was full.
    private long dropped;
    /// Whether no further event is queued.
    private boolean ended;

    /// Creates a stream; only an [EventSource] does.
    EventStream(int capacity, Function<? super E, Optional<?>> coalescingKey, Consumer<EventStream<E>> onClose) {
        this.capacity = capacity;
        this.coalescingKey = coalescingKey;
        this.onClose = onClose;
    }

    /// Queues an event, dropping the oldest when the queue is full; ignored once the stream has ended.
    void offer(E event) {
        var key = coalescingKey.apply(event);
        lock.lock();
        try {
            if (ended) {
                return;
            }
            if (key.isPresent()) {
                var iterator = queue.iterator();
                while (iterator.hasNext()) {
                    var queued = iterator.next();
                    if (key.equals(coalescingKey.apply(queued))) {
                        iterator.remove();
                        break;
                    }
                }
            }
            if (queue.size() >= capacity) {
                queue.removeFirst();
                dropped++;
            }
            queue.addLast(event);
            available.signal();
        } finally {
            lock.unlock();
        }
    }

    /// Ends the stream from the source's side; the events already queued are still delivered.
    void end() {
        lock.lock();
        try {
            ended = true;
            available.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Waits for the next event.
    ///
    /// @return the next event
    /// @throws NoSuchElementException if the stream has ended and every queued event was taken
    /// @throws InterruptedException   if the calling thread is interrupted while waiting
    public E next() throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (queue.isEmpty()) {
                if (ended) {
                    throw new NoSuchElementException("the event stream has ended");
                }
                available.await();
            }
            return queue.removeFirst();
        } finally {
            lock.unlock();
        }
    }

    /// Waits up to `timeout` for the next event.
    ///
    /// An empty result means either that the timeout elapsed or that the stream has ended; [#isEnded()] tells them
    /// apart. A zero or negative timeout takes a queued event without waiting.
    ///
    /// @param timeout the longest time to wait
    /// @return the next event, or an empty optional when the timeout elapsed or the stream has ended
    /// @throws InterruptedException if the calling thread is interrupted while waiting
    public Optional<E> next(Duration timeout) throws InterruptedException {
        Objects.requireNonNull(timeout, "timeout cannot be null");
        var left = timeout.isNegative() ? 0 : saturatedNanos(timeout);
        lock.lockInterruptibly();
        try {
            while (queue.isEmpty()) {
                if (ended || left <= 0) {
                    return Optional.empty();
                }
                left = available.awaitNanos(left);
            }
            return Optional.of(queue.removeFirst());
        } finally {
            lock.unlock();
        }
    }

    /// {@return whether the stream has ended, by its source or by [#close()], and every queued event was taken}
    public boolean isEnded() {
        lock.lock();
        try {
            return ended && queue.isEmpty();
        } finally {
            lock.unlock();
        }
    }

    /// {@return how many events were dropped, oldest first, because the consumer fell behind by more than the
    /// source's capacity}
    public long dropped() {
        lock.lock();
        try {
            return dropped;
        } finally {
            lock.unlock();
        }
    }

    /// {@return a sequential stream of the events, blocking for each and ending with this stream}
    ///
    /// Closing the returned stream closes this one. An interrupt while it waits ends it and leaves the thread's
    /// interrupt status set.
    public Stream<E> stream() {
        return StreamSupport.stream(Spliterators.spliteratorUnknownSize(iterator(),
                Spliterator.ORDERED | Spliterator.NONNULL), false).onClose(this::close);
    }

    /// {@return an iterator that blocks in `hasNext()` until an event arrives and stops when the stream ends}
    ///
    /// An interrupt while `hasNext()` waits ends the iteration and leaves the thread's interrupt status set.
    @Override
    public Iterator<E> iterator() {
        return new Iterator<>() {
            /// The event `hasNext()` took, or `null`.
            private E pending;
            /// Whether the iteration has ended.
            private boolean done;

            @Override
            public boolean hasNext() {
                if (pending != null) {
                    return true;
                }
                if (done) {
                    return false;
                }
                try {
                    pending = EventStream.this.next();
                    return true;
                } catch (NoSuchElementException exception) {
                    done = true;
                    return false;
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    done = true;
                    return false;
                }
            }

            @Override
            public E next() {
                if (!hasNext()) {
                    throw new NoSuchElementException("the event stream has ended");
                }
                var event = pending;
                pending = null;
                return event;
            }
        };
    }

    /// Ends the stream, discards the events still queued and unregisters it from its source; idempotent.
    @Override
    public void close() {
        lock.lock();
        try {
            ended = true;
            queue.clear();
            available.signalAll();
        } finally {
            lock.unlock();
        }
        onClose.accept(this);
    }

    /// {@return `timeout` in nanoseconds, saturated at `Long.MAX_VALUE`}
    private static long saturatedNanos(Duration timeout) {
        try {
            return timeout.toNanos();
        } catch (ArithmeticException exception) {
            return Long.MAX_VALUE;
        }
    }
}
