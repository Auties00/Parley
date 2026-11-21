package com.github.auties00.parley.event;

import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;

/// The producing side of a family of [EventStream]s: a component keeps its source private, publishes into it and
/// exposes only the streams it opens.
///
/// Every stream gets every event published while it is open. The first stream ever opened also gets the events
/// published since the source was created, up to its capacity, so an application that opens a component's events
/// right after creating it, or after the calls that raise the first events, loses none. Later streams start empty.
/// Each stream is bounded: past the capacity the oldest queued event is dropped and counted in
/// [EventStream#dropped()].
///
/// A source may coalesce events: with a coalescing key, an event whose key is present replaces a queued, undelivered
/// event with an equal key in every stream, so a consumer that falls behind sees the latest value of a fast-changing
/// quantity (a target bitrate per layer) instead of every intermediate one.
///
/// {@snippet lang = java :
/// private final EventSource<TrackEvent> events = new EventSource<>();
///
/// public EventStream<TrackEvent> events() {
///     return events.open();
/// }
///
/// void onMuted() {
///     events.publish(new TrackEvent.Muted());
/// }
/// }
///
/// # Threading
///
/// Every method is safe for concurrent use; [#publish(Object)] never blocks on a consumer.
///
/// @param <E> the event type
public final class EventSource<E> {
    private static final System.Logger LOGGER = System.getLogger(EventSource.class.getName());

    /// The capacity of each stream of a source created without one.
    public static final int DEFAULT_CAPACITY = 1024;

    /// Guards [#streams], [#backlog] and [#ended].
    private final ReentrantLock lock = new ReentrantLock();
    /// The most events each stream queues.
    private final int capacity;
    /// The key under which a newer event replaces a queued one.
    private final Function<? super E, Optional<?>> coalescingKey;
    /// The streams events are published to, the unclaimed backlog included.
    private final List<EventStream<E>> streams = new ArrayList<>();
    /// The stream that has collected every event since construction, until the first [#open()] claims it.
    private EventStream<E> backlog;
    /// Whether the source has ended.
    private boolean ended;

    /// Creates a source whose streams hold [#DEFAULT_CAPACITY] events each and never coalesce.
    public EventSource() {
        this(DEFAULT_CAPACITY);
    }

    /// Creates a source whose streams hold `capacity` events each and never coalesce.
    ///
    /// @param capacity the most events a stream queues, positive
    /// @throws IllegalArgumentException if `capacity` is not positive
    public EventSource(int capacity) {
        this(capacity, event -> Optional.empty());
    }

    /// Creates a source whose streams hold `capacity` events each and coalesce by `coalescingKey`.
    ///
    /// @param capacity      the most events a stream queues, positive
    /// @param coalescingKey a function giving the key under which an event replaces a queued, undelivered event with
    ///                      an equal key, or an empty optional for an event that is always queued; it must not throw
    /// @throws IllegalArgumentException if `capacity` is not positive
    public EventSource(int capacity, Function<? super E, Optional<?>> coalescingKey) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive: " + capacity);
        }
        this.capacity = capacity;
        this.coalescingKey = Objects.requireNonNull(coalescingKey, "coalescingKey cannot be null");
        this.backlog = newStream();
        streams.add(backlog);
    }

    /// Opens a stream of the events published from now on.
    ///
    /// The first stream ever opened starts with the events published since the source was created. Once the
    /// source has ended, a new stream is already ended (the first one still delivers the backlog first).
    ///
    /// @return the stream, which the caller should close when done
    public EventStream<E> open() {
        lock.lock();
        try {
            if (backlog != null) {
                var stream = backlog;
                backlog = null;
                return stream;
            }
            var stream = newStream();
            if (ended) {
                stream.end();
            } else {
                streams.add(stream);
            }
            return stream;
        } finally {
            lock.unlock();
        }
    }

    /// Hands every event published from now on (the backlog too, if no stream was opened yet) to `listener`, in
    /// order, on one thread `threads` creates.
    ///
    /// A listener that throws is logged and keeps receiving the following events.
    ///
    /// @param listener the listener
    /// @param threads  the factory of the listener's thread
    /// @return the stream the listener reads; closing it stops the listener after the event it is handling
    public EventStream<E> addListener(Consumer<? super E> listener, ThreadFactory threads) {
        Objects.requireNonNull(listener, "listener cannot be null");
        Objects.requireNonNull(threads, "threads cannot be null");
        var stream = open();
        var thread = threads.newThread(() -> {
            for (var event : stream) {
                try {
                    listener.accept(event);
                } catch (RuntimeException exception) {
                    LOGGER.log(Level.WARNING, "an event listener threw", exception);
                }
            }
        });
        if (thread == null) {
            stream.close();
            throw new IllegalStateException("the thread factory refused to create a listener thread");
        }
        thread.start();
        return stream;
    }

    /// Publishes an event to every open stream; ignored once the source has ended.
    ///
    /// @param event the event
    public void publish(E event) {
        Objects.requireNonNull(event, "event cannot be null");
        lock.lock();
        try {
            if (ended) {
                return;
            }
            for (var stream : streams) {
                stream.offer(event);
            }
        } finally {
            lock.unlock();
        }
    }

    /// Ends the source: every stream delivers the events it queued, then ends; idempotent.
    public void end() {
        lock.lock();
        try {
            if (ended) {
                return;
            }
            ended = true;
            for (var stream : streams) {
                stream.end();
            }
            streams.clear();
        } finally {
            lock.unlock();
        }
    }

    /// {@return whether the source has ended}
    public boolean isEnded() {
        lock.lock();
        try {
            return ended;
        } finally {
            lock.unlock();
        }
    }

    /// {@return a new stream that unregisters itself when closed}
    private EventStream<E> newStream() {
        return new EventStream<>(capacity, coalescingKey, this::unregister);
    }

    /// Stops publishing to a closed stream.
    private void unregister(EventStream<E> stream) {
        lock.lock();
        try {
            streams.remove(stream);
            if (backlog == stream) {
                backlog = null;
            }
        } finally {
            lock.unlock();
        }
    }
}
