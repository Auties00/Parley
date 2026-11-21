package com.github.auties00.parley.peer;

import java.time.Duration;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/// A blocking stream of the events of one source, from the moment it was opened until it is closed.
///
/// Each stream has its own queue: every event the source raises after the stream was opened is delivered to it once,
/// in the order raised, whatever other streams and listeners do. The stream ends when it is closed or when its source
/// ends (a closed peer connection, a stopped track); [#next()] then throws and the iterator stops.
///
/// {@snippet lang = java :
/// try (var events = peerConnection.events()) {
///     for (var event : events) {
///         switch (event) {
///             case PeerConnectionEvent.IceCandidate(var candidate) -> signaling.send(candidate);
///             case PeerConnectionEvent.ConnectionStateChanged(var state) -> log(state);
///             default -> {}
///         }
///     }
/// }
/// }
///
/// # Threading
///
/// A stream is meant for one consuming thread; [#close()] may be called from any thread and wakes it.
///
/// @param <E> the event type
public final class EventStream<E> implements Iterable<E>, AutoCloseable {
    /// Marks the end of the stream in the queue.
    private static final Object END = new Object();

    /// The queued events, then [#END].
    private final LinkedBlockingQueue<Object> queue = new LinkedBlockingQueue<>();
    /// Called when the stream is closed, to unregister it from its source.
    private final Consumer<EventStream<E>> onClose;
    /// Whether the stream has ended.
    private volatile boolean closed;

    /// Creates a stream that runs `onClose` when it closes.
    EventStream(Consumer<EventStream<E>> onClose) {
        this.onClose = Objects.requireNonNull(onClose);
    }

    /// Queues an event; ignored once the stream has ended.
    void offer(E event) {
        if (!closed) {
            queue.add(event);
        }
    }

    /// Ends the stream from the source's side, delivering the events already queued first.
    void end() {
        if (!closed) {
            closed = true;
            queue.add(END);
        }
    }

    /// Waits for the next event.
    ///
    /// @return the next event
    /// @throws NoSuchElementException if the stream has ended and every queued event was taken
    /// @throws InterruptedException   if the calling thread is interrupted while waiting
    public E next() throws InterruptedException {
        var item = queue.take();
        return unwrap(item).orElseThrow(() -> new NoSuchElementException("the event stream has ended"));
    }

    /// Waits up to `timeout` for the next event.
    ///
    /// @param timeout the longest time to wait
    /// @return the next event, or an empty optional when the timeout elapsed or the stream has ended
    /// @throws InterruptedException if the calling thread is interrupted while waiting
    public Optional<E> next(Duration timeout) throws InterruptedException {
        Objects.requireNonNull(timeout, "timeout cannot be null");
        var item = queue.poll(timeout.toNanos(), TimeUnit.NANOSECONDS);
        return item == null ? Optional.empty() : unwrap(item);
    }

    /// {@return the next event if one is queued, without waiting}
    public Optional<E> poll() {
        var item = queue.poll();
        return item == null ? Optional.empty() : unwrap(item);
    }

    /// Converts a queue item, putting the end marker back for later calls.
    @SuppressWarnings("unchecked")
    private Optional<E> unwrap(Object item) {
        if (item == END) {
            queue.add(END);
            return Optional.empty();
        }
        return Optional.of((E) item);
    }

    /// {@return whether the stream has ended; queued events may still be taken}
    public boolean isClosed() {
        return closed;
    }

    /// {@return an iterator that blocks in `hasNext()` until an event arrives and stops when the stream ends}
    ///
    /// An interrupt while `hasNext()` waits ends the iteration and leaves the thread's interrupt status set.
    @Override
    public Iterator<E> iterator() {
        return new Iterator<>() {
            /// The event fetched by `hasNext()`, or `null`.
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
                    var item = queue.take();
                    var event = unwrap(item);
                    if (event.isEmpty()) {
                        done = true;
                        return false;
                    }
                    pending = event.get();
                    return true;
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

    /// Ends the stream and unregisters it from its source; idempotent.
    @Override
    public void close() {
        end();
        onClose.accept(this);
    }
}
