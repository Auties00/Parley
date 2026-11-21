package com.github.auties00.parley.peer;

import java.lang.System.Logger.Level;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadFactory;
import java.util.function.Consumer;

/// Fans the events of one source out to its [EventStream]s and listeners.
///
/// Each listener runs on its own thread from the hub's factory, reading its own stream, so a slow listener delays
/// only itself and sees the events in order.
final class EventHub<E> {
    private static final System.Logger LOGGER = System.getLogger(EventHub.class.getName());

    /// The open streams.
    private final CopyOnWriteArrayList<EventStream<E>> streams = new CopyOnWriteArrayList<>();
    /// The factory of the listener threads.
    private final ThreadFactory threadFactory;
    /// Whether the source has ended.
    private volatile boolean ended;

    EventHub(ThreadFactory threadFactory) {
        this.threadFactory = Objects.requireNonNull(threadFactory);
    }

    /// {@return a new stream of the events raised from now on; an already ended stream if the source has ended}
    EventStream<E> open() {
        return register(new EventStream<E>(streams::remove));
    }

    /// Registers a stream, ending it at once when the source has ended.
    private EventStream<E> register(EventStream<E> stream) {
        streams.add(stream);
        if (ended) {
            stream.end();
        }
        return stream;
    }

    /// Starts a thread that hands every event raised from now on to `listener`, in order.
    ///
    /// @return the stream the listener reads; closing it stops the listener
    EventStream<E> addListener(Consumer<? super E> listener) {
        Objects.requireNonNull(listener, "listener cannot be null");
        var stream = open();
        var thread = threadFactory.newThread(() -> {
            for (var event : stream) {
                try {
                    listener.accept(event);
                } catch (RuntimeException exception) {
                    LOGGER.log(Level.WARNING, "an event listener threw", exception);
                }
            }
        });
        thread.start();
        return stream;
    }

    /// Delivers an event to every open stream.
    void publish(E event) {
        Objects.requireNonNull(event);
        for (var stream : streams) {
            stream.offer(event);
        }
    }

    /// Ends every stream after the events already queued.
    void end() {
        ended = true;
        for (var stream : streams) {
            stream.end();
        }
        streams.clear();
    }
}
