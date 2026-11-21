package com.github.auties00.parley.peer;

/// A registered listener; closing it stops the listener after the event it is handling.
@FunctionalInterface
public interface Subscription extends AutoCloseable {
    /// Stops the listener; idempotent.
    @Override
    void close();
}
