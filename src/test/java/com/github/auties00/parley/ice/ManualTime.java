package com.github.auties00.parley.ice;

import com.github.auties00.parley.net.MonotonicClock;

import java.time.Duration;
import java.util.PriorityQueue;
import java.util.concurrent.atomic.AtomicLong;

/// Simulated time for ICE tests: a clock that moves only when [#advance(Duration)] is called, and schedulers whose
/// tasks run, in due order, on the thread that advances it.
final class ManualTime implements MonotonicClock {
    /// The current time.
    private final AtomicLong now = new AtomicLong(1_000_000_000L);

    /// The pending tasks of every scheduler.
    private final PriorityQueue<Task> queue = new PriorityQueue<>();

    /// The schedule order, which breaks ties.
    private long sequence;

    @Override
    public long nanos() {
        return now.get();
    }

    /// {@return a scheduler whose tasks run when time advances}
    IceScheduler scheduler() {
        return new IceScheduler() {
            private volatile boolean closed;

            @Override
            public Cancellable schedule(long delayNanos, Runnable task) {
                synchronized (queue) {
                    if (closed) {
                        return () -> {
                        };
                    }
                    var entry = new Task(now.get() + Math.max(0, delayNanos), sequence++, task);
                    queue.add(entry);
                    return () -> entry.cancelled = true;
                }
            }

            @Override
            public void close() {
                closed = true;
            }
        };
    }

    /// Moves time forward, running every task that falls due on the way, at its due time.
    ///
    /// @param duration how far to move
    void advance(Duration duration) {
        var target = now.get() + duration.toNanos();
        while (true) {
            Task next;
            synchronized (queue) {
                next = queue.peek();
                if (next == null || next.due > target) {
                    break;
                }
                queue.poll();
            }
            now.set(Math.max(now.get(), next.due));
            if (!next.cancelled) {
                next.task.run();
            }
        }
        now.set(target);
    }

    /// Moves time forward in steps, pausing in real time between them so reader threads can deliver datagrams.
    ///
    /// @param duration how far to move
    /// @param step     the step
    void advanceSlowly(Duration duration, Duration step) throws InterruptedException {
        var steps = duration.toNanos() / step.toNanos();
        for (var i = 0; i < steps; i++) {
            advance(step);
            Thread.sleep(2);
        }
    }

    /// A scheduled task.
    private static final class Task implements Comparable<Task> {
        private final long due;
        private final long order;
        private final Runnable task;
        private volatile boolean cancelled;

        Task(long due, long order, Runnable task) {
            this.due = due;
            this.order = order;
            this.task = task;
        }

        @Override
        public int compareTo(Task other) {
            var byDue = Long.compare(due, other.due);
            return byDue != 0 ? byDue : Long.compare(order, other.order);
        }
    }
}
