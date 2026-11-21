package com.github.auties00.parley.ice;

import com.github.auties00.parley.net.MonotonicClock;

import java.lang.System.Logger.Level;
import java.util.PriorityQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/// The timer of an ICE agent: check pacing, retransmissions, nomination, consent and liveness all run as tasks on it.
///
/// Tasks run one at a time, in due order, never on the caller of [#schedule(long,Runnable)], so a task can take the
/// agent's lock without a reentrancy hazard. The production scheduler runs them on one thread it starts; tests use a
/// scheduler driven by a hand-advanced clock.
interface IceScheduler extends AutoCloseable {
    /// Schedules a task.
    ///
    /// @param delayNanos the delay from now, in nanoseconds of the scheduler's clock; `0` or less runs it as soon as
    ///                   possible
    /// @param task       the task
    /// @return a handle that cancels the task
    Cancellable schedule(long delayNanos, Runnable task);

    /// Cancels every task and stops the scheduler; later schedules are ignored.
    @Override
    void close();

    /// A scheduled task that can be cancelled.
    @FunctionalInterface
    interface Cancellable {
        /// Cancels the task; it does not run unless it already started. Cancelling twice has no effect.
        void cancel();
    }

    /// A scheduler that runs tasks on one thread of a [ThreadFactory], waiting with the thread's timed park.
    final class ThreadScheduler implements IceScheduler {
        /// The logger of the scheduler.
        private static final System.Logger LOGGER = System.getLogger(ThreadScheduler.class.getName());

        /// The lock guarding the queue.
        private final ReentrantLock lock = new ReentrantLock();

        /// Signalled when the queue's head changes or the scheduler closes.
        private final Condition changed = lock.newCondition();

        /// The pending tasks by due time; guarded by [#lock].
        private final PriorityQueue<Task> queue = new PriorityQueue<>();

        /// The clock due times are read from.
        private final MonotonicClock clock;

        /// The sequence number of the next task, which breaks ties in schedule order; guarded by [#lock].
        private long sequence;

        /// Whether [#close()] ran; guarded by [#lock].
        private boolean closed;

        /// Creates the scheduler and starts its thread.
        ThreadScheduler(MonotonicClock clock, ThreadFactory threadFactory) {
            this.clock = clock;
            threadFactory.newThread(this::run).start();
        }

        @Override
        public Cancellable schedule(long delayNanos, Runnable task) {
            lock.lock();
            try {
                if (closed) {
                    return () -> {
                    };
                }
                var entry = new Task(clock.nanos() + Math.max(0, delayNanos), sequence++, task);
                queue.add(entry);
                if (queue.peek() == entry) {
                    changed.signalAll();
                }
                return () -> entry.cancelled = true;
            } finally {
                lock.unlock();
            }
        }

        /// Runs due tasks until the scheduler closes.
        private void run() {
            while (true) {
                Task next;
                lock.lock();
                try {
                    while (true) {
                        if (closed) {
                            return;
                        }
                        var head = queue.peek();
                        if (head == null) {
                            changed.await();
                            continue;
                        }
                        var wait = head.due - clock.nanos();
                        if (wait > 0) {
                            changed.awaitNanos(wait);
                            continue;
                        }
                        next = queue.poll();
                        break;
                    }
                } catch (InterruptedException exception) {
                    return;
                } finally {
                    lock.unlock();
                }
                if (!next.cancelled) {
                    try {
                        next.task.run();
                    } catch (RuntimeException exception) {
                        if (LOGGER.isLoggable(Level.WARNING)) {
                            LOGGER.log(Level.WARNING, "an ICE timer task failed", exception);
                        }
                    }
                }
            }
        }

        @Override
        public void close() {
            lock.lock();
            try {
                closed = true;
                queue.clear();
                changed.signalAll();
            } finally {
                lock.unlock();
            }
        }

        /// A queued task.
        private static final class Task implements Comparable<Task> {
            /// The due time.
            private final long due;

            /// The schedule order.
            private final long sequence;

            /// The task.
            private final Runnable task;

            /// Whether the task was cancelled.
            private volatile boolean cancelled;

            /// Creates a task.
            Task(long due, long sequence, Runnable task) {
                this.due = due;
                this.sequence = sequence;
                this.task = task;
            }

            @Override
            public int compareTo(Task other) {
                var byDue = Long.compare(due - other.due, 0);
                return byDue != 0 ? byDue : Long.compare(sequence, other.sequence);
            }
        }
    }
}
