package com.github.auties00.parley.stun;

import com.github.auties00.parley.net.MonotonicClock;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;

/// The STUN client transactions outstanding on one transport, matched to their responses by transaction id.
///
/// A thread runs a transaction with [#execute(StunMessage,Transmitter,StunRetransmission,Predicate)], which sends the
/// request through a [Transmitter], retransmits it on the [StunRetransmission] schedule and blocks until a response
/// arrives or the schedule ends. The transport's reading thread hands every response it receives to
/// [#complete(StunMessage)], which wakes the matching transaction.
///
/// A response is accepted only when it passes the transaction's authenticator (typically
/// [StunMessage#verifyIntegrity(StunKey)]) and carries no comprehension-required attribute Parley does not
/// understand, as RFC 8489 section 6.3.3 and 9.2.5 require. A rejected response over an unreliable transport is
/// dropped and the retransmissions continue; over a reliable transport it ends the transaction with a
/// [StunIntegrityException].
///
/// {@snippet lang = java :
/// var transactions = new StunClientTransactions(MonotonicClock.system());
/// // on the reader thread: if (StunMessage.isStun(packet)) transactions.complete(StunMessage.decode(packet));
/// var request = StunMessage.request(StunMethod.BINDING, List.of());
/// var datagram = request.encode(true);
/// var response = transactions.execute(request,
///         () -> endpoint.send(datagram.duplicate(), server),
///         StunRetransmission.UDP,
///         _ -> true);
/// }
///
/// # Threading
///
/// Safe for use by several threads at once; each transaction blocks only the thread that runs it.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public final class StunClientTransactions implements AutoCloseable {
    /// The outstanding transactions by transaction id.
    private final Map<StunTransactionId, Pending> pending = new ConcurrentHashMap<>();

    /// The clock round-trip times are measured with.
    private final MonotonicClock clock;

    /// Whether [#close()] ran.
    private volatile boolean closed;

    /// Creates an empty transaction table.
    ///
    /// @param clock the clock round-trip times are measured with
    public StunClientTransactions(MonotonicClock clock) {
        this.clock = Objects.requireNonNull(clock, "clock cannot be null");
    }

    /// Runs a client transaction and returns its response.
    ///
    /// The request is transmitted at once and then on `schedule`, blocking the calling thread until a response
    /// passes `authenticator` or the schedule ends. The response may be a success or an error; the caller inspects
    /// it. The transaction ends either way: a response that arrives later is not matched.
    ///
    /// @param request       the request, whose transaction id must not be outstanding
    /// @param transmitter   sends the encoded request once; called for every transmission
    /// @param schedule      the retransmission schedule
    /// @param authenticator accepts a response, called on the reading thread while the response's buffer is valid;
    ///                      `_ -> true` for an unauthenticated request
    /// @return the response
    /// @throws StunTimeoutException    if no response arrived
    /// @throws StunIntegrityException  if responses arrived but none passed `authenticator`
    /// @throws IOException             if a transmission failed, or the table was closed
    /// @throws InterruptedException    if the calling thread was interrupted while waiting
    /// @throws IllegalArgumentException if `request` is not a request or its transaction is already outstanding
    public StunResponse execute(StunMessage request, Transmitter transmitter, StunRetransmission schedule,
                                Predicate<StunMessage> authenticator) throws IOException, InterruptedException {
        Objects.requireNonNull(request, "request cannot be null");
        Objects.requireNonNull(transmitter, "transmitter cannot be null");
        Objects.requireNonNull(schedule, "schedule cannot be null");
        Objects.requireNonNull(authenticator, "authenticator cannot be null");
        if (request.messageClass() != StunClass.REQUEST) {
            throw new IllegalArgumentException("not a request: " + request);
        }
        if (closed) {
            throw new IOException("the STUN transactions are closed");
        }
        var transaction = new Pending(schedule.reliable(), authenticator);
        if (pending.putIfAbsent(request.transactionId(), transaction) != null) {
            throw new IllegalArgumentException("transaction already outstanding: " + request.transactionId());
        }
        try {
            for (var transmission = 0; transmission < schedule.maxTransmissions(); transmission++) {
                var sentAt = clock.nanos();
                transmitter.transmit();
                var response = transaction.await(schedule.waitAfter(transmission));
                if (response != null) {
                    return new StunResponse(response, Duration.ofNanos(Math.max(0, clock.nanos() - sentAt)), transmission + 1);
                }
            }
            if (transaction.rejected) {
                throw new StunIntegrityException("every response to " + request.method() + " failed authentication");
            }
            throw new StunTimeoutException(request.method() + " request timed out after " + schedule.totalTimeout().toMillis() + " ms");
        } finally {
            pending.remove(request.transactionId());
        }
    }

    /// Offers a received response to the outstanding transactions.
    ///
    /// Called on the reading thread for every STUN response it decodes. The response is copied when a transaction
    /// accepts it, so the caller's buffer may be reused once the call returns.
    ///
    /// @param response the response
    /// @return `true` if the response matched an outstanding transaction (whether or not it was accepted); `false`
    ///         if it matched none or is not a response
    public boolean complete(StunMessage response) {
        Objects.requireNonNull(response, "response cannot be null");
        if (!response.messageClass().isResponse()) {
            return false;
        }
        var transaction = pending.get(response.transactionId());
        if (transaction == null) {
            return false;
        }
        transaction.offer(response);
        return true;
    }

    /// {@return whether a transaction with `transactionId` is outstanding}
    ///
    /// @param transactionId the transaction id
    public boolean isPending(StunTransactionId transactionId) {
        return pending.containsKey(transactionId);
    }

    /// Fails every outstanding transaction with an [IOException] and refuses new ones. Calling it again has no
    /// effect.
    @Override
    public void close() {
        closed = true;
        pending.values().forEach(Pending::abort);
    }

    /// Sends the encoded request of a transaction once.
    @FunctionalInterface
    public interface Transmitter {
        /// Sends the request.
        ///
        /// @throws IOException if the request cannot be sent; the transaction fails with it
        void transmit() throws IOException;
    }

    /// One outstanding transaction.
    private static final class Pending {
        /// The lock guarding the fields below.
        private final ReentrantLock lock = new ReentrantLock();

        /// Signalled when [#response] is set or the transaction is aborted.
        private final Condition done = lock.newCondition();

        /// Whether the transport is reliable.
        private final boolean reliable;

        /// The authenticator of responses.
        private final Predicate<StunMessage> authenticator;

        /// The accepted response, owning its bytes; guarded by [#lock].
        private StunMessage response;

        /// The failure that ends the transaction early; guarded by [#lock].
        private IOException failure;

        /// Whether a response was rejected; guarded by [#lock].
        private boolean rejected;

        /// Creates a transaction.
        Pending(boolean reliable, Predicate<StunMessage> authenticator) {
            this.reliable = reliable;
            this.authenticator = authenticator;
        }

        /// Checks a response and wakes the waiting thread when it is accepted or ends the transaction.
        void offer(StunMessage message) {
            var accepted = message.unknownComprehensionRequired().isEmpty() && test(message);
            lock.lock();
            try {
                if (response != null || failure != null) {
                    return;
                }
                if (accepted) {
                    response = message.copy();
                    done.signalAll();
                } else {
                    rejected = true;
                    if (reliable) {
                        failure = new StunIntegrityException("the response failed authentication");
                        done.signalAll();
                    }
                }
            } finally {
                lock.unlock();
            }
        }

        /// {@return the authenticator's verdict, `false` when it throws}
        private boolean test(StunMessage message) {
            try {
                return authenticator.test(message);
            } catch (RuntimeException exception) {
                return false;
            }
        }

        /// Ends the transaction because the table closed.
        void abort() {
            lock.lock();
            try {
                if (failure == null && response == null) {
                    failure = new IOException("the STUN transactions were closed");
                    done.signalAll();
                }
            } finally {
                lock.unlock();
            }
        }

        /// {@return the accepted response, or `null` when `timeout` elapsed first}
        ///
        /// @throws IOException          if the transaction ended with a failure
        /// @throws InterruptedException if the thread was interrupted
        StunMessage await(Duration timeout) throws IOException, InterruptedException {
            var nanos = timeout.toNanos();
            lock.lock();
            try {
                while (response == null && failure == null && nanos > 0) {
                    nanos = done.awaitNanos(nanos);
                }
                if (failure != null) {
                    throw failure;
                }
                return response;
            } finally {
                lock.unlock();
            }
        }
    }
}
