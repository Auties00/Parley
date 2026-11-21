package com.github.auties00.parley.ice;

import com.github.auties00.parley.stun.StunMessage;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/// Runs the ICE connectivity checks of one UDP component, with RTP and RTCP multiplexed on it, as a full agent.
///
/// The agent owns no socket: it sends through a [DatagramSender], and the owner of the socket feeds it every STUN
/// message the socket receives through [#handle(StunMessage,InetSocketAddress)]. The two roles select a pair
/// differently:
///
/// - As the controlling agent it nominates aggressively: every check carries `USE-CANDIDATE`, and the first remote
///   candidate that answers with a valid response becomes the selected pair. This is how a full agent talks to an
///   `ice-lite` peer, which never sends checks of its own.
/// - As the controlled agent it answers checks and selects the source of the first valid check that carries
///   `USE-CANDIDATE`; the checks it sends itself only open its NAT bindings.
///
/// Requests from the peer are answered with `XOR-MAPPED-ADDRESS`, `MESSAGE-INTEGRITY` keyed with the local password
/// and `FINGERPRINT`; a request whose `USERNAME` does not start with the local fragment or whose integrity does not
/// verify is dropped. Role conflicts are not resolved: an agent keeps the role it was created with.
///
/// After selection, [#refreshConsent()] sends the consent freshness checks of RFC 7675, and [#lastConsentNanos()]
/// tells when the peer last proved that it still wants the traffic; the caller decides when consent has expired.
///
/// # Threading
///
/// [#handle(StunMessage,InetSocketAddress)] may run on the socket's receive thread while another thread blocks in
/// [#nominate(List,Duration)] or calls [#refreshConsent()]; all methods are safe for concurrent use. The agent
/// starts no thread of its own.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc5245.html RFC 5245: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal for Offer/Answer Protocols
/// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
public final class IceAgent {
    /// The pacing interval between two checks, the 50 ms RFC 8445 section 14.2 recommends.
    private static final long PACING_NANOS = TimeUnit.MILLISECONDS.toNanos(50);

    /// The retransmission interval of a check to the same candidate.
    private static final long RETRANSMIT_NANOS = TimeUnit.MILLISECONDS.toNanos(200);

    /// The local preference written into the `PRIORITY` attribute, the highest there is.
    private static final int LOCAL_PREFERENCE = 65535;

    /// The sender the agent writes STUN messages through.
    private final DatagramSender sender;

    /// The local credentials, which key the responses and the integrity check of requests.
    private final IceCredentials local;

    /// The remote credentials, which key the checks and the integrity check of responses.
    private final IceCredentials remote;

    /// Whether this agent is the controlling one.
    private final boolean controlling;

    /// The tie-breaker of the role attributes.
    private final long tieBreaker;

    /// The target of each outstanding check, keyed by transaction id in hex.
    private final Map<String, InetSocketAddress> pending = new ConcurrentHashMap<>();

    /// The lock that guards [#selected] and wakes [#nominate(List,Duration)].
    private final Object lock = new Object();

    /// The selected remote address, or `null` before selection; guarded by [#lock].
    private InetSocketAddress selected;

    /// The [System#nanoTime()] of the last valid response or request from the selected peer.
    private volatile long lastConsentNanos;

    /// Creates an agent; it sends nothing until [#nominate(List,Duration)] or [#handle(StunMessage,InetSocketAddress)]
    /// is called.
    ///
    /// @param local       the local credentials, advertised in this side's session description
    /// @param remote      the remote credentials, from the peer's session description
    /// @param controlling whether this agent is the controlling one
    /// @param sender      the sender of outgoing STUN messages
    public IceAgent(IceCredentials local, IceCredentials remote, boolean controlling, DatagramSender sender) {
        this.local = Objects.requireNonNull(local, "local cannot be null");
        this.remote = Objects.requireNonNull(remote, "remote cannot be null");
        this.sender = Objects.requireNonNull(sender, "sender cannot be null");
        this.controlling = controlling;
        this.tieBreaker = new SecureRandom().nextLong();
    }

    /// Runs the connectivity checks until a pair is selected, and returns the selected remote address.
    ///
    /// Sends a check to each candidate address in turn, paced 50 ms apart and repeated every 200 ms per candidate.
    /// As the controlling agent the checks carry `USE-CANDIDATE` and the first valid response selects its candidate;
    /// as the controlled agent they do not, and the call waits for the peer's nomination. Either way the call blocks
    /// until a pair is selected or the timeout elapses. A send that fails is skipped and retried with the next round.
    ///
    /// @param candidates the remote candidate addresses, in priority order; each must be resolved
    /// @param timeout    the longest time to wait
    /// @return the selected remote address
    /// @throws IceException         if `candidates` is empty, or no pair is selected within the timeout
    /// @throws InterruptedException if the calling thread is interrupted while waiting
    public InetSocketAddress nominate(List<InetSocketAddress> candidates, Duration timeout)
            throws IceException, InterruptedException {
        Objects.requireNonNull(candidates, "candidates cannot be null");
        if (candidates.isEmpty()) {
            throw new IceException("the remote description carries no usable candidate");
        }
        var targets = new ArrayList<>(candidates);
        var deadline = System.nanoTime() + timeout.toNanos();
        var lastSent = new long[targets.size()];
        var next = 0;
        while (true) {
            synchronized (lock) {
                if (selected != null) {
                    return selected;
                }
            }
            var now = System.nanoTime();
            if (now - deadline >= 0) {
                throw new IceException("no ICE candidate pair succeeded within " + timeout.toMillis() + " ms");
            }
            var index = next++ % targets.size();
            if (lastSent[index] == 0 || now - lastSent[index] >= RETRANSMIT_NANOS) {
                lastSent[index] = now;
                sendCheck(targets.get(index), controlling);
            }
            synchronized (lock) {
                if (selected == null) {
                    TimeUnit.NANOSECONDS.timedWait(lock, Math.min(PACING_NANOS, Math.max(1, deadline - now)));
                }
            }
        }
    }

    /// Handles a STUN message received on the component.
    ///
    /// Answers a valid Binding request, records a valid Binding success response to one of this agent's checks,
    /// forgets the check a Binding error response answers, and ignores everything else. Handling a message may
    /// select a pair and wake a thread blocked in [#nominate(List,Duration)].
    ///
    /// @param message the decoded message
    /// @param source  the address it came from
    /// @return `true` if the message was a valid Binding request or a response to an outstanding check of this
    ///         agent; `false` if it was ignored
    public boolean handle(StunMessage message, InetSocketAddress source) {
        return switch (message.type()) {
            case StunMessage.BINDING_REQUEST -> handleRequest(message, source);
            case StunMessage.BINDING_SUCCESS -> handleSuccess(message, source);
            case StunMessage.BINDING_ERROR -> pending.remove(key(message)) != null;
            default -> false;
        };
    }

    /// Sends one consent freshness check to the selected address; does nothing before a pair is selected.
    ///
    /// A valid answer updates [#lastConsentNanos()]. RFC 7675 asks for a check every five seconds on average, with
    /// jitter; the caller schedules them.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
    public void refreshConsent() {
        var target = selected().orElse(null);
        if (target != null) {
            sendCheck(target, false);
        }
    }

    /// {@return the selected remote address, or an empty optional before selection}
    public Optional<InetSocketAddress> selected() {
        synchronized (lock) {
            return Optional.ofNullable(selected);
        }
    }

    /// {@return the [System#nanoTime()] at which the selected peer last answered a check or sent a valid request, or
    /// `0` before selection}
    ///
    /// Selection itself counts as consent.
    public long lastConsentNanos() {
        return lastConsentNanos;
    }

    /// Sends one Binding request to `target`, with `USE-CANDIDATE` when `useCandidate` is set, and records it as
    /// outstanding; a send failure only forgets it.
    private void sendCheck(InetSocketAddress target, boolean useCandidate) {
        var request = StunMessage.create(StunMessage.BINDING_REQUEST)
                .add(StunMessage.USERNAME, remote.ufrag() + ":" + local.ufrag())
                .addInt(StunMessage.PRIORITY, IceCandidate.peerReflexivePriority(LOCAL_PREFERENCE))
                .addLong(controlling ? StunMessage.ICE_CONTROLLING : StunMessage.ICE_CONTROLLED, tieBreaker);
        if (useCandidate) {
            request.add(StunMessage.USE_CANDIDATE, new byte[0]);
        }
        pending.put(key(request), target);
        try {
            sender.send(request.encode(remote.key(), true), target);
        } catch (IOException exception) {
            pending.remove(key(request));
        }
    }

    /// Answers a Binding request from the peer, selecting its source as the controlled agent when it nominates.
    ///
    /// @return `true` if the request was valid; a valid request whose answer could not be sent still counts
    private boolean handleRequest(StunMessage request, InetSocketAddress source) {
        var username = request.stringAttribute(StunMessage.USERNAME).orElse("");
        if (!username.startsWith(local.ufrag() + ":") || !request.verifyIntegrity(local.key())) {
            return false;
        }
        var response = StunMessage.response(StunMessage.BINDING_SUCCESS, request)
                .addXorMappedAddress(source);
        try {
            sender.send(response.encode(local.key(), true), source);
        } catch (IOException exception) {
            return true;
        }
        synchronized (lock) {
            if (selected == null && !controlling && request.has(StunMessage.USE_CANDIDATE)) {
                select(source);
            } else if (source.equals(selected)) {
                lastConsentNanos = System.nanoTime();
            }
        }
        return true;
    }

    /// Records a Binding success response to one of this agent's checks, selecting its source as the controlling
    /// agent.
    ///
    /// @return `true` if the response came from the checked address and answered an outstanding check with valid
    ///         integrity
    private boolean handleSuccess(StunMessage response, InetSocketAddress source) {
        var target = pending.get(key(response));
        if (target == null || !target.equals(source) || !response.verifyIntegrity(remote.key())) {
            return false;
        }
        pending.remove(key(response));
        synchronized (lock) {
            if (selected == null && controlling) {
                select(source);
            } else if (source.equals(selected)) {
                lastConsentNanos = System.nanoTime();
            }
        }
        return true;
    }

    /// Selects a remote address and wakes the nominating thread; the caller holds [#lock].
    private void select(InetSocketAddress source) {
        selected = source;
        lastConsentNanos = System.nanoTime();
        lock.notifyAll();
    }

    /// {@return the map key of a message's transaction, its id in hex}
    private static String key(StunMessage message) {
        return HexFormat.of().formatHex(message.transactionId());
    }

    /// Sends a datagram on the socket of the agent's component.
    ///
    /// The agent calls it from the thread that runs [IceAgent#nominate(List,Duration)],
    /// [IceAgent#handle(StunMessage,InetSocketAddress)] or [IceAgent#refreshConsent()], so an implementation is
    /// called concurrently and should not block for long.
    @FunctionalInterface
    public interface DatagramSender {
        /// Sends a datagram.
        ///
        /// @param data   the datagram, which the implementation may keep
        /// @param target the destination
        /// @throws IOException if the socket cannot send; the agent treats the datagram as lost
        void send(byte[] data, InetSocketAddress target) throws IOException;
    }
}
