package com.github.auties00.parley.ice;

import com.github.auties00.parley.ice.IcePath.RelayPath;
import com.github.auties00.parley.ice.IcePath.TcpActivePath;
import com.github.auties00.parley.ice.IcePath.TcpLink;
import com.github.auties00.parley.ice.IcePath.TcpPassivePath;
import com.github.auties00.parley.ice.IcePath.UdpPath;
import com.github.auties00.parley.mdns.MdnsResolver;
import com.github.auties00.parley.mdns.MdnsResponder;
import com.github.auties00.parley.net.DatagramEndpoint;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.net.NetworkInterfaceAddress;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.net.PacketReceiver;
import com.github.auties00.parley.stun.StunAddressFamily;
import com.github.auties00.parley.stun.StunAttribute;
import com.github.auties00.parley.stun.StunAttribute.ErrorCode;
import com.github.auties00.parley.stun.StunAttribute.IceControlled;
import com.github.auties00.parley.stun.StunAttribute.IceControlling;
import com.github.auties00.parley.stun.StunAttribute.Priority;
import com.github.auties00.parley.stun.StunAttribute.UseCandidate;
import com.github.auties00.parley.stun.StunAttribute.Username;
import com.github.auties00.parley.stun.StunAttribute.XorMappedAddress;
import com.github.auties00.parley.stun.StunClass;
import com.github.auties00.parley.stun.StunClientTransactions;
import com.github.auties00.parley.stun.StunFormatException;
import com.github.auties00.parley.stun.StunIntegrity;
import com.github.auties00.parley.stun.StunKey;
import com.github.auties00.parley.stun.StunMessage;
import com.github.auties00.parley.stun.StunMethod;
import com.github.auties00.parley.stun.StunRetransmission;
import com.github.auties00.parley.stun.StunServer;
import com.github.auties00.parley.stun.StunTransactionId;
import com.github.auties00.parley.turn.TurnAllocationOptions;
import com.github.auties00.parley.turn.TurnClient;
import com.github.auties00.parley.turn.TurnCredentials;
import com.github.auties00.parley.turn.TurnException;
import com.github.auties00.parley.turn.TurnServer;
import com.github.auties00.parley.turn.TurnTransport;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Predicate;

/// An ICE agent for one component, full or lite, that gathers candidates, runs connectivity checks, selects a pair
/// and then carries datagrams over it.
///
/// # Lifecycle
///
/// {@snippet lang = java :
/// var agent = IceAgent.builder()
///         .iceServers(List.of(IceServer.of("stun:stun.example.org")))
///         .role(IceRole.CONTROLLING)
///         .receiver((packet, arrival) -> handle(packet))   // set before any datagram can arrive
///         .eventListener(event -> {
///             if (event instanceof IceEvent.CandidateGathered(var candidate, var server)) {
///                 signaling.send(candidate.toSdp());
///             }
///         })
///         .build();
/// agent.gather();                                   // trickles candidates through the listener
/// agent.setRemoteParameters(remoteParameters);      // from the peer's a=ice-ufrag/a=ice-pwd
/// remoteCandidates.forEach(agent::addRemoteCandidate);
/// agent.endOfRemoteCandidates();
/// if (!agent.awaitConnected(Duration.ofSeconds(10))) {
///     throw new IOException("ICE timed out");
/// }
/// agent.send(datagram);
/// }
///
/// [#gather()] starts gathering in the background: host candidates on every usable interface (UDP, and TCP when
/// enabled), server-reflexive candidates from `stun:` servers (and, with TCP candidates, active TCP server-reflexive
/// ones from `stuns:` servers, whose binding runs over TLS) and relayed candidates from `turn:` and `turns:`
/// servers, each reported by an [IceEvent.CandidateGathered] as soon as it exists (trickle ICE), then
/// [IceEvent.GatheringStateChanged] with [IceGatheringState#COMPLETE]. Checks start as soon as the remote parameters
/// and a remote candidate are known, whether or not gathering finished. [#close()] stops everything, deletes TURN
/// allocations and closes every socket.
///
/// # Connectivity checks
///
/// A full agent forms candidate pairs (same family, matching protocol and TCP direction, at most 100), orders them by
/// pair priority, and unfreezes them by foundation as RFC 8445 section 6.1.2.6 describes. It sends one check every
/// `Ta` (50 ms), triggered checks first, retransmitting over UDP on the STUN schedule. Requests from the peer are
/// answered at once and trigger a check of their pair; a request from an unknown address creates a peer-reflexive
/// remote candidate, and a response that reveals an unknown mapped address a peer-reflexive local one. Role
/// conflicts are resolved by the tie-breakers, with 487 Role Conflict errors as section 7.3.1.1 requires.
///
/// The controlling agent nominates with regular nomination: once the best pair it can expect has succeeded (or half
/// a second after the first valid pair), it repeats the check on the best valid pair with `USE-CANDIDATE`. Before
/// that nomination completes it already sends on the best valid pair. The controlled agent selects the
/// highest-priority pair the peer nominated; a peer that nominates aggressively (every check with `USE-CANDIDATE`)
/// is handled the same way.
///
/// A lite agent ([Builder#lite(boolean)]) gathers host candidates only, sends no checks, is always controlled, and
/// selects the pair a nominating check arrives on.
///
/// # Untrusted input
///
/// Remote candidates come from signaling and peer-reflexive ones from connectivity checks: at most
/// [#MAX_REMOTE_CANDIDATES] are kept per ICE generation, and the rest are dropped and counted in
/// [IceTransportStatistics#remoteCandidatesDropped()]. At most [#MAX_PENDING_RESOLUTIONS] `.local` names wait for
/// multicast DNS at once, each resolved once however many candidates carry it, by one resolver thread.
///
/// # Consent and restart
///
/// Once a pair is selected, a full agent sends a consent check every four to six seconds (RFC 7675); after ten
/// seconds without an answer the state turns [IceTransportState#DISCONNECTED], and after thirty consent expires:
/// the agent stops sending on the pair and falls back to another valid pair or turns
/// [IceTransportState#FAILED]. [#restart(IceParameters)] starts an ICE restart with new local parameters; the
/// selected pair keeps carrying data (and consent) under the old credentials until a pair of the new generation is
/// selected.
///
/// # Threading
///
/// Every thread comes from the [NetworkStack#threadFactory()] of the agent's stack: one reader per socket and TCP
/// connection, one timer that runs checks and consent, one dispatcher that delivers events serially, and short-lived
/// threads for gathering, the mDNS resolver thread and ICE-TCP connects. Every public method is safe for concurrent
/// use and returns without waiting on the network, except [#awaitConnected(Duration)] and [#send(ByteBuffer)].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc8421.html RFC 8421: Guidelines for Multihomed and IPv4/IPv6 Dual-Stack Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8838.html RFC 8838: Trickle ICE: Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (ICE) Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc7675.html RFC 7675: Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness
/// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03 draft-ietf-mmusic-mdns-ice-candidates-03: Using Multicast DNS to protect privacy when exposing ICE candidates
public final class IceAgent implements IceTransport {
    /// The logger of the agent.
    private static final System.Logger LOGGER = System.getLogger(IceAgent.class.getName());

    /// The component every candidate belongs to: WebRTC multiplexes RTP and RTCP.
    private static final int COMPONENT = 1;

    /// The most candidate pairs a checklist holds (RFC 8445 section 6.1.2.5).
    private static final int MAX_PAIRS = 100;

    /// The most remote candidates, signalled and peer-reflexive, kept per ICE generation.
    public static final int MAX_REMOTE_CANDIDATES = 100;

    /// The most `.local` names that wait for multicast DNS resolution at once.
    public static final int MAX_PENDING_RESOLUTIONS = 32;

    /// The type preference of an active TCP server-reflexive candidate, below UDP server-reflexive ones.
    private static final int TCP_SRFLX_TYPE_PREFERENCE = 70;

    /// The source of the mDNS candidate error reported when the responder cannot be opened.
    static final URI MDNS_SERVER = URI.create("mdns:224.0.0.251:5353");

    /// The datagram budget before a pair is selected, small enough for any path.
    private static final int DEFAULT_MAX_DATAGRAM = 1200;

    /// The type preference of TCP host candidates, below UDP host and server-reflexive candidates.
    private static final int TCP_HOST_TYPE_PREFERENCE = 90;

    /// The type preference of TCP peer-reflexive candidates.
    private static final int TCP_PRFLX_TYPE_PREFERENCE = 80;

    /// The port of an active TCP candidate (RFC 6544 section 4.5).
    private static final int ACTIVE_TCP_PORT = 9;

    /// The largest datagram a reader accepts.
    private static final int MAX_DATAGRAM = 0x10000;

    /// The network stack.
    private final NetworkStack stack;

    /// The clock of every timer and timestamp.
    private final MonotonicClock clock;

    /// The STUN and TURN servers.
    private final List<IceServer> servers;

    /// The candidate policy.
    private final IceTransportPolicy transportPolicy;

    /// How host candidates are exposed.
    private final HostCandidatePolicy hostPolicy;

    /// Whether this agent is lite.
    private final boolean lite;

    /// Whether TCP host candidates are gathered.
    private final boolean tcpCandidates;

    /// Whether loopback addresses are used when others exist.
    private final boolean loopback;

    /// Whether link-local addresses are used.
    private final boolean linkLocal;

    /// Whether virtual interfaces are used.
    private final boolean virtualInterfaces;

    /// The application filter of host addresses.
    private final Predicate<NetworkInterfaceAddress> addressFilter;

    /// The listener of events.
    private final Consumer<IceEvent> listener;

    /// The timer.
    private final IceScheduler scheduler;

    /// The timing constants.
    private final IceTimers timers;

    /// Opens the mDNS responder on first use.
    private final MdnsFactory mdnsFactory;

    /// The tie-breaker of role conflicts, compared as unsigned.
    private final long tieBreaker;

    /// The lock that guards the agent state below.
    private final ReentrantLock lock = new ReentrantLock();

    /// Signalled when [#state] changes.
    private final Condition stateChanged = lock.newCondition();

    /// The role; guarded by [#lock].
    private IceRole role;

    /// The local parameters; guarded by [#lock].
    private IceParameters localParameters;

    /// The remote parameters, or `null` before they are set; guarded by [#lock].
    private IceParameters remoteParameters;

    /// The local parameters of the generation before an ICE restart, while its pair is retained; guarded by
    /// [#lock].
    private IceParameters retainedLocal;

    /// The remote parameters of the generation before an ICE restart; guarded by [#lock].
    private IceParameters retainedRemote;

    /// The transport state; guarded by [#lock].
    private IceTransportState state = IceTransportState.NEW;

    /// The gathering state; guarded by [#lock].
    private IceGatheringState gatheringState = IceGatheringState.NEW;

    /// Whether gathering runs; guarded by [#lock].
    private boolean gatheringStarted;

    /// Whether gathered candidates are held back (a candidate pool before [#gather()]); guarded by [#lock].
    private boolean pooling;

    /// The events held back while pooling; guarded by [#lock].
    private final List<IceEvent> pooledEvents = new ArrayList<>();

    /// The gathering tasks still running; guarded by [#lock].
    private int pendingGatherTasks;

    /// Whether the peer signalled the end of its candidates; guarded by [#lock].
    private boolean remoteEndOfCandidates;

    /// The local candidates, pairable and server-reflexive; guarded by [#lock].
    private final List<LocalCandidate> locals = new ArrayList<>();

    /// The remote candidates with a usable address; guarded by [#lock].
    private final List<RemoteCandidate> remotes = new ArrayList<>();

    /// The remote candidates by address and protocol, the index of [#remotes]; guarded by [#lock].
    private final Map<RemoteKey, RemoteCandidate> remoteIndex = new HashMap<>();

    /// The remote candidates dropped because the generation already held [#MAX_REMOTE_CANDIDATES], or because the
    /// resolution queue was full; guarded by [#lock].
    private long remoteCandidatesDropped;

    /// The `.local` candidates waiting for resolution, by lower-cased name, in arrival order; guarded by [#lock].
    private final Map<String, List<IceCandidate>> pendingResolutions = new java.util.LinkedHashMap<>();

    /// Whether the resolver thread runs; guarded by [#lock].
    private boolean resolving;

    /// The DSCP value of the sockets, from [#setTrafficClass(int)]; guarded by [#lock].
    private int trafficClass;

    /// The checklist, highest priority first after [#sortPairs()]; guarded by [#lock].
    private final List<CheckPair> pairs = new ArrayList<>();

    /// The triggered-check queue; guarded by [#lock].
    private final ArrayDeque<CheckPair> triggered = new ArrayDeque<>();

    /// The outstanding checks by transaction id; guarded by [#lock].
    private final Map<StunTransactionId, Check> checks = new HashMap<>();

    /// Whether the pacing task is scheduled; guarded by [#lock].
    private boolean ticking;

    /// When the first valid pair appeared, or `-1`; guarded by [#lock].
    private long firstValidNanos = -1;

    /// Whether the nomination timer is scheduled; guarded by [#lock].
    private boolean nominationScheduled;

    /// Whether the checklist concluded: a nominated pair is selected, so no new ordinary pair is checked (RFC 8445
    /// section 8.1.2); guarded by [#lock].
    private boolean concluded;

    /// The pair the controlling agent is nominating, or `null`; guarded by [#lock].
    private CheckPair nominating;

    /// The pair selected before an ICE restart, kept until the new generation selects one; guarded by [#lock].
    private CheckPair retained;

    /// How many times the selected pair changed; guarded by [#lock].
    private long selectedChanges;

    /// The foundations by candidate kind; guarded by [#lock].
    private final Map<String, String> foundations = new HashMap<>();

    /// Whether [#close()] ran; guarded by [#lock].
    private boolean closed;

    /// The pair datagrams are sent on.
    private volatile CheckPair selected;

    /// The receiver of application datagrams, `null` when none is set.
    private volatile PacketReceiver receiver;

    /// The pair each (local candidate, remote address) routes to, for the reading threads.
    private final Map<PairKey, CheckPair> routes = new ConcurrentHashMap<>();

    /// The version of [#routes], incremented after every change, so a cached route is used only while it is current.
    private final AtomicInteger routesVersion = new AtomicInteger();

    /// The route the last application datagram took, or `null`: media arrives from one remote address on one local
    /// candidate, so this spares a lookup key per datagram.
    private volatile CachedRoute lastRoute;

    /// Datagrams queued under the lock and sent after it is released.
    private final ConcurrentLinkedQueue<Outgoing> outgoing = new ConcurrentLinkedQueue<>();

    /// The STUN transactions of server-reflexive gathering.
    private final StunClientTransactions gatherTransactions;

    /// The events waiting for the dispatcher.
    private final LinkedBlockingQueue<Optional<IceEvent>> events = new LinkedBlockingQueue<>();

    /// The sockets, listeners, connections and TURN clients to close; guarded by [#lock].
    private final List<AutoCloseable> resources = new ArrayList<>();

    /// The mDNS responder, or `null` before first use; guarded by [#lock].
    private MdnsResponder responder;

    /// Whether opening the mDNS responder failed; guarded by [#lock].
    private boolean responderFailed;

    /// The mDNS resolver, or `null` before first use; guarded by [#lock].
    private MdnsResolver resolver;

    /// Creates an agent from a builder and starts its timer and dispatcher.
    private IceAgent(Builder builder) {
        this.stack = builder.stack != null ? builder.stack : NetworkStack.system(Thread.ofVirtual().name("parley-ice-", 0).factory());
        this.clock = builder.clock;
        this.servers = List.copyOf(builder.servers);
        this.transportPolicy = builder.transportPolicy;
        this.hostPolicy = builder.hostPolicy;
        this.lite = builder.lite;
        this.tcpCandidates = builder.tcpCandidates;
        this.loopback = builder.loopback;
        this.linkLocal = builder.linkLocal;
        this.virtualInterfaces = builder.virtualInterfaces;
        this.addressFilter = builder.addressFilter;
        this.listener = builder.listener;
        this.receiver = builder.receiver;
        this.timers = builder.timers;
        this.mdnsFactory = builder.mdnsFactory != null ? builder.mdnsFactory : MdnsFactory.multicast(stack);
        this.role = builder.lite ? IceRole.CONTROLLED : builder.role;
        this.localParameters = builder.localParameters != null
                ? new IceParameters(builder.localParameters.usernameFragment(), builder.localParameters.password(), builder.lite)
                : IceParameters.generate(builder.lite);
        this.tieBreaker = new SecureRandom().nextLong();
        this.gatherTransactions = new StunClientTransactions(clock);
        this.scheduler = builder.scheduler != null ? builder.scheduler : new IceScheduler.ThreadScheduler(clock, stack.threadFactory());
        stack.threadFactory().newThread(this::dispatchLoop).start();
        if (builder.candidatePoolSize > 0) {
            lock.lock();
            try {
                pooling = true;
                startGathering();
            } finally {
                lock.unlock();
            }
        }
    }

    /// {@return a builder of agents}
    public static Builder builder() {
        return new Builder();
    }

    /// Starts gathering local candidates in the background and returns at once.
    ///
    /// Candidates are reported by [IceEvent.CandidateGathered] and the end by [IceEvent.GatheringStateChanged] with
    /// [IceGatheringState#COMPLETE]. When the builder asked for a candidate pool, the candidates it already gathered
    /// are reported now. Calling it again, or after an ICE restart re-reported the candidates, has no effect.
    ///
    /// @throws IllegalStateException if the agent is closed
    public void gather() {
        lock.lock();
        try {
            ensureOpen();
            if (pooling) {
                pooling = false;
                var held = List.copyOf(pooledEvents);
                pooledEvents.clear();
                emit(new IceEvent.GatheringStateChanged(IceGatheringState.GATHERING));
                if (gatheringState == IceGatheringState.NEW) {
                    gatheringState = IceGatheringState.GATHERING;
                }
                for (var event : held) {
                    if (event instanceof IceEvent.CandidateGathered(var candidate, var server)) {
                        emit(new IceEvent.CandidateGathered(candidate.withUsernameFragment(localParameters.usernameFragment()), server));
                    }
                }
                if (gatheringState == IceGatheringState.COMPLETE) {
                    emit(new IceEvent.GatheringStateChanged(IceGatheringState.COMPLETE));
                }
                return;
            }
            if (!gatheringStarted) {
                startGathering();
            }
        } finally {
            lock.unlock();
        }
    }

    /// Sets the peer's ICE parameters, from its `a=ice-ufrag`, `a=ice-pwd` and `a=ice-lite`.
    ///
    /// Parameters equal to the current ones change nothing. New parameters after earlier ones mean the peer
    /// restarted ICE: remote candidates of the old generation are dropped and the selected pair is retained until a
    /// new one is selected. When the peer is lite and this agent is full, this agent takes the controlling role.
    ///
    /// @param remote the peer's parameters
    /// @throws IllegalStateException if the agent is closed
    public void setRemoteParameters(IceParameters remote) {
        Objects.requireNonNull(remote, "remote cannot be null");
        lock.lock();
        try {
            ensureOpen();
            if (remoteParameters != null && remoteParameters.sameCredentials(remote)) {
                remoteParameters = remote;
                return;
            }
            if (remoteParameters != null) {
                retainSelected(localParameters, remoteParameters);
                dropGeneration();
            }
            remoteParameters = remote;
            remoteEndOfCandidates = false;
            if (remote.lite() && !lite && role != IceRole.CONTROLLING) {
                changeRole(IceRole.CONTROLLING);
            }
            if (state == IceTransportState.NEW && !pairs.isEmpty()) {
                setState(IceTransportState.CHECKING);
            }
            ensureTicking();
        } finally {
            lock.unlock();
            drainOutgoing();
        }
    }

    /// Adds a remote candidate, at any time (trickle ICE).
    ///
    /// A candidate whose `ufrag` names another generation than the remote parameters is ignored, as are candidates of
    /// another component, FQDN addresses, simultaneous-open TCP candidates and, under the relay policy, `.local`
    /// candidates. A `.local` candidate is resolved with multicast DNS in the background and paired once resolved; a
    /// name already waiting is not queried again, and a candidate beyond [#MAX_PENDING_RESOLUTIONS] waiting names or
    /// [#MAX_REMOTE_CANDIDATES] candidates of the generation is dropped and counted.
    ///
    /// @param candidate the candidate
    /// @throws IllegalStateException if the agent is closed
    public void addRemoteCandidate(IceCandidate candidate) {
        Objects.requireNonNull(candidate, "candidate cannot be null");
        lock.lock();
        try {
            ensureOpen();
            if (candidate.component() != COMPONENT || candidate.tcpType().orElse(null) == IceTcpType.SO) {
                return;
            }
            if (candidate.usernameFragment().isPresent() && remoteParameters != null
                    && !candidate.usernameFragment().get().equals(remoteParameters.usernameFragment())) {
                return;
            }
            if (candidate.protocol() == IceProtocol.TCP && !tcpCandidates) {
                return;
            }
            var address = candidate.socketAddress();
            if (address.isPresent()) {
                addRemote(candidate, address.get());
                return;
            }
            if (!candidate.isMdns() || transportPolicy == IceTransportPolicy.RELAY || !MdnsResolver.isIceName(candidate.address())) {
                return;
            }
            queueResolution(candidate);
        } finally {
            lock.unlock();
            drainOutgoing();
        }
    }

    /// Records that the peer will send no more candidates (`a=end-of-candidates`).
    ///
    /// Without it the agent never turns [IceTransportState#FAILED] or [IceTransportState#COMPLETED], since a
    /// candidate that works may still arrive.
    public void endOfRemoteCandidates() {
        lock.lock();
        try {
            remoteEndOfCandidates = true;
            updateState();
        } finally {
            lock.unlock();
        }
    }

    /// Starts an ICE restart with new local parameters.
    ///
    /// The local candidates are reported again with the new username fragment (gathering goes back to
    /// [IceGatheringState#GATHERING] and then [IceGatheringState#COMPLETE]); the remote parameters are cleared until
    /// [#setRemoteParameters(IceParameters)] supplies the peer's new ones. The selected pair keeps carrying data,
    /// and consent checks under the old credentials, until a pair of the new generation is selected.
    ///
    /// @param newLocal the new local parameters, which must differ from the current ones
    /// @throws IllegalArgumentException if `newLocal` has the current username fragment and password
    /// @throws IllegalStateException    if the agent is closed
    public void restart(IceParameters newLocal) {
        Objects.requireNonNull(newLocal, "newLocal cannot be null");
        lock.lock();
        try {
            ensureOpen();
            if (newLocal.sameCredentials(localParameters)) {
                throw new IllegalArgumentException("an ICE restart needs new credentials");
            }
            if (remoteParameters != null) {
                retainSelected(localParameters, remoteParameters);
            }
            dropGeneration();
            localParameters = new IceParameters(newLocal.usernameFragment(), newLocal.password(), lite);
            remoteParameters = null;
            remoteEndOfCandidates = false;
            if (gatheringStarted && !pooling) {
                setGatheringState(IceGatheringState.GATHERING);
                for (var local : locals) {
                    if (local.signaled != null) {
                        emit(new IceEvent.CandidateGathered(local.signaled.withUsernameFragment(localParameters.usernameFragment()), local.server));
                    }
                }
                if (pendingGatherTasks == 0) {
                    setGatheringState(IceGatheringState.COMPLETE);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /// Changes the role, as JSEP does when the session description roles change; pair priorities are recomputed.
    ///
    /// A lite agent stays controlled.
    ///
    /// @param newRole the role
    public void setRole(IceRole newRole) {
        Objects.requireNonNull(newRole, "newRole cannot be null");
        lock.lock();
        try {
            if (!lite) {
                changeRole(newRole);
            }
        } finally {
            lock.unlock();
        }
    }

    /// Blocks until a pair is selected.
    ///
    /// @param timeout the longest time to wait
    /// @return `true` once the state is [IceTransportState#CONNECTED] or [IceTransportState#COMPLETED], `false` when
    ///         the timeout elapsed first
    /// @throws IceException         if the transport fails or closes first
    /// @throws InterruptedException if the calling thread is interrupted
    public boolean awaitConnected(Duration timeout) throws IceException, InterruptedException {
        Objects.requireNonNull(timeout, "timeout cannot be null");
        var nanos = timeout.toNanos();
        lock.lock();
        try {
            while (true) {
                switch (state) {
                    case CONNECTED, COMPLETED -> {
                        return true;
                    }
                    case FAILED -> throw new IceException("ICE failed: no candidate pair works");
                    case CLOSED -> throw new IceException("the ICE agent is closed");
                    default -> {
                    }
                }
                if (nanos <= 0) {
                    return false;
                }
                nanos = stateChanged.awaitNanos(nanos);
            }
        } finally {
            lock.unlock();
        }
    }

    /// Sends one datagram on the selected pair.
    ///
    /// Over a relayed pair the datagram goes through the TURN server, over a TCP pair it is framed; the caller sees
    /// neither.
    ///
    /// @param datagram the datagram
    /// @throws IceException if no pair is selected, consent on it expired, or the agent is closed
    /// @throws IOException  if the network refused the datagram
    @Override
    public void send(ByteBuffer datagram) throws IOException {
        Objects.requireNonNull(datagram, "datagram cannot be null");
        var pair = selected;
        if (pair == null) {
            throw new IceException("no ICE candidate pair is selected");
        }
        if (pair.consentExpired) {
            throw new IceException("consent to send on the selected pair expired");
        }
        var length = datagram.remaining();
        transmit(pair.local, pair.link, pair.remoteAddress, datagram);
        pair.packetsSent.incrementAndGet();
        pair.bytesSent.addAndGet(length);
        pair.lastPacketSentNanos = clock.nanos();
    }

    /// {@inheritDoc}
    ///
    /// Prefer [Builder#receiver(PacketReceiver)], which is in place before the first datagram can arrive; a datagram
    /// that arrives while no receiver is set is dropped.
    @Override
    public void setReceiver(PacketReceiver receiver) {
        this.receiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    /// Sets the DSCP value of the packets this agent sends, on every UDP socket it has and will open.
    ///
    /// @param dscp the differentiated services code point, `0..63`; RFC 8837 maps each WebRTC priority to one
    /// @return whether every socket accepted the value; a platform may ignore it
    /// @throws IllegalArgumentException if `dscp` is outside `0..63`
    /// @spec https://www.rfc-editor.org/rfc/rfc8837.html RFC 8837: Differentiated Services Code Point (DSCP) Packet Markings for WebRTC QoS
    public boolean setTrafficClass(int dscp) {
        if (dscp < 0 || dscp > 63) {
            throw new IllegalArgumentException("dscp must be in 0..63: " + dscp);
        }
        List<DatagramEndpoint> endpoints;
        lock.lock();
        try {
            trafficClass = dscp;
            endpoints = resources.stream().filter(DatagramEndpoint.class::isInstance)
                    .map(DatagramEndpoint.class::cast).toList();
        } finally {
            lock.unlock();
        }
        var accepted = true;
        for (var endpoint : endpoints) {
            accepted &= markQuietly(endpoint, dscp);
        }
        return accepted;
    }

    /// Sets the DSCP value of one endpoint; a platform refusal is reported as `false`, never thrown.
    private static boolean markQuietly(DatagramEndpoint endpoint, int dscp) {
        try {
            return endpoint.setTrafficClass(dscp);
        } catch (RuntimeException exception) {
            LOGGER.log(Level.DEBUG, "the traffic class could not be set: " + exception);
            return false;
        }
    }

    @Override
    public int maxDatagramSize() {
        var pair = selected;
        if (pair == null) {
            return DEFAULT_MAX_DATAGRAM;
        }
        var ipHeader = pair.remoteAddress.getAddress() instanceof Inet4Address ? 20 : 40;
        return switch (pair.local.path) {
            case UdpPath _ -> 1500 - ipHeader - 8;
            case RelayPath relay -> relay.allocation().maxPayloadSize();
            case TcpPassivePath _, TcpActivePath _ -> 1500 - ipHeader - 20 - 2;
        };
    }

    @Override
    public IceRole role() {
        lock.lock();
        try {
            return role;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public IceTransportState state() {
        lock.lock();
        try {
            return state;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public IceGatheringState gatheringState() {
        lock.lock();
        try {
            return gatheringState;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public IceParameters localParameters() {
        lock.lock();
        try {
            return localParameters;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public Optional<IceParameters> remoteParameters() {
        lock.lock();
        try {
            return Optional.ofNullable(remoteParameters);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public Optional<IceCandidatePair> selectedPair() {
        var pair = selected;
        return pair == null ? Optional.empty() : Optional.of(pair.toPublic());
    }

    @Override
    public List<IceCandidate> localCandidates() {
        lock.lock();
        try {
            return locals.stream()
                    .filter(local -> local.signaled != null && !pooling)
                    .map(local -> local.signaled.withUsernameFragment(localParameters.usernameFragment()))
                    .toList();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<IceCandidate> remoteCandidates() {
        lock.lock();
        try {
            return remotes.stream().map(RemoteCandidate::candidate).toList();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public IceTransportStatistics statistics() {
        lock.lock();
        try {
            var current = selected;
            var pairStatistics = new ArrayList<IceCandidatePairStatistics>(pairs.size() + 1);
            long packetsSent = 0;
            long packetsReceived = 0;
            long bytesSent = 0;
            long bytesReceived = 0;
            var all = new ArrayList<>(pairs);
            if (retained != null && !all.contains(retained)) {
                all.add(retained);
            }
            for (var pair : all) {
                pairStatistics.add(pair.statistics(pair == current));
                packetsSent += pair.packetsSent.get();
                packetsReceived += pair.packetsReceived.get();
                bytesSent += pair.bytesSent.get();
                bytesReceived += pair.bytesReceived.get();
            }
            return new IceTransportStatistics(role, state, gatheringState,
                    current == null ? Optional.empty() : Optional.of(current.toPublic()), selectedChanges,
                    packetsSent, packetsReceived, bytesSent, bytesReceived,
                    locals.stream().filter(local -> local.signaled != null).map(local -> local.signaled).toList(),
                    remotes.stream().map(RemoteCandidate::candidate).toList(), pairStatistics, remoteCandidatesDropped);
        } finally {
            lock.unlock();
        }
    }

    /// Closes the agent: the state turns [IceTransportState#CLOSED], TURN allocations are deleted (waiting at most a
    /// second each), and every socket, connection and thread ends. Calling it again has no effect.
    @Override
    public void close() {
        List<AutoCloseable> toClose;
        MdnsResponder closingResponder;
        MdnsResolver closingResolver;
        lock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            setState(IceTransportState.CLOSED);
            selected = null;
            toClose = List.copyOf(resources);
            resources.clear();
            closingResponder = responder;
            closingResolver = resolver;
            checks.clear();
            triggered.clear();
            pendingResolutions.clear();
        } finally {
            lock.unlock();
        }
        scheduler.close();
        gatherTransactions.close();
        for (var resource : toClose) {
            try {
                resource.close();
            } catch (Exception exception) {
                if (LOGGER.isLoggable(Level.DEBUG)) {
                    LOGGER.log(Level.DEBUG, "cannot close an ICE resource", exception);
                }
            }
        }
        if (closingResponder != null) {
            closingResponder.close();
        }
        if (closingResolver != null) {
            closingResolver.close();
        }
        events.add(Optional.empty());
    }

    /// Fails if the agent is closed; the caller holds [#lock].
    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("the ICE agent is closed");
        }
    }

    /// Starts the gathering thread; the caller holds [#lock].
    private void startGathering() {
        gatheringStarted = true;
        if (!pooling) {
            setGatheringState(IceGatheringState.GATHERING);
        }
        pendingGatherTasks++;
        stack.threadFactory().newThread(this::gatherHosts).start();
    }

    /// Gathers the host candidates, then starts the server-reflexive and relayed gathering.
    private void gatherHosts() {
        try {
            List<HostAddresses.Ranked> addresses;
            try {
                addresses = HostAddresses.choose(stack.interfaceAddresses(), loopback, linkLocal, virtualInterfaces, addressFilter);
            } catch (IOException exception) {
                if (LOGGER.isLoggable(Level.WARNING)) {
                    LOGGER.log(Level.WARNING, "cannot enumerate the network interfaces", exception);
                }
                addresses = List.of();
            }
            var udpBases = new ArrayList<LocalCandidate>();
            for (var ranked : addresses) {
                var address = ranked.address().address();
                try {
                    var endpoint = stack.bindUdp(new InetSocketAddress(address, 0));
                    var bound = new InetSocketAddress(address, endpoint.localAddress().getPort());
                    var host = new LocalCandidate(new UdpPath(endpoint), bound, IceCandidateType.HOST, IceProtocol.UDP,
                            Optional.empty(), IceCandidate.priority(IceCandidateType.HOST.typePreference(), ranked.localPreference(), COMPONENT),
                            foundation("host", address, "udp"));
                    if (!registerResource(endpoint)) {
                        return;
                    }
                    int dscp;
                    lock.lock();
                    try {
                        dscp = trafficClass;
                    } finally {
                        lock.unlock();
                    }
                    if (dscp != 0) {
                        markQuietly(endpoint, dscp);
                    }
                    addLocal(host, signaledHost(host));
                    udpBases.add(host);
                    stack.threadFactory().newThread(() -> readUdp(host, endpoint)).start();
                } catch (IOException exception) {
                    if (LOGGER.isLoggable(Level.DEBUG)) {
                        LOGGER.log(Level.DEBUG, "cannot bind UDP on " + address, exception);
                    }
                }
                if (tcpCandidates && transportPolicy == IceTransportPolicy.ALL) {
                    gatherTcp(ranked);
                }
            }
            if (lite) {
                return;
            }
            var relayIndex = 0;
            for (var server : servers) {
                for (var stunServer : server.stunServers()) {
                    if (stunServer.secure()) {
                        if (tcpCandidates && transportPolicy == IceTransportPolicy.ALL) {
                            launchGatherTask(() -> gatherSecureReflexive(stunServer));
                        }
                        continue;
                    }
                    for (var base : udpBases) {
                        launchGatherTask(() -> gatherServerReflexive(server, stunServer, base));
                    }
                }
                var credentials = server.turnCredentials();
                if (credentials.isEmpty()) {
                    continue;
                }
                for (var turnServer : server.turnServers()) {
                    var families = udpBases.stream()
                            .map(base -> StunAddressFamily.of(base.base.getAddress()))
                            .distinct()
                            .toList();
                    var index = relayIndex++;
                    for (var family : families.isEmpty() ? List.of(StunAddressFamily.IPV4) : families) {
                        launchGatherTask(() -> gatherRelay(turnServer, index, credentials.get(), family));
                    }
                }
            }
        } finally {
            finishGatherTask();
        }
    }

    /// Opens the passive and active TCP host candidates of one address.
    private void gatherTcp(HostAddresses.Ranked ranked) {
        var address = ranked.address().address();
        try {
            var listener = stack.listenTcp(new InetSocketAddress(address, 0));
            if (!registerResource(listener)) {
                return;
            }
            var bound = new InetSocketAddress(address, listener.localAddress().getPort());
            var passive = new LocalCandidate(new TcpPassivePath(listener), bound, IceCandidateType.HOST, IceProtocol.TCP,
                    Optional.of(IceTcpType.PASSIVE), IceCandidate.priority(TCP_HOST_TYPE_PREFERENCE, tcpLocalPreference(IceTcpType.PASSIVE, ranked.rank()), COMPONENT),
                    foundation("host", address, "tcp"));
            addLocal(passive, signaledHost(passive));
            stack.threadFactory().newThread(() -> acceptLoop(passive, listener)).start();
        } catch (IOException exception) {
            if (LOGGER.isLoggable(Level.DEBUG)) {
                LOGGER.log(Level.DEBUG, "cannot listen on TCP " + address, exception);
            }
        }
        if (lite) {
            return;
        }
        var active = new LocalCandidate(new TcpActivePath(address), new InetSocketAddress(address, ACTIVE_TCP_PORT),
                IceCandidateType.HOST, IceProtocol.TCP, Optional.of(IceTcpType.ACTIVE),
                IceCandidate.priority(TCP_HOST_TYPE_PREFERENCE, tcpLocalPreference(IceTcpType.ACTIVE, ranked.rank()), COMPONENT),
                foundation("host", address, "tcp"));
        addLocal(active, signaledHost(active));
    }

    /// {@return the local preference of a TCP candidate, `2^13 * direction + other` per RFC 6544 section 4.2}
    private static int tcpLocalPreference(IceTcpType direction, int rank) {
        var directionPreference = direction == IceTcpType.ACTIVE ? 6 : 4;
        return (directionPreference << 13) + Math.max(0, 8191 - rank);
    }

    /// Queries a STUN server through a host socket and adds the server-reflexive candidate it reveals.
    private void gatherServerReflexive(IceServer server, StunServer stunServer, LocalCandidate base) {
        var path = (UdpPath) base.path;
        try {
            var resolved = stack.resolve(stunServer.host()).stream()
                    .filter(address -> sameFamily(address, base.base.getAddress()))
                    .findFirst();
            if (resolved.isEmpty()) {
                return;
            }
            var target = new InetSocketAddress(resolved.get(), stunServer.port());
            var request = StunMessage.request(StunMethod.BINDING, List.of());
            var encoded = request.encode(true);
            var schedule = timers.checkRetransmission().truncatedTo(timers.gatherTimeout());
            var response = gatherTransactions.execute(request, () -> path.endpoint().send(encoded.duplicate(), target),
                    schedule, _ -> true).message();
            var mapped = response.attribute(XorMappedAddress.class).map(XorMappedAddress::address)
                    .or(() -> response.attribute(StunAttribute.MappedAddress.class).map(StunAttribute.MappedAddress::address));
            if (response.messageClass() != StunClass.SUCCESS_RESPONSE || mapped.isEmpty()) {
                var error = response.errorCode();
                emitError(stunServer.toUri(), base.base, error.map(ErrorCode::code).orElse(IceEvent.CandidateError.UNREACHABLE),
                        error.map(ErrorCode::reason).orElse("no mapped address"));
                return;
            }
            var reflexive = new LocalCandidate(base.path, mapped.get(), IceCandidateType.SERVER_REFLEXIVE, IceProtocol.UDP,
                    Optional.empty(), IceCandidate.priority(IceCandidateType.SERVER_REFLEXIVE.typePreference(),
                    (int) ((base.priority >>> 8) & 0xFFFF), COMPONENT),
                    foundation("srflx", base.base.getAddress(), stunServer.host()));
            lock.lock();
            try {
                if (closed) {
                    return;
                }
                var redundant = locals.stream().anyMatch(local -> local.path == base.path && local.base.equals(mapped.get())
                        && (local.type != IceCandidateType.HOST || hostPolicy == HostCandidatePolicy.EXPOSE));
                if (redundant) {
                    return;
                }
            } finally {
                lock.unlock();
            }
            var signaled = transportPolicy == IceTransportPolicy.ALL
                    ? new IceCandidate(reflexive.foundation, COMPONENT, IceProtocol.UDP, reflexive.priority,
                    IceCandidate.hostString(mapped.get()), mapped.get().getPort(), IceCandidateType.SERVER_REFLEXIVE,
                    Optional.empty(), Optional.of(relatedAddress(base.base, mapped.get())), Optional.empty())
                    : null;
            reflexive.server = Optional.of(stunServer.toUri());
            addLocal(reflexive, signaled);
        } catch (IOException exception) {
            emitError(stunServer.toUri(), base.base, IceEvent.CandidateError.UNREACHABLE, String.valueOf(exception.getMessage()));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    /// Allocates a relayed address on a TURN server and adds the relayed candidate.
    ///
    /// @param turnServer the server
    /// @param index      the position of the server among the TURN URLs of the agent, which keeps the local
    ///                   preference of every relayed candidate unique
    /// @param credentials the credentials
    /// @param family     the address family of the relayed address
    private void gatherRelay(TurnServer turnServer, int index, TurnCredentials credentials, StunAddressFamily family) {
        TurnClient client = null;
        try {
            client = TurnClient.connect(turnServer, credentials, stack, clock, timers.gatherTimeout());
            if (!registerResource(client)) {
                client.close();
                return;
            }
            var relayHolder = new AtomicReference<LocalCandidate>();
            var options = (family == StunAddressFamily.IPV6 ? TurnAllocationOptions.IPV6 : TurnAllocationOptions.IPV4)
                    .receiver((peer, data, arrival) -> {
                        var candidate = relayHolder.get();
                        if (candidate != null) {
                            onPacket(candidate, null, data, peer, arrival);
                        }
                    });
            var allocation = client.allocate(options, timers.gatherTimeout());
            var relayed = allocation.relayedAddress();
            var relayProtocol = switch (turnServer.transport()) {
                case UDP -> IceProtocol.UDP;
                case TCP -> IceProtocol.TCP;
                case TLS -> IceProtocol.TLS;
            };
            var relay = new LocalCandidate(new RelayPath(client, allocation), relayed, IceCandidateType.RELAY,
                    IceProtocol.UDP, Optional.empty(), IceCandidate.priority(IceCandidateType.RELAY.typePreference(),
                    relayLocalPreference(index, family, relayProtocol), COMPONENT),
                    foundation("relay", relayed.getAddress(), turnServer.host() + "/" + turnServer.transport()));
            relayHolder.set(relay);
            var related = allocation.mappedAddress().map(mapped -> relatedAddress(mapped, relayed));
            var signaled = new IceCandidate(relay.foundation, COMPONENT, IceProtocol.UDP, relay.priority,
                    IceCandidate.hostString(relayed), relayed.getPort(), IceCandidateType.RELAY, Optional.empty(),
                    related, Optional.empty(), Optional.of(relayProtocol));
            relay.server = Optional.of(turnServer.toUri());
            addLocal(relay, signaled);
        } catch (TurnException exception) {
            emitError(turnServer.toUri(), null, exception.errorCode().orElse(IceEvent.CandidateError.UNREACHABLE),
                    String.valueOf(exception.getMessage()));
            closeQuietly(client);
        } catch (IOException exception) {
            emitError(turnServer.toUri(), null, IceEvent.CandidateError.UNREACHABLE, String.valueOf(exception.getMessage()));
            closeQuietly(client);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            closeQuietly(client);
        }
    }

    /// {@return the related address a reflexive or relayed candidate is signalled with: its base under
    /// [HostCandidatePolicy#EXPOSE], otherwise the wildcard address and port `0`, so the candidate does not reveal
    /// what the host policy hides}
    ///
    /// @param base    the base, or the mapped address of a relayed candidate
    /// @param address the candidate address, whose family the wildcard takes
    private InetSocketAddress relatedAddress(InetSocketAddress base, InetSocketAddress address) {
        if (hostPolicy == HostCandidatePolicy.EXPOSE) {
            return base;
        }
        var wildcard = address.getAddress() instanceof Inet4Address
                ? InetAddress.ofLiteral("0.0.0.0")
                : InetAddress.ofLiteral("::");
        return new InetSocketAddress(wildcard, 0);
    }

    /// {@return the local preference of a relayed candidate, unique for each server, family and transport}
    ///
    /// The transport to the server takes the top two bits (UDP above TCP above TLS, as relaying over UDP adds the
    /// least delay), the family the next one (IPv6 above IPv4, as RFC 8421 prefers), and the position of the server
    /// the low thirteen bits, the first server highest.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
    static int relayLocalPreference(int serverIndex, StunAddressFamily family, IceProtocol relayProtocol) {
        var transport = switch (relayProtocol) {
            case UDP -> 2;
            case TCP -> 1;
            case TLS -> 0;
        };
        var familyBit = family == StunAddressFamily.IPV6 ? 1 : 0;
        return transport << 14 | familyBit << 13 | (8191 - Math.min(serverIndex, 8191));
    }

    /// Learns the public address of the active TCP candidates through a `stuns:` server: a Binding request over TLS
    /// reveals the address the TCP mapping of the host appears from, signalled as an active TCP server-reflexive
    /// candidate of the host candidate with the connection's local address.
    ///
    /// A TLS mapping gives no UDP candidate; the active TCP candidate it yields lets the peer recognize this side's
    /// connections instead of learning them as peer-reflexive.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
    /// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
    private void gatherSecureReflexive(StunServer stunServer) {
        com.github.auties00.parley.net.StreamConnection connection = null;
        IceScheduler.Cancellable watchdog = null;
        try {
            connection = stack.connectTls(InetSocketAddress.createUnresolved(stunServer.host(), stunServer.port()),
                    stunServer.host(), timers.gatherTimeout());
            if (!registerResource(connection)) {
                return;
            }
            var closing = connection;
            watchdog = scheduler.schedule(timers.gatherTimeout().toNanos(), () -> closeQuietly(closing));
            var request = StunMessage.request(StunMethod.BINDING, List.of());
            connection.write(request.encode(true));
            var response = readStunMessage(connection);
            var mapped = response.attribute(XorMappedAddress.class).map(XorMappedAddress::address)
                    .or(() -> response.attribute(StunAttribute.MappedAddress.class).map(StunAttribute.MappedAddress::address));
            if (!response.transactionId().equals(request.transactionId())
                    || response.messageClass() != StunClass.SUCCESS_RESPONSE || mapped.isEmpty()) {
                emitError(stunServer.toUri(), connection.localAddress(),
                        response.errorCode().map(ErrorCode::code).orElse(IceEvent.CandidateError.UNREACHABLE),
                        response.errorCode().map(ErrorCode::reason).orElse("no mapped address"));
                return;
            }
            var localAddress = connection.localAddress().getAddress();
            LocalCandidate base = null;
            lock.lock();
            try {
                for (var local : locals) {
                    if (local.type == IceCandidateType.HOST && local.protocol == IceProtocol.TCP
                            && local.tcpType.orElse(null) == IceTcpType.ACTIVE && local.base.getAddress().equals(localAddress)) {
                        base = local;
                    }
                }
            } finally {
                lock.unlock();
            }
            if (base == null) {
                return;
            }
            var address = new InetSocketAddress(mapped.get().getAddress(), ACTIVE_TCP_PORT);
            var reflexive = new LocalCandidate(base.path, address, IceCandidateType.SERVER_REFLEXIVE, IceProtocol.TCP,
                    Optional.of(IceTcpType.ACTIVE), IceCandidate.priority(TCP_SRFLX_TYPE_PREFERENCE,
                    (int) ((base.priority >>> 8) & 0xFFFF), COMPONENT),
                    foundation("srflx", localAddress, stunServer.host() + "/tls"));
            reflexive.server = Optional.of(stunServer.toUri());
            var signaled = new IceCandidate(reflexive.foundation, COMPONENT, IceProtocol.TCP, reflexive.priority,
                    IceCandidate.hostString(address), ACTIVE_TCP_PORT, IceCandidateType.SERVER_REFLEXIVE,
                    Optional.of(IceTcpType.ACTIVE), Optional.of(relatedAddress(base.base, address)), Optional.empty());
            addLocal(reflexive, signaled);
        } catch (IOException exception) {
            emitError(stunServer.toUri(), connection == null ? null : connection.localAddress(),
                    IceEvent.CandidateError.UNREACHABLE, String.valueOf(exception.getMessage()));
        } finally {
            if (watchdog != null) {
                watchdog.cancel();
            }
            closeQuietly(connection);
        }
    }

    /// {@return the next STUN message on a stream, which carries STUN messages back to back}
    ///
    /// @throws IOException if the stream ends or the message is malformed
    private static StunMessage readStunMessage(com.github.auties00.parley.net.StreamConnection connection) throws IOException {
        var header = ByteBuffer.allocate(StunMessage.HEADER_LENGTH);
        readFully(connection, header);
        var length = header.getShort(2) & 0xFFFF;
        if (length > MAX_DATAGRAM) {
            throw new IOException("STUN message of " + length + " bytes");
        }
        var message = ByteBuffer.allocate(StunMessage.HEADER_LENGTH + length);
        message.put(header.flip());
        readFully(connection, message);
        try {
            return StunMessage.decode(message.flip());
        } catch (StunFormatException exception) {
            throw new IOException("malformed STUN response", exception);
        }
    }

    /// Fills a buffer from a stream.
    ///
    /// @throws IOException if the stream ends first
    private static void readFully(com.github.auties00.parley.net.StreamConnection connection, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            if (connection.read(buffer) < 0) {
                throw new IOException("the STUN server closed the connection");
            }
        }
    }

    /// Queues a remote `.local` candidate for resolution, starting the resolver thread when it is idle; the caller
    /// holds [#lock].
    private void queueResolution(IceCandidate candidate) {
        var name = candidate.address().toLowerCase(java.util.Locale.ROOT);
        var waiting = pendingResolutions.get(name);
        if (waiting == null) {
            if (pendingResolutions.size() >= MAX_PENDING_RESOLUTIONS) {
                remoteCandidatesDropped++;
                return;
            }
            waiting = new ArrayList<>(1);
            pendingResolutions.put(name, waiting);
        }
        if (!waiting.contains(candidate)) {
            waiting.add(candidate);
        }
        if (!resolving) {
            resolving = true;
            stack.threadFactory().newThread(this::resolveLoop).start();
        }
    }

    /// Resolves the queued `.local` names one at a time until the queue is empty, adding each name's candidates with
    /// the resolved address when their generation is still current.
    private void resolveLoop() {
        while (true) {
            String name;
            IceParameters generation;
            MdnsResolver current;
            lock.lock();
            try {
                var next = pendingResolutions.keySet().iterator();
                if (closed || !next.hasNext()) {
                    resolving = false;
                    return;
                }
                name = next.next();
                generation = remoteParameters;
                if (resolver == null) {
                    try {
                        resolver = mdnsFactory.openResolver();
                    } catch (IOException exception) {
                        if (LOGGER.isLoggable(Level.DEBUG)) {
                            LOGGER.log(Level.DEBUG, "cannot open the mDNS resolver", exception);
                        }
                        pendingResolutions.clear();
                        resolving = false;
                        return;
                    }
                }
                current = resolver;
            } finally {
                lock.unlock();
            }
            Optional<InetAddress> address;
            try {
                address = current.resolve(name, timers.resolveTimeout());
            } catch (InterruptedException exception) {
                lock.lock();
                try {
                    resolving = false;
                } finally {
                    lock.unlock();
                }
                Thread.currentThread().interrupt();
                return;
            }
            lock.lock();
            try {
                var candidates = pendingResolutions.remove(name);
                if (candidates != null && address.isPresent() && !closed && remoteParameters == generation) {
                    for (var candidate : candidates) {
                        addRemote(candidate, new InetSocketAddress(address.get(), candidate.port()));
                    }
                }
            } finally {
                lock.unlock();
                drainOutgoing();
            }
        }
    }

    /// {@return the `.local` names waiting for resolution}
    int pendingResolutionCount() {
        lock.lock();
        try {
            return pendingResolutions.size();
        } finally {
            lock.unlock();
        }
    }

    /// Runs a gathering task on its own thread, counting it until it ends.
    private void launchGatherTask(Runnable task) {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            pendingGatherTasks++;
        } finally {
            lock.unlock();
        }
        stack.threadFactory().newThread(() -> {
            try {
                task.run();
            } finally {
                finishGatherTask();
            }
        }).start();
    }

    /// Counts a gathering task as done, completing gathering after the last one.
    private void finishGatherTask() {
        lock.lock();
        try {
            pendingGatherTasks--;
            if (pendingGatherTasks == 0 && !closed) {
                setGatheringState(IceGatheringState.COMPLETE);
                updateState();
            }
        } finally {
            lock.unlock();
        }
    }

    /// {@return the candidate a host candidate is signalled as, or `null` when it is not signalled}
    private IceCandidate signaledHost(LocalCandidate host) {
        if (transportPolicy == IceTransportPolicy.RELAY || hostPolicy == HostCandidatePolicy.NONE) {
            return null;
        }
        var address = IceCandidate.hostString(host.base);
        if (hostPolicy == HostCandidatePolicy.MDNS) {
            var name = mdnsName(host.base.getAddress());
            if (name.isEmpty()) {
                emitError(MDNS_SERVER, host.base, IceEvent.CandidateError.UNREACHABLE,
                        "the mDNS responder could not be opened, so the host candidate is withheld");
                return null;
            }
            address = name.get();
        }
        return new IceCandidate(host.foundation, COMPONENT, host.protocol, host.priority, address, host.base.getPort(),
                IceCandidateType.HOST, host.tcpType, Optional.empty(), Optional.empty());
    }

    /// {@return the `<uuid>.local` name of a local address, registered with the responder, or an empty optional when
    /// the responder cannot be opened, so that no name nobody answers for is signalled}
    private Optional<String> mdnsName(InetAddress address) {
        lock.lock();
        try {
            if (responder == null && !responderFailed) {
                try {
                    responder = mdnsFactory.openResponder();
                } catch (IOException exception) {
                    responderFailed = true;
                    if (LOGGER.isLoggable(Level.WARNING)) {
                        LOGGER.log(Level.WARNING, "cannot open the mDNS responder; .local candidates will not resolve", exception);
                    }
                }
            }
            return responder == null ? Optional.empty() : Optional.of(responder.register(address));
        } finally {
            lock.unlock();
        }
    }

    /// {@return the foundation of a kind of candidate, the same for the same type, base and server}
    private String foundation(String type, InetAddress base, String server) {
        lock.lock();
        try {
            var key = type + "|" + base.getHostAddress() + "|" + server;
            return foundations.computeIfAbsent(key, _ -> Integer.toString(foundations.size() + 1));
        } finally {
            lock.unlock();
        }
    }

    /// Registers a resource to close with the agent.
    ///
    /// @return `false` when the agent is already closed, in which case the resource is closed
    private boolean registerResource(AutoCloseable resource) {
        lock.lock();
        try {
            if (!closed) {
                resources.add(resource);
                return true;
            }
        } finally {
            lock.unlock();
        }
        closeQuietly(resource);
        return false;
    }

    /// Adds a gathered local candidate, pairs it with the remote candidates, and reports it when signalled.
    private void addLocal(LocalCandidate local, IceCandidate signaled) {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            local.signaled = signaled;
            locals.add(local);
            if (signaled != null) {
                emit(new IceEvent.CandidateGathered(signaled.withUsernameFragment(localParameters.usernameFragment()), local.server));
            }
            if (local.isPairable() && !concluded) {
                for (var remote : List.copyOf(remotes)) {
                    formPair(local, remote);
                }
                sortPairs();
                ensureTicking();
            }
        } finally {
            lock.unlock();
            drainOutgoing();
        }
    }

    /// Adds a remote candidate with its resolved address and pairs it; the caller holds [#lock].
    ///
    /// @return the remote candidate, new or existing, or `null` when the generation is full and the candidate was
    ///         dropped
    private RemoteCandidate addRemote(IceCandidate candidate, InetSocketAddress address) {
        var key = new RemoteKey(address, candidate.protocol());
        var existing = remoteIndex.get(key);
        if (existing != null) {
            if (existing.candidate.type() == IceCandidateType.PEER_REFLEXIVE && candidate.type() != IceCandidateType.PEER_REFLEXIVE) {
                var replaced = new RemoteCandidate(candidate, address);
                remotes.set(remotes.indexOf(existing), replaced);
                remoteIndex.put(key, replaced);
                for (var pair : pairs) {
                    if (pair.remote == existing) {
                        pair.remote = replaced;
                    }
                }
                return replaced;
            }
            return existing;
        }
        if (remotes.size() >= MAX_REMOTE_CANDIDATES) {
            remoteCandidatesDropped++;
            return null;
        }
        var remote = new RemoteCandidate(candidate, address);
        remotes.add(remote);
        remoteIndex.put(key, remote);
        for (var local : List.copyOf(locals)) {
            if (local.isPairable() && !concluded) {
                formPair(local, remote);
            }
        }
        sortPairs();
        if (remoteParameters != null && state == IceTransportState.NEW && !pairs.isEmpty()) {
            setState(IceTransportState.CHECKING);
        }
        ensureTicking();
        return remote;
    }

    /// Forms the pair of a local and a remote candidate when they can be paired; the caller holds [#lock].
    ///
    /// @return the pair, new or existing, or `null` when they cannot be paired
    private CheckPair formPair(LocalCandidate local, RemoteCandidate remote) {
        if (!sameFamily(local.base.getAddress(), remote.address.getAddress())) {
            return null;
        }
        if (local.protocol != remote.candidate.protocol()) {
            return null;
        }
        if (local.protocol == IceProtocol.TCP) {
            // A passive candidate pairs with an active one only once its connection arrives, under the address the
            // connection comes from, so only active-to-passive pairs are formed ahead of time.
            var localDirection = local.tcpType.orElseThrow();
            var remoteDirection = remote.candidate.tcpType().orElse(IceTcpType.PASSIVE);
            if (localDirection != IceTcpType.ACTIVE || remoteDirection != IceTcpType.PASSIVE) {
                return null;
            }
        }
        if (local.type == IceCandidateType.RELAY && remote.candidate.isMdns()) {
            return null;
        }
        if (transportPolicy == IceTransportPolicy.RELAY && local.type != IceCandidateType.RELAY) {
            return null;
        }
        if (local.base.getAddress().isLoopbackAddress() != remote.address.getAddress().isLoopbackAddress()) {
            return null;
        }
        for (var pair : pairs) {
            if (pair.local == local && pair.remote.address.equals(remote.address)) {
                return pair;
            }
        }
        var pair = new CheckPair(local, remote);
        if (pairs.size() >= MAX_PAIRS) {
            sortPairs();
            var lowest = pairs.getLast();
            if (lowest.priority(role) >= pair.priority(role) || lowest == selected || lowest == retained) {
                return null;
            }
            pairs.removeLast();
            routes.values().remove(lowest);
            routesVersion.incrementAndGet();
        }
        var foundation = pair.foundation();
        var active = pairs.stream().anyMatch(other -> other.foundation().equals(foundation)
                && other.state != IceCandidatePairState.FROZEN && other.state != IceCandidatePairState.FAILED);
        pair.state = active ? IceCandidatePairState.FROZEN : IceCandidatePairState.WAITING;
        pairs.add(pair);
        routes.put(new PairKey(local, remote.address), pair);
        routesVersion.incrementAndGet();
        if (local.path instanceof RelayPath relay) {
            installPermission(relay, remote.address);
        }
        return pair;
    }

    /// Installs a TURN permission for a remote address in the background.
    private void installPermission(RelayPath relay, InetSocketAddress remote) {
        if (relay.allocation().hasPermission(remote.getAddress())) {
            return;
        }
        stack.threadFactory().newThread(() -> {
            try {
                relay.allocation().createPermission(remote.getAddress(), timers.gatherTimeout());
            } catch (IOException exception) {
                if (LOGGER.isLoggable(Level.DEBUG)) {
                    LOGGER.log(Level.DEBUG, "cannot install a TURN permission for " + remote, exception);
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }

    /// Orders the checklist by pair priority, highest first; the caller holds [#lock].
    private void sortPairs() {
        var current = role;
        pairs.sort(Comparator.comparingLong((CheckPair pair) -> pair.priority(current)).reversed());
    }

    /// Drops the pairs and remote candidates of the current generation, after a restart; the caller holds [#lock].
    private void dropGeneration() {
        for (var check : List.copyOf(checks.values())) {
            if (check.pair != retained) {
                check.cancel();
                checks.remove(check.id);
            }
        }
        pairs.clear();
        triggered.clear();
        remotes.clear();
        remoteIndex.clear();
        pendingResolutions.clear();
        routes.values().removeIf(pair -> pair != retained);
        routesVersion.incrementAndGet();
        nominating = null;
        nominationScheduled = false;
        firstValidNanos = -1;
        concluded = false;
    }

    /// Keeps the selected pair alive across a restart, with the credentials of its generation; the caller holds
    /// [#lock].
    private void retainSelected(IceParameters local, IceParameters remote) {
        if (selected != null) {
            retained = selected;
            retainedLocal = local;
            retainedRemote = remote;
            routes.put(new PairKey(retained.local, retained.remoteAddress), retained);
            routesVersion.incrementAndGet();
        }
    }

    /// Starts the pacing task when checks are possible and it is not running; the caller holds [#lock].
    private void ensureTicking() {
        if (ticking || closed || lite || remoteParameters == null) {
            return;
        }
        ticking = true;
        scheduler.schedule(0, this::tick);
    }

    /// Sends the next check, every `Ta`: a triggered check first, else the highest-priority waiting pair, else the
    /// highest-priority frozen pair whose foundation is idle.
    private void tick() {
        lock.lock();
        try {
            if (closed || remoteParameters == null) {
                ticking = false;
                return;
            }
            var next = nextPairToCheck();
            if (next == null) {
                ticking = false;
                updateState();
                return;
            }
            sendCheck(next, shouldNominate(next), false);
            scheduler.schedule(timers.pacing().toNanos(), this::tick);
        } finally {
            lock.unlock();
            drainOutgoing();
        }
    }

    /// {@return the pair the next ordinary or triggered check runs on, or `null`}; the caller holds [#lock].
    private CheckPair nextPairToCheck() {
        while (!triggered.isEmpty()) {
            var pair = triggered.poll();
            if (pairs.contains(pair) && pair.state != IceCandidatePairState.FAILED && pair.inFlight == null) {
                return pair;
            }
        }
        if (nominationDone()) {
            return null;
        }
        for (var pair : pairs) {
            if (pair.state == IceCandidatePairState.WAITING) {
                return pair;
            }
        }
        for (var pair : pairs) {
            if (pair.state != IceCandidatePairState.FROZEN) {
                continue;
            }
            var foundation = pair.foundation();
            var busy = pairs.stream().anyMatch(other -> other.foundation().equals(foundation)
                    && (other.state == IceCandidatePairState.WAITING || other.state == IceCandidatePairState.IN_PROGRESS));
            if (!busy) {
                pair.state = IceCandidatePairState.WAITING;
                return pair;
            }
        }
        return null;
    }

    /// {@return whether the controlling agent finished nominating, so ordinary checks stop}; the caller holds
    /// [#lock].
    private boolean nominationDone() {
        return pairs.stream().anyMatch(pair -> pair.nominated && pair.state == IceCandidatePairState.SUCCEEDED);
    }

    /// {@return whether a check of `pair` should carry `USE-CANDIDATE`}; the caller holds [#lock].
    private boolean shouldNominate(CheckPair pair) {
        return role == IceRole.CONTROLLING && pair == nominating;
    }

    /// Sends a connectivity or consent check on a pair and schedules its retransmission; the caller holds [#lock].
    private void sendCheck(CheckPair pair, boolean useCandidate, boolean consent) {
        var credentialsLocal = pair == retained && retainedLocal != null ? retainedLocal : localParameters;
        var credentialsRemote = pair == retained && retainedRemote != null ? retainedRemote : remoteParameters;
        if (credentialsRemote == null) {
            return;
        }
        if (pair.local.path instanceof TcpActivePath && pair.link == null) {
            if (!pair.connecting) {
                pair.connecting = true;
                pair.state = IceCandidatePairState.IN_PROGRESS;
                stack.threadFactory().newThread(() -> connectTcp(pair)).start();
            }
            return;
        }
        if ((pair.local.path instanceof TcpPassivePath) && pair.link == null) {
            pair.state = IceCandidatePairState.FAILED;
            return;
        }
        var attributes = new ArrayList<StunAttribute>(5);
        attributes.add(new Username(credentialsRemote.usernameFragment() + ":" + credentialsLocal.usernameFragment()));
        attributes.add(new Priority(peerReflexivePriority(pair.local)));
        attributes.add(role == IceRole.CONTROLLING ? new IceControlling(tieBreaker) : new IceControlled(tieBreaker));
        if (useCandidate) {
            attributes.add(new UseCandidate());
        }
        var request = StunMessage.request(StunMethod.BINDING, attributes);
        var encoded = request.encode(credentialsRemote.key(), StunIntegrity.HMAC_SHA1, true);
        var reliable = pair.local.protocol == IceProtocol.TCP;
        var check = new Check(request.transactionId(), pair, encoded, useCandidate, consent, role, reliable);
        checks.put(check.id, check);
        if (!consent) {
            pair.inFlight = check;
            if (pair.state != IceCandidatePairState.SUCCEEDED) {
                pair.state = IceCandidatePairState.IN_PROGRESS;
            }
            pair.requestsSent++;
        } else {
            pair.consentRequestsSent++;
        }
        transmitCheck(check);
    }

    /// Transmits a check once and schedules the next retransmission or its timeout; the caller holds [#lock].
    private void transmitCheck(Check check) {
        check.sentAt = clock.nanos();
        outgoing.add(new Outgoing(check.pair.local, check.pair.link, check.pair.remoteAddress, check.encoded.duplicate()));
        long wait;
        if (check.consent) {
            wait = timers.consentInterval().toNanos();
        } else if (check.reliable) {
            wait = timers.reliableCheckTimeout().toNanos();
        } else {
            var schedule = timers.checkRetransmission();
            var active = pairs.stream().filter(pair -> pair.state == IceCandidatePairState.WAITING
                    || pair.state == IceCandidatePairState.IN_PROGRESS).count();
            var rto = Math.max(schedule.initialRto().toNanos(), timers.pacing().toNanos() * active);
            wait = check.transmissions >= schedule.maxTransmissions() - 1
                    ? rto * schedule.lastWaitMultiplier()
                    : rto << Math.min(check.transmissions, 30);
        }
        check.transmissions++;
        check.timer = scheduler.schedule(wait, () -> onCheckTimer(check));
    }

    /// Retransmits a check or fails its pair when its schedule ends.
    private void onCheckTimer(Check check) {
        lock.lock();
        try {
            if (closed || checks.get(check.id) != check) {
                return;
            }
            var limit = check.reliable || check.consent ? 1 : timers.checkRetransmission().maxTransmissions();
            if (check.transmissions < limit) {
                transmitCheck(check);
                return;
            }
            checks.remove(check.id);
            if (check.consent) {
                return;
            }
            if (check.pair.inFlight == check) {
                check.pair.inFlight = null;
                if (check.pair.state != IceCandidatePairState.SUCCEEDED) {
                    check.pair.state = IceCandidatePairState.FAILED;
                }
                if (nominating == check.pair) {
                    nominating = null;
                    scheduleNomination();
                }
                ensureTicking();
                updateState();
            }
        } finally {
            lock.unlock();
            drainOutgoing();
        }
    }

    /// {@return the `PRIORITY` a check from `local` carries: the peer-reflexive priority of its base}
    private static long peerReflexivePriority(LocalCandidate local) {
        var typePreference = local.protocol == IceProtocol.TCP ? TCP_PRFLX_TYPE_PREFERENCE : IceCandidateType.PEER_REFLEXIVE.typePreference();
        return IceCandidate.priority(typePreference, (int) ((local.priority >>> 8) & 0xFFFF), COMPONENT);
    }

    /// Opens the TCP connection of an active pair, then checks it.
    private void connectTcp(CheckPair pair) {
        try {
            var connection = stack.connectTcp(pair.remoteAddress, timers.gatherTimeout());
            var link = new TcpLink(connection);
            if (!registerResource(connection)) {
                return;
            }
            lock.lock();
            try {
                pair.link = link;
                pair.connecting = false;
                if (pairs.contains(pair) && pair.state != IceCandidatePairState.FAILED) {
                    triggered.addFirst(pair);
                    ensureTicking();
                }
            } finally {
                lock.unlock();
            }
            stack.threadFactory().newThread(() -> readTcp(pair.local, link)).start();
        } catch (IOException exception) {
            lock.lock();
            try {
                pair.connecting = false;
                pair.state = IceCandidatePairState.FAILED;
                updateState();
            } finally {
                lock.unlock();
            }
        }
    }

    /// Reads datagrams from a host UDP socket until it closes.
    private void readUdp(LocalCandidate host, com.github.auties00.parley.net.DatagramEndpoint endpoint) {
        var buffer = ByteBuffer.allocate(MAX_DATAGRAM);
        while (true) {
            buffer.clear();
            InetSocketAddress source;
            try {
                source = endpoint.receive(buffer);
            } catch (java.net.PortUnreachableException exception) {
                // An ICMP error for an earlier check to a dead candidate; the socket is still usable.
                continue;
            } catch (IOException exception) {
                return;
            }
            var arrival = clock.nanos();
            buffer.flip();
            onPacket(host, null, buffer, source, arrival);
        }
    }

    /// Accepts connections on a passive TCP candidate until the listener closes.
    private void acceptLoop(LocalCandidate passive, com.github.auties00.parley.net.StreamListener listener) {
        while (true) {
            com.github.auties00.parley.net.StreamConnection connection;
            try {
                connection = listener.accept();
            } catch (IOException exception) {
                return;
            }
            if (!registerResource(connection)) {
                return;
            }
            var link = new TcpLink(connection);
            stack.threadFactory().newThread(() -> readTcp(passive, link)).start();
        }
    }

    /// Reads frames from an ICE-TCP connection until it ends.
    private void readTcp(LocalCandidate local, TcpLink link) {
        var remote = link.remoteAddress();
        try {
            link.readLoop(frame -> onPacket(local, link, frame, remote, clock.nanos()));
        } catch (IOException exception) {
            lock.lock();
            try {
                for (var pair : pairs) {
                    if (pair.link == link) {
                        pair.link = null;
                        if (pair.state != IceCandidatePairState.SUCCEEDED) {
                            pair.state = IceCandidatePairState.FAILED;
                        }
                    }
                }
                updateState();
            } finally {
                lock.unlock();
            }
            link.close();
        }
    }

    /// Handles one datagram that arrived on a local candidate: STUN goes to the agent, anything else from a known
    /// remote address to the receiver.
    private void onPacket(LocalCandidate local, TcpLink link, ByteBuffer packet, InetSocketAddress source, long arrival) {
        if (StunMessage.isStun(packet)) {
            StunMessage message;
            try {
                message = StunMessage.decode(packet);
            } catch (StunFormatException exception) {
                return;
            }
            if (message.method() != StunMethod.BINDING) {
                return;
            }
            if (link == null && local.path instanceof UdpPath && gatherTransactions.complete(message)) {
                return;
            }
            switch (message.messageClass()) {
                case REQUEST -> handleRequest(local, link, message, source, arrival);
                case SUCCESS_RESPONSE, ERROR_RESPONSE -> handleResponse(message, source, arrival);
                case INDICATION -> {
                }
            }
            drainOutgoing();
            return;
        }
        CheckPair pair;
        var version = routesVersion.get();
        var cached = lastRoute;
        if (cached != null && cached.version() == version && cached.local() == local
                && cached.remote().equals(source)) {
            pair = cached.pair();
        } else {
            pair = routes.get(new PairKey(local, source));
            if (pair != null) {
                lastRoute = new CachedRoute(local, source, pair, version);
            }
        }
        if (pair == null && link != null) {
            pair = findByLink(link);
        }
        if (pair == null) {
            return;
        }
        pair.packetsReceived.incrementAndGet();
        pair.bytesReceived.addAndGet(packet.remaining());
        pair.lastPacketReceivedNanos = arrival;
        var current = receiver;
        if (current == null) {
            return;
        }
        try {
            current.receive(packet, arrival);
        } catch (RuntimeException exception) {
            if (LOGGER.isLoggable(Level.WARNING)) {
                LOGGER.log(Level.WARNING, "the ICE packet receiver failed", exception);
            }
        }
    }

    /// {@return the pair that owns a TCP link, or `null`}
    private CheckPair findByLink(TcpLink link) {
        lock.lock();
        try {
            for (var pair : pairs) {
                if (pair.link == link) {
                    return pair;
                }
            }
            return retained != null && retained.link == link ? retained : null;
        } finally {
            lock.unlock();
        }
    }

    /// Answers a Binding request from the peer and runs the triggered-check, peer-reflexive and nomination logic
    /// of RFC 8445 section 7.3.
    private void handleRequest(LocalCandidate local, TcpLink link, StunMessage request, InetSocketAddress source, long arrival) {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            var username = request.attribute(Username.class).map(Username::value).orElse(null);
            IceParameters matched = null;
            if (username != null) {
                if (username.startsWith(localParameters.usernameFragment() + ":")) {
                    matched = localParameters;
                } else if (retainedLocal != null && username.startsWith(retainedLocal.usernameFragment() + ":")) {
                    matched = retainedLocal;
                }
            }
            if (request.integrity().isEmpty() || username == null) {
                respondError(local, link, source, request, ErrorCode.BAD_REQUEST, "Bad Request", null);
                return;
            }
            if (matched == null || !request.verifyIntegrity(matched.key())) {
                respondError(local, link, source, request, ErrorCode.UNAUTHENTICATED, "Unauthenticated", null);
                return;
            }
            var unknown = request.unknownComprehensionRequired();
            if (!unknown.isEmpty()) {
                respondError(local, link, source, request, ErrorCode.UNKNOWN_ATTRIBUTE, "Unknown Attribute",
                        matched, new StunAttribute.UnknownAttributes(unknown));
                return;
            }
            var peerControlling = request.attribute(IceControlling.class);
            var peerControlled = request.attribute(IceControlled.class);
            if (!lite) {
                if (role == IceRole.CONTROLLING && peerControlling.isPresent()) {
                    if (Long.compareUnsigned(tieBreaker, peerControlling.get().tieBreaker()) >= 0) {
                        respondError(local, link, source, request, ErrorCode.ROLE_CONFLICT, "Role Conflict", matched);
                        return;
                    }
                    changeRole(IceRole.CONTROLLED);
                } else if (role == IceRole.CONTROLLED && peerControlled.isPresent()) {
                    if (Long.compareUnsigned(tieBreaker, peerControlled.get().tieBreaker()) >= 0) {
                        changeRole(IceRole.CONTROLLING);
                    } else {
                        respondError(local, link, source, request, ErrorCode.ROLE_CONFLICT, "Role Conflict", matched);
                        return;
                    }
                }
            }
            var response = request.successResponse(List.of(new XorMappedAddress(source)));
            outgoing.add(new Outgoing(local, link, source, response.encode(matched.key(), StunIntegrity.HMAC_SHA1, true)));
            if (matched != localParameters) {
                if (retained != null && retained.local == local && retained.remoteAddress.equals(source)) {
                    retained.requestsReceived++;
                    retained.responsesSent++;
                    retained.lastRequestReceivedNanos = arrival;
                }
                return;
            }
            var remote = findRemote(source, local.protocol);
            if (remote == null) {
                var priority = request.attribute(Priority.class).map(Priority::priority).orElse(0L);
                var prflx = new IceCandidate(randomFoundation(), COMPONENT, local.protocol, priority,
                        IceCandidate.hostString(source), source.getPort(), IceCandidateType.PEER_REFLEXIVE,
                        local.protocol == IceProtocol.TCP ? Optional.of(IceTcpType.ACTIVE) : Optional.empty(),
                        Optional.empty(), remoteParameters == null ? Optional.empty() : Optional.of(remoteParameters.usernameFragment()));
                remote = addRemote(prflx, source);
                if (remote == null) {
                    return;
                }
            }
            var pair = findPair(local, source);
            if (pair == null && local.path instanceof TcpPassivePath) {
                pair = new CheckPair(local, remote);
                pair.state = IceCandidatePairState.WAITING;
                pairs.add(pair);
                routes.put(new PairKey(local, source), pair);
                routesVersion.incrementAndGet();
                sortPairs();
            }
            if (pair == null) {
                pair = formPair(local, remote);
                sortPairs();
            }
            if (pair == null) {
                return;
            }
            if (link != null && pair.link == null) {
                pair.link = link;
            }
            pair.requestsReceived++;
            pair.responsesSent++;
            pair.lastRequestReceivedNanos = arrival;
            var useCandidate = request.has(UseCandidate.class);
            if (lite) {
                if (pair.state != IceCandidatePairState.SUCCEEDED) {
                    pair.state = IceCandidatePairState.SUCCEEDED;
                }
                pair.lastConsentNanos = arrival;
                if (useCandidate) {
                    pair.nominated = true;
                    updateSelection();
                }
                updateState();
                return;
            }
            if (useCandidate && role == IceRole.CONTROLLED) {
                pair.useCandidateReceived = true;
                if (pair.state == IceCandidatePairState.SUCCEEDED) {
                    pair.nominated = true;
                    updateSelection();
                    updateState();
                    return;
                }
            }
            if (remoteParameters == null) {
                return;
            }
            switch (pair.state) {
                case SUCCEEDED -> {
                }
                case IN_PROGRESS -> {
                    if (pair.inFlight == null) {
                        triggered.add(pair);
                    }
                }
                case WAITING, FROZEN, FAILED -> {
                    pair.state = IceCandidatePairState.WAITING;
                    if (!triggered.contains(pair)) {
                        triggered.add(pair);
                    }
                }
            }
            if (state == IceTransportState.NEW) {
                setState(IceTransportState.CHECKING);
            }
            ensureTicking();
        } finally {
            lock.unlock();
        }
    }

    /// Queues an error response to a request, signed when the request's credentials are known; the caller holds
    /// [#lock].
    private void respondError(LocalCandidate local, TcpLink link, InetSocketAddress source, StunMessage request, int code,
                              String reason, IceParameters credentials, StunAttribute... extra) {
        var response = request.errorResponse(code, reason, List.of(extra));
        var encoded = credentials == null
                ? response.encode(true)
                : response.encode(credentials.key(), StunIntegrity.HMAC_SHA1, true);
        outgoing.add(new Outgoing(local, link, source, encoded));
    }

    /// Processes a response to one of this agent's checks (RFC 8445 section 7.2.5).
    private void handleResponse(StunMessage response, InetSocketAddress source, long arrival) {
        lock.lock();
        try {
            var check = checks.get(response.transactionId());
            if (check == null || closed) {
                return;
            }
            var pair = check.pair;
            var credentials = pair == retained && retainedRemote != null ? retainedRemote : remoteParameters;
            if (credentials == null || !response.verifyIntegrity(credentials.key())) {
                return;
            }
            checks.remove(check.id);
            check.cancel();
            pair.responsesReceived++;
            var rtt = Math.max(0, arrival - check.sentAt);
            pair.currentRtt = Duration.ofNanos(rtt);
            pair.totalRtt = pair.totalRtt.plusNanos(rtt);
            if (!source.equals(pair.remoteAddress)) {
                if (!check.consent && pair.inFlight == check) {
                    pair.inFlight = null;
                    pair.state = IceCandidatePairState.FAILED;
                    updateState();
                }
                return;
            }
            if (check.consent) {
                if (response.messageClass() == StunClass.SUCCESS_RESPONSE && !pair.consentExpired) {
                    pair.lastConsentNanos = arrival;
                    updateState();
                }
                return;
            }
            if (pair.inFlight == check) {
                pair.inFlight = null;
            }
            if (response.messageClass() == StunClass.ERROR_RESPONSE) {
                var code = response.errorCode().map(ErrorCode::code).orElse(0);
                if (code == ErrorCode.ROLE_CONFLICT) {
                    if (check.role == role) {
                        changeRole(role.opposite());
                    }
                    pair.state = IceCandidatePairState.WAITING;
                    triggered.add(pair);
                    ensureTicking();
                    return;
                }
                pair.state = IceCandidatePairState.FAILED;
                if (nominating == pair) {
                    nominating = null;
                    scheduleNomination();
                }
                updateState();
                return;
            }
            var mapped = response.attribute(XorMappedAddress.class).map(XorMappedAddress::address);
            if (mapped.isPresent() && !pair.local.base.equals(mapped.get()) && pair.local.protocol == IceProtocol.UDP
                    && pair.local.type == IceCandidateType.HOST) {
                var known = locals.stream().anyMatch(local -> local.base.equals(mapped.get()));
                if (!known) {
                    pair.learnedLocal = new IceCandidate(randomFoundation(), COMPONENT, IceProtocol.UDP,
                            peerReflexivePriority(pair.local), IceCandidate.hostString(mapped.get()), mapped.get().getPort(),
                            IceCandidateType.PEER_REFLEXIVE, Optional.empty(), Optional.empty(), Optional.empty());
                }
            }
            var wasValid = pair.state == IceCandidatePairState.SUCCEEDED;
            pair.state = IceCandidatePairState.SUCCEEDED;
            pair.lastConsentNanos = arrival;
            if (!wasValid) {
                var foundation = pair.foundation();
                for (var other : pairs) {
                    if (other.state == IceCandidatePairState.FROZEN && other.foundation().equals(foundation)) {
                        other.state = IceCandidatePairState.WAITING;
                    }
                }
                if (firstValidNanos < 0) {
                    firstValidNanos = arrival;
                }
            }
            if (check.useCandidate && role == IceRole.CONTROLLING) {
                pair.nominated = true;
                nominating = null;
            } else if (pair.useCandidateReceived && role == IceRole.CONTROLLED) {
                pair.nominated = true;
            }
            if (role == IceRole.CONTROLLING && !nominationDone()) {
                scheduleNomination();
            }
            updateSelection();
            updateState();
            ensureTicking();
        } finally {
            lock.unlock();
        }
    }

    /// {@return the remote candidate with an address and protocol, or `null`}; the caller holds [#lock].
    private RemoteCandidate findRemote(InetSocketAddress address, IceProtocol protocol) {
        return remoteIndex.get(new RemoteKey(address, protocol));
    }

    /// {@return the pair of a local candidate and a remote address, or `null`}; the caller holds [#lock].
    private CheckPair findPair(LocalCandidate local, InetSocketAddress remote) {
        for (var pair : pairs) {
            if (pair.local == local && pair.remoteAddress.equals(remote)) {
                return pair;
            }
        }
        return null;
    }

    /// {@return a random foundation for a peer-reflexive candidate}
    private static String randomFoundation() {
        return Long.toString(ThreadLocalRandom.current().nextLong(1L << 32));
    }

    /// Evaluates nomination now or after the nomination delay; the caller holds [#lock].
    private void scheduleNomination() {
        if (role != IceRole.CONTROLLING || nominating != null || nominationDone() || closed) {
            return;
        }
        var best = bestValid();
        if (best == null) {
            return;
        }
        var bestPriority = best.priority(role);
        var remotePeerLite = remoteParameters != null && remoteParameters.lite();
        var betterPending = pairs.stream().anyMatch(pair -> pair.priority(role) > bestPriority
                && pair.state != IceCandidatePairState.SUCCEEDED && pair.state != IceCandidatePairState.FAILED);
        var elapsed = clock.nanos() - firstValidNanos;
        if (!betterPending || remotePeerLite || elapsed >= timers.nominationDelay().toNanos()) {
            nominating = best;
            triggered.addFirst(best);
            ensureTicking();
            return;
        }
        if (!nominationScheduled) {
            nominationScheduled = true;
            scheduler.schedule(timers.nominationDelay().toNanos() - elapsed, () -> {
                lock.lock();
                try {
                    nominationScheduled = false;
                    scheduleNomination();
                } finally {
                    lock.unlock();
                    drainOutgoing();
                }
            });
        }
    }

    /// Concludes the checklist once a nominated pair is selected: pairs not yet checked are removed and checks in
    /// progress stop, as RFC 8445 section 8.1.2 describes; the caller holds [#lock].
    ///
    /// Checks the peer triggers later still run, so a peer that nominates another pair is followed.
    private void conclude() {
        concluded = true;
        for (var pair : List.copyOf(pairs)) {
            switch (pair.state) {
                case WAITING, FROZEN -> {
                    pairs.remove(pair);
                    triggered.remove(pair);
                    routes.values().remove(pair);
                    routesVersion.incrementAndGet();
                }
                case IN_PROGRESS -> {
                    if (pair.inFlight != null) {
                        pair.inFlight.cancel();
                        checks.remove(pair.inFlight.id);
                        pair.inFlight = null;
                    }
                    pair.state = IceCandidatePairState.FAILED;
                }
                case SUCCEEDED, FAILED -> {
                }
            }
        }
    }

    /// {@return the highest-priority valid pair whose consent did not expire, or `null`}; the caller holds [#lock].
    private CheckPair bestValid() {
        for (var pair : pairs) {
            if (pair.state == IceCandidatePairState.SUCCEEDED && !pair.consentExpired) {
                return pair;
            }
        }
        return null;
    }

    /// Recomputes the selected pair; the caller holds [#lock].
    ///
    /// The controlled agent selects the highest-priority nominated pair; the controlling agent its nominated pair,
    /// or before nominating the best valid pair. A pair retained across a restart stays selected until the new
    /// generation has one.
    private void updateSelection() {
        CheckPair candidate = null;
        for (var pair : pairs) {
            if (pair.state != IceCandidatePairState.SUCCEEDED || pair.consentExpired) {
                continue;
            }
            if (pair.nominated) {
                candidate = pair;
                break;
            }
        }
        if (candidate == null && role == IceRole.CONTROLLING && !lite) {
            candidate = bestValid();
        }
        if (candidate == null && retained != null && !retained.consentExpired) {
            candidate = retained;
        }
        if (candidate != null && candidate != retained && retained != null) {
            routes.values().remove(retained);
            routesVersion.incrementAndGet();
            retained = null;
            retainedLocal = null;
            retainedRemote = null;
        }
        if (candidate != null && candidate.nominated && !concluded) {
            conclude();
        }
        if (candidate == selected) {
            return;
        }
        var previous = selected;
        selected = candidate;
        if (candidate == null) {
            return;
        }
        if (candidate.consentTimer == null) {
            scheduleConsent(candidate);
        }
        if (previous != null && previous != candidate && previous.consentTimer != null && previous != retained) {
            previous.consentTimer.cancel();
            previous.consentTimer = null;
        }
        if (candidate.local.path instanceof RelayPath relay) {
            var remote = candidate.remoteAddress;
            stack.threadFactory().newThread(() -> {
                try {
                    relay.allocation().bindChannel(remote, timers.gatherTimeout());
                } catch (IOException exception) {
                    if (LOGGER.isLoggable(Level.DEBUG)) {
                        LOGGER.log(Level.DEBUG, "cannot bind a TURN channel to " + remote, exception);
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        selectedChanges++;
        emit(new IceEvent.SelectedPairChanged(candidate.toPublic()));
    }

    /// Schedules the next consent check of a pair, 0.8 to 1.2 times the consent interval from now; the caller holds
    /// [#lock].
    private void scheduleConsent(CheckPair pair) {
        var interval = timers.consentInterval().toNanos();
        var jittered = (long) (interval * (0.8 + 0.4 * ThreadLocalRandom.current().nextDouble()));
        pair.consentTimer = scheduler.schedule(jittered, () -> consentTick(pair));
    }

    /// Sends a consent check on a selected (or retained) pair and checks its consent deadlines.
    private void consentTick(CheckPair pair) {
        lock.lock();
        try {
            pair.consentTimer = null;
            if (closed || (pair != selected && pair != retained)) {
                return;
            }
            var now = clock.nanos();
            var silence = now - pair.lastConsentNanos;
            if (silence >= timers.consentExpiry().toNanos()) {
                expireConsent(pair);
                return;
            }
            if (lite) {
                updateState();
                scheduleConsent(pair);
                return;
            }
            sendCheck(pair, false, true);
            updateState();
            scheduleConsent(pair);
        } finally {
            lock.unlock();
            drainOutgoing();
        }
    }

    /// Ends consent on a pair: it stops carrying data and the agent falls back to another valid pair or fails; the
    /// caller holds [#lock].
    private void expireConsent(CheckPair pair) {
        pair.consentExpired = true;
        pair.state = IceCandidatePairState.FAILED;
        pair.nominated = false;
        for (var check : List.copyOf(checks.values())) {
            if (check.pair == pair) {
                check.cancel();
                checks.remove(check.id);
            }
        }
        if (pair == retained) {
            routes.values().remove(retained);
            routesVersion.incrementAndGet();
            retained = null;
        }
        if (selected == pair) {
            selected = null;
            updateSelection();
        }
        updateState();
    }

    /// Recomputes the transport state from the checklist; the caller holds [#lock].
    private void updateState() {
        if (closed || state == IceTransportState.CLOSED) {
            return;
        }
        var current = selected;
        if (current != null) {
            var silence = clock.nanos() - current.lastConsentNanos;
            if (silence >= timers.disconnectedAfter().toNanos()) {
                setState(IceTransportState.DISCONNECTED);
                return;
            }
            var settled = current.nominated && gatheringState == IceGatheringState.COMPLETE && remoteEndOfCandidates
                    && pairs.stream().noneMatch(pair -> pair.state == IceCandidatePairState.WAITING
                    || pair.state == IceCandidatePairState.IN_PROGRESS);
            setState(settled ? IceTransportState.COMPLETED : IceTransportState.CONNECTED);
            return;
        }
        var anyAlive = pairs.stream().anyMatch(pair -> pair.state != IceCandidatePairState.FAILED);
        var exhausted = !anyAlive && gatheringState == IceGatheringState.COMPLETE
                && (remoteEndOfCandidates || (remoteParameters != null && remoteParameters.lite()));
        if (exhausted && (state != IceTransportState.NEW || !pairs.isEmpty())) {
            setState(IceTransportState.FAILED);
        } else if (state == IceTransportState.CONNECTED || state == IceTransportState.COMPLETED) {
            setState(anyAlive ? IceTransportState.CHECKING : IceTransportState.DISCONNECTED);
        } else if (state == IceTransportState.NEW && remoteParameters != null && !pairs.isEmpty()) {
            setState(IceTransportState.CHECKING);
        } else if (state == IceTransportState.FAILED && anyAlive) {
            setState(IceTransportState.CHECKING);
        }
    }

    /// Sets the transport state, reporting a change; the caller holds [#lock].
    private void setState(IceTransportState newState) {
        if (state == newState || state == IceTransportState.CLOSED) {
            return;
        }
        state = newState;
        stateChanged.signalAll();
        emit(new IceEvent.StateChanged(newState));
    }

    /// Sets the gathering state, reporting a change; the caller holds [#lock].
    private void setGatheringState(IceGatheringState newState) {
        if (gatheringState == newState) {
            return;
        }
        gatheringState = newState;
        emit(new IceEvent.GatheringStateChanged(newState));
    }

    /// Changes the role and reorders the checklist; the caller holds [#lock].
    private void changeRole(IceRole newRole) {
        if (role == newRole) {
            return;
        }
        role = newRole;
        sortPairs();
        if (newRole == IceRole.CONTROLLED) {
            nominating = null;
        } else {
            scheduleNomination();
        }
    }

    /// Queues an event for the dispatcher, or holds it back while pooling; the caller holds [#lock].
    private void emit(IceEvent event) {
        if (pooling && (event instanceof IceEvent.CandidateGathered || event instanceof IceEvent.GatheringStateChanged)) {
            pooledEvents.add(event);
            return;
        }
        events.add(Optional.of(event));
    }

    /// Reports a server that failed to provide a candidate.
    ///
    /// @param localAddress the local address the request was sent from, or `null` when it is not known
    private void emitError(URI server, InetSocketAddress localAddress, int code, String reason) {
        lock.lock();
        try {
            if (!closed) {
                emit(new IceEvent.CandidateError(server, Optional.ofNullable(localAddress), code, reason));
            }
        } finally {
            lock.unlock();
        }
    }

    /// Delivers events to the listener until the agent closes and the queue drains.
    private void dispatchLoop() {
        while (true) {
            Optional<IceEvent> next;
            try {
                next = events.take();
            } catch (InterruptedException exception) {
                return;
            }
            if (next.isEmpty()) {
                return;
            }
            try {
                listener.accept(next.get());
            } catch (RuntimeException exception) {
                if (LOGGER.isLoggable(Level.WARNING)) {
                    LOGGER.log(Level.WARNING, "the ICE event listener failed", exception);
                }
            }
        }
    }

    /// Sends the datagrams queued under the lock; called after releasing it.
    private void drainOutgoing() {
        Outgoing next;
        while ((next = outgoing.poll()) != null) {
            try {
                transmit(next.local, next.link, next.remote, next.datagram);
            } catch (IOException exception) {
                if (LOGGER.isLoggable(Level.DEBUG)) {
                    LOGGER.log(Level.DEBUG, "cannot send an ICE message to " + next.remote, exception);
                }
            }
        }
    }

    /// Sends one datagram from a local candidate to a remote address.
    private static void transmit(LocalCandidate local, TcpLink link, InetSocketAddress remote, ByteBuffer datagram) throws IOException {
        switch (local.path) {
            case UdpPath udp -> udp.endpoint().send(datagram, remote);
            case RelayPath relay -> relay.allocation().send(datagram, remote);
            case TcpPassivePath _, TcpActivePath _ -> {
                if (link == null) {
                    throw new IOException("the ICE-TCP connection is not open");
                }
                link.send(datagram);
            }
        }
    }

    /// {@return whether two addresses share a family}
    private static boolean sameFamily(InetAddress first, InetAddress second) {
        return (first instanceof Inet4Address) == (second instanceof Inet4Address)
                && (first instanceof Inet6Address && first.isLinkLocalAddress()) == (second instanceof Inet6Address && second.isLinkLocalAddress());
    }

    /// Closes a resource, ignoring a failure.
    private static void closeQuietly(AutoCloseable resource) {
        if (resource == null) {
            return;
        }
        try {
            resource.close();
        } catch (Exception _) {
            // A failed close leaves nothing to release.
        }
    }

    /// A local candidate with the network resource behind it.
    private static final class LocalCandidate {
        /// The path datagrams leave through.
        private final IcePath path;

        /// The transport address: the bound address of a host candidate, the mapped address of a server-reflexive one,
        /// the relayed address of a relayed one.
        private final InetSocketAddress base;

        /// The type.
        private final IceCandidateType type;

        /// The protocol.
        private final IceProtocol protocol;

        /// The TCP direction.
        private final Optional<IceTcpType> tcpType;

        /// The priority.
        private final long priority;

        /// The foundation.
        private final String foundation;

        /// The candidate as signalled, or `null` when it is not signalled; written under the agent lock before the
        /// candidate is published.
        private IceCandidate signaled;

        /// The URL of the STUN or TURN server the candidate came from, empty for a host or peer-reflexive one; written
        /// before the candidate is published.
        private Optional<URI> server = Optional.empty();

        /// Creates a local candidate.
        LocalCandidate(IcePath path, InetSocketAddress base, IceCandidateType type, IceProtocol protocol,
                       Optional<IceTcpType> tcpType, long priority, String foundation) {
            this.path = path;
            this.base = base;
            this.type = type;
            this.protocol = protocol;
            this.tcpType = tcpType;
            this.priority = priority;
            this.foundation = foundation;
        }

        /// {@return whether the candidate forms pairs: every type but server-reflexive, whose base pairs instead}
        boolean isPairable() {
            return type != IceCandidateType.SERVER_REFLEXIVE;
        }

        /// {@return the candidate as pairs and statistics show it}
        IceCandidate describe() {
            if (signaled != null) {
                return signaled;
            }
            return new IceCandidate(foundation, COMPONENT, protocol, priority, IceCandidate.hostString(base), base.getPort(),
                    type, tcpType, Optional.empty(), Optional.empty());
        }
    }

    /// A remote candidate with its resolved address.
    ///
    /// @param candidate the candidate as signalled (or learned)
    /// @param address   the resolved transport address
    private record RemoteCandidate(IceCandidate candidate, InetSocketAddress address) {
    }

    /// The key of a remote candidate: its transport address and protocol.
    ///
    /// @param address  the transport address
    /// @param protocol the protocol
    private record RemoteKey(InetSocketAddress address, IceProtocol protocol) {
    }

    /// The key that routes received application data to a pair.
    ///
    /// @param local  the local candidate the data arrived on
    /// @param remote the source address
    private record PairKey(LocalCandidate local, InetSocketAddress remote) {
    }

    /// A route a datagram took, valid while [#routesVersion] still holds `version`.
    ///
    /// @param local   the local candidate the datagram arrived on
    /// @param remote  its source address
    /// @param pair    the pair it routed to
    /// @param version the version of the routes it was looked up in
    private record CachedRoute(LocalCandidate local, InetSocketAddress remote, CheckPair pair, int version) {
    }

    /// A datagram queued for sending once the lock is released.
    ///
    /// @param local    the local candidate to send from
    /// @param link     the TCP connection of an ICE-TCP pair, or `null`
    /// @param remote   the destination
    /// @param datagram the datagram
    private record Outgoing(LocalCandidate local, TcpLink link, InetSocketAddress remote, ByteBuffer datagram) {
    }

    /// One outstanding connectivity or consent check.
    private static final class Check {
        /// The transaction id.
        private final StunTransactionId id;

        /// The pair checked.
        private final CheckPair pair;

        /// The encoded request.
        private final ByteBuffer encoded;

        /// Whether the check carries `USE-CANDIDATE`.
        private final boolean useCandidate;

        /// Whether it is a consent check, sent once.
        private final boolean consent;

        /// The role the check was sent in.
        private final IceRole role;

        /// Whether it runs over TCP, without retransmission.
        private final boolean reliable;

        /// How many times it was sent.
        private int transmissions;

        /// When it was last sent.
        private long sentAt;

        /// The retransmission timer.
        private IceScheduler.Cancellable timer;

        /// Creates a check.
        Check(StunTransactionId id, CheckPair pair, ByteBuffer encoded, boolean useCandidate, boolean consent,
              IceRole role, boolean reliable) {
            this.id = id;
            this.pair = pair;
            this.encoded = encoded;
            this.useCandidate = useCandidate;
            this.consent = consent;
            this.role = role;
            this.reliable = reliable;
        }

        /// Cancels the retransmission timer.
        void cancel() {
            if (timer != null) {
                timer.cancel();
            }
        }
    }

    /// One candidate pair of the checklist with its state and counters; fields without a comment saying otherwise
    /// are guarded by the agent lock.
    private static final class CheckPair {
        /// The local candidate.
        private final LocalCandidate local;

        /// The remote candidate.
        private RemoteCandidate remote;

        /// The remote transport address.
        private final InetSocketAddress remoteAddress;

        /// The checklist state.
        private IceCandidatePairState state;

        /// Whether the pair is nominated.
        private boolean nominated;

        /// Whether the peer sent `USE-CANDIDATE` on the pair before it was valid.
        private boolean useCandidateReceived;

        /// The connectivity check in flight.
        private Check inFlight;

        /// The TCP connection of an ICE-TCP pair; volatile for the senders.
        private volatile TcpLink link;

        /// Whether an active TCP connect runs.
        private boolean connecting;

        /// The peer-reflexive local candidate a check revealed.
        private IceCandidate learnedLocal;

        /// The last consent response, or check of a lite agent.
        private long lastConsentNanos;

        /// Whether consent expired; volatile for the senders.
        private volatile boolean consentExpired;

        /// The consent timer.
        private IceScheduler.Cancellable consentTimer;

        /// The last round-trip time.
        private Duration currentRtt;

        /// The sum of round-trip times.
        private Duration totalRtt = Duration.ZERO;

        /// The counters of checks.
        private long requestsSent;

        /// The checks received.
        private long requestsReceived;

        /// The responses sent.
        private long responsesSent;

        /// The responses received.
        private long responsesReceived;

        /// The consent checks sent.
        private long consentRequestsSent;

        /// When the last check arrived.
        private long lastRequestReceivedNanos;

        /// The application packets sent, updated without the lock.
        private final AtomicLong packetsSent = new AtomicLong();

        /// The application packets received, updated without the lock.
        private final AtomicLong packetsReceived = new AtomicLong();

        /// The application bytes sent, updated without the lock.
        private final AtomicLong bytesSent = new AtomicLong();

        /// The application bytes received, updated without the lock.
        private final AtomicLong bytesReceived = new AtomicLong();

        /// When the last application packet was sent, `0` before one.
        private volatile long lastPacketSentNanos;

        /// When the last application packet arrived, `0` before one.
        private volatile long lastPacketReceivedNanos;

        /// Creates a pair.
        CheckPair(LocalCandidate local, RemoteCandidate remote) {
            this.local = local;
            this.remote = remote;
            this.remoteAddress = remote.address;
        }

        /// {@return the pair priority in `role`}
        long priority(IceRole role) {
            var localPriority = local.priority;
            var remotePriority = remote.candidate.priority();
            return role == IceRole.CONTROLLING
                    ? IceCandidatePair.priority(localPriority, remotePriority)
                    : IceCandidatePair.priority(remotePriority, localPriority);
        }

        /// {@return the pair foundation, the local and remote foundations joined}
        String foundation() {
            return local.foundation + ":" + remote.candidate.foundation();
        }

        /// {@return the public view of the pair}
        IceCandidatePair toPublic() {
            return new IceCandidatePair(learnedLocal != null ? learnedLocal : local.describe(), remote.candidate);
        }

        /// {@return a snapshot of the counters}
        IceCandidatePairStatistics statistics(boolean selected) {
            return new IceCandidatePairStatistics(toPublic(), state, nominated, selected, packetsSent.get(),
                    packetsReceived.get(), bytesSent.get(), bytesReceived.get(), Optional.ofNullable(currentRtt),
                    totalRtt, requestsSent, requestsReceived, responsesSent, responsesReceived, consentRequestsSent,
                    lastPacketSentNanos == 0 ? OptionalLong.empty() : OptionalLong.of(lastPacketSentNanos),
                    lastPacketReceivedNanos == 0 ? OptionalLong.empty() : OptionalLong.of(lastPacketReceivedNanos));
        }
    }

    /// Opens the multicast DNS responder and resolver of an agent; tests replace them.
    interface MdnsFactory {
        /// {@return a started responder}
        ///
        /// @throws IOException if it cannot be opened
        MdnsResponder openResponder() throws IOException;

        /// {@return a started resolver}
        ///
        /// @throws IOException if it cannot be opened
        MdnsResolver openResolver() throws IOException;

        /// {@return the factory of the real multicast responder and a resolver on `stack`}
        static MdnsFactory multicast(NetworkStack stack) {
            return new MdnsFactory() {
                @Override
                public MdnsResponder openResponder() throws IOException {
                    return MdnsResponder.openMulticast(stack.threadFactory());
                }

                @Override
                public MdnsResolver openResolver() throws IOException {
                    return MdnsResolver.open(stack);
                }
            };
        }
    }

    /// Builds an [IceAgent].
    ///
    /// Every setting has a default: the JDK network stack with virtual threads, the system clock, no servers, the
    /// [IceTransportPolicy#ALL] and [HostCandidatePolicy#EXPOSE] policies, the controlling role, a full agent, no
    /// candidate pool, fresh local parameters, ICE-TCP candidates, and no event listener.
    public static final class Builder {
        /// The network stack, or `null` for the default.
        private NetworkStack stack;

        /// The clock.
        private MonotonicClock clock = MonotonicClock.system();

        /// The servers.
        private List<IceServer> servers = List.of();

        /// The candidate policy.
        private IceTransportPolicy transportPolicy = IceTransportPolicy.ALL;

        /// The host candidate policy.
        private HostCandidatePolicy hostPolicy = HostCandidatePolicy.EXPOSE;

        /// The initial role.
        private IceRole role = IceRole.CONTROLLING;

        /// Whether the agent is lite.
        private boolean lite;

        /// The candidate pool size.
        private int candidatePoolSize;

        /// The local parameters, or `null` to generate them.
        private IceParameters localParameters;

        /// The event listener.
        private Consumer<IceEvent> listener = _ -> {
        };

        /// The receiver of application datagrams, or `null` for none.
        private PacketReceiver receiver;

        /// Whether TCP candidates are gathered.
        private boolean tcpCandidates = true;

        /// Whether loopback addresses are used when others exist.
        private boolean loopback;

        /// Whether link-local addresses are used.
        private boolean linkLocal;

        /// Whether virtual interfaces are used.
        private boolean virtualInterfaces = true;

        /// The filter of host addresses.
        private Predicate<NetworkInterfaceAddress> addressFilter = _ -> true;

        /// The scheduler, or `null` for the default; tests only.
        private IceScheduler scheduler;

        /// The timers; tests shorten them.
        private IceTimers timers = IceTimers.DEFAULT;

        /// The mDNS factory, or `null` for the default; tests only.
        private MdnsFactory mdnsFactory;

        /// Creates a builder with the defaults.
        private Builder() {
        }

        /// Sets the network stack every socket and thread comes from.
        ///
        /// @param stack the stack
        /// @return this builder
        public Builder networkStack(NetworkStack stack) {
            this.stack = Objects.requireNonNull(stack, "stack cannot be null");
            return this;
        }

        /// Sets the clock of timers and timestamps.
        ///
        /// @param clock the clock
        /// @return this builder
        public Builder clock(MonotonicClock clock) {
            this.clock = Objects.requireNonNull(clock, "clock cannot be null");
            return this;
        }

        /// Sets the STUN and TURN servers candidates are gathered from.
        ///
        /// @param servers the servers, copied
        /// @return this builder
        public Builder iceServers(List<IceServer> servers) {
            this.servers = List.copyOf(servers);
            return this;
        }

        /// Sets which local candidates are used.
        ///
        /// @param policy the policy
        /// @return this builder
        public Builder transportPolicy(IceTransportPolicy policy) {
            this.transportPolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets how host candidates are exposed.
        ///
        /// @param policy the policy
        /// @return this builder
        public Builder hostCandidatePolicy(HostCandidatePolicy policy) {
            this.hostPolicy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /// Sets the initial role; ignored by a lite agent, which is always controlled.
        ///
        /// @param role the role
        /// @return this builder
        public Builder role(IceRole role) {
            this.role = Objects.requireNonNull(role, "role cannot be null");
            return this;
        }

        /// Makes the agent a lite agent (RFC 8445 section 2.5): host candidates only, no checks of its own, always
        /// controlled. Its local parameters carry the `lite` flag.
        ///
        /// @param lite whether the agent is lite
        /// @return this builder
        public Builder lite(boolean lite) {
            this.lite = lite;
            return this;
        }

        /// Sets the candidate pool size; a positive size starts gathering when the agent is built and holds the
        /// candidates back until [IceAgent#gather()], as the W3C `iceCandidatePoolSize` pre-gathers.
        ///
        /// @param size the pool size, `0` for none
        /// @return this builder
        /// @throws IllegalArgumentException if `size` is negative
        public Builder candidatePoolSize(int size) {
            if (size < 0) {
                throw new IllegalArgumentException("negative candidate pool size");
            }
            this.candidatePoolSize = size;
            return this;
        }

        /// Sets the local parameters instead of generating them; the `lite` flag follows [#lite(boolean)].
        ///
        /// @param parameters the parameters
        /// @return this builder
        public Builder localParameters(IceParameters parameters) {
            this.localParameters = Objects.requireNonNull(parameters, "parameters cannot be null");
            return this;
        }

        /// Sets the listener of events, called serially on one thread of the stack.
        ///
        /// @param listener the listener
        /// @return this builder
        public Builder eventListener(Consumer<IceEvent> listener) {
            this.listener = Objects.requireNonNull(listener, "listener cannot be null");
            return this;
        }

        /// Sets the receiver of the application datagrams that arrive on the selected pair, in place before the first
        /// one can arrive; [IceAgent#setReceiver(PacketReceiver)] replaces it later.
        ///
        /// @param receiver the receiver, called on the reading thread of the socket the datagram arrived on
        /// @return this builder
        public Builder receiver(PacketReceiver receiver) {
            this.receiver = Objects.requireNonNull(receiver, "receiver cannot be null");
            return this;
        }

        /// Sets whether ICE-TCP host candidates (passive, and active for a full agent) are gathered and remote TCP
        /// candidates paired.
        ///
        /// @param enabled whether ICE-TCP is used
        /// @return this builder
        public Builder tcpCandidates(boolean enabled) {
            this.tcpCandidates = enabled;
            return this;
        }

        /// Sets whether loopback addresses are gathered when other addresses exist; they are always gathered when
        /// nothing else is.
        ///
        /// @param enabled whether loopback addresses are gathered
        /// @return this builder
        public Builder loopbackCandidates(boolean enabled) {
            this.loopback = enabled;
            return this;
        }

        /// Sets whether link-local addresses (`169.254.0.0/16`, `fe80::/10`) are gathered.
        ///
        /// @param enabled whether link-local addresses are gathered
        /// @return this builder
        public Builder linkLocalCandidates(boolean enabled) {
            this.linkLocal = enabled;
            return this;
        }

        /// Sets whether the addresses of virtual and tunnel interfaces (VPNs) are gathered; when they are, they rank
        /// below physical interfaces.
        ///
        /// @param enabled whether virtual interfaces are gathered
        /// @return this builder
        public Builder virtualInterfaceCandidates(boolean enabled) {
            this.virtualInterfaces = enabled;
            return this;
        }

        /// Sets a filter every host address must pass, such as one that keeps a single interface.
        ///
        /// @param filter the filter
        /// @return this builder
        public Builder addressFilter(Predicate<NetworkInterfaceAddress> filter) {
            this.addressFilter = Objects.requireNonNull(filter, "filter cannot be null");
            return this;
        }

        /// Sets the scheduler; tests only.
        Builder scheduler(IceScheduler scheduler) {
            this.scheduler = scheduler;
            return this;
        }

        /// Sets the timers; tests only.
        Builder timers(IceTimers timers) {
            this.timers = timers;
            return this;
        }

        /// Sets the mDNS factory; tests only.
        Builder mdnsFactory(MdnsFactory factory) {
            this.mdnsFactory = factory;
            return this;
        }

        /// {@return a new agent with these settings}
        ///
        /// The agent starts its timer and event dispatcher at once; with a candidate pool it also starts gathering.
        public IceAgent build() {
            return new IceAgent(this);
        }
    }
}
