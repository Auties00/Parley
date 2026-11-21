package com.github.auties00.parley.turn;

import java.util.OptionalLong;
import com.github.auties00.parley.net.MonotonicClock;
import com.github.auties00.parley.stun.StunAttribute;
import com.github.auties00.parley.stun.StunAttribute.ErrorCode;
import com.github.auties00.parley.stun.StunAttribute.XorPeerAddress;
import com.github.auties00.parley.stun.StunClass;
import com.github.auties00.parley.stun.StunMessage;
import com.github.auties00.parley.stun.StunMethod;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/// A relayed transport address held on a TURN server, with the permissions and channels that let peers reach it.
///
/// [TurnClient#allocate(TurnAllocationOptions,Duration)] creates the allocation; from then on its refresh timer keeps
/// it alive: the allocation is refreshed a minute before its lifetime ends, every permission every four minutes
/// (permissions last five) and every channel binding every nine minutes (bindings last ten), until [#close()] deletes
/// it. A peer can send to the relayed address only once [#createPermission(InetAddress,Duration)] (or
/// [#bindChannel(InetSocketAddress,Duration)]) installed a permission for its IP address.
///
/// [#send(ByteBuffer,InetSocketAddress)] relays a datagram to a peer as ChannelData when a channel is bound to it and
/// as a Send indication otherwise, the indication carrying `DONT-FRAGMENT` when the Allocate request did and the
/// server accepted it; datagrams from peers reach the [TurnDataReceiver] of the [TurnAllocationOptions].
///
/// An allocation fails when the server reports it gone (437 Allocation Mismatch), when a refresh cannot reach the
/// server before the allocation expires, or when the connection to the server ends; [#isActive()] then turns `false`
/// and sends fail.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
public final class TurnAllocation implements AutoCloseable {
    /// The logger of the allocation.
    private static final System.Logger LOGGER = System.getLogger(TurnAllocation.class.getName());

    /// How long a refresh may take before it counts as failed.
    private static final Duration REFRESH_TIMEOUT = Duration.ofSeconds(10);

    /// How soon a failed refresh of a still-valid allocation is retried.
    private static final long RETRY_NANOS = Duration.ofSeconds(5).toNanos();

    /// The client the allocation belongs to.
    private final TurnClient client;

    /// The relayed transport address.
    private final InetSocketAddress relayedAddress;

    /// The server-reflexive address of the client as the server saw it.
    private final Optional<InetSocketAddress> mappedAddress;

    /// The options the allocation was created with.
    private final TurnAllocationOptions options;

    /// The refresh intervals.
    private final TurnTimers timers;

    /// The clock of deadlines.
    private final MonotonicClock clock;

    /// The lock that guards the refresh state.
    private final ReentrantLock lock = new ReentrantLock();

    /// Signalled when the refresh state changes, to wake the refresh timer.
    private final Condition changed = lock.newCondition();

    /// The current lifetime; guarded by [#lock].
    private Duration lifetime;

    /// When the allocation expires; guarded by [#lock].
    private long expiresAt;

    /// When the allocation is next refreshed; guarded by [#lock].
    private long refreshAt;

    /// When each permission is next refreshed, by peer IP; guarded by [#lock].
    private final Map<InetAddress, Long> permissions = new HashMap<>();

    /// When each channel binding is next refreshed, by channel; guarded by [#lock].
    private final Map<Integer, Long> channelRefreshes = new HashMap<>();

    /// The channel bound to each peer.
    private final Map<InetSocketAddress, Integer> channelsByPeer = new ConcurrentHashMap<>();

    /// The peer bound to each channel.
    private final Map<Integer, InetSocketAddress> peersByChannel = new ConcurrentHashMap<>();

    /// The next channel number to bind; guarded by [#lock].
    private int nextChannel = ChannelData.MIN_CHANNEL;

    /// The receiver of relayed data, or `null` to drop it.
    private volatile TurnDataReceiver receiver;

    /// The token of the port reserved by `EVEN-PORT`, if the server reported one.
    private final OptionalLong reservationToken;

    /// Whether the allocation is usable.
    private volatile boolean active = true;

    /// Creates the allocation the server granted.
    TurnAllocation(TurnClient client, InetSocketAddress relayedAddress, Optional<InetSocketAddress> mappedAddress,
                   Duration lifetime, TurnAllocationOptions options, TurnTimers timers, MonotonicClock clock,
                   Optional<Long> reservationToken) {
        this.client = client;
        this.receiver = options.receiver().orElse(null);
        this.reservationToken = reservationToken.map(OptionalLong::of).orElse(OptionalLong.empty());
        this.relayedAddress = relayedAddress;
        this.mappedAddress = mappedAddress;
        this.options = options;
        this.timers = timers;
        this.clock = clock;
        setLifetime(lifetime);
    }

    /// {@return the relayed transport address peers send to}
    public InetSocketAddress relayedAddress() {
        return relayedAddress;
    }

    /// {@return the client's server-reflexive address as the TURN server saw it, from the Allocate response's
    /// `XOR-MAPPED-ADDRESS`, or an empty optional when the server did not report it}
    public Optional<InetSocketAddress> mappedAddress() {
        return mappedAddress;
    }

    /// {@return the `RESERVATION-TOKEN` of the port the server reserved for an `EVEN-PORT` request that asked for the
    /// next port, eight bytes to pass to [TurnAllocationOptions#reservationToken(byte\[\])]; empty otherwise}
    public Optional<byte[]> reservationToken() {
        if (reservationToken.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(java.nio.ByteBuffer.allocate(8).putLong(reservationToken.getAsLong()).array());
    }

    /// {@return whether the server accepted `DONT-FRAGMENT`, so Send indications carry it too}
    public boolean dontFragment() {
        return options.dontFragment();
    }

    /// {@return the TURN server holding the allocation}
    public TurnServer server() {
        return client.server();
    }

    /// {@return the lifetime the server granted at the last refresh}
    public Duration lifetime() {
        lock.lock();
        try {
            return lifetime;
        } finally {
            lock.unlock();
        }
    }

    /// {@return whether the allocation is usable: not closed, not expired, and not reported gone by the server}
    public boolean isActive() {
        return active && !client.isClosed();
    }

    /// {@return the largest datagram a peer receives through the relay without IP fragmentation, after the IP, UDP
    /// or TCP and ChannelData overhead of both legs}
    public int maxPayloadSize() {
        return client.maxPayloadSize(relayedAddress);
    }

    /// {@return whether a permission for `peer` is installed}
    ///
    /// @param peer the peer's IP address
    public boolean hasPermission(InetAddress peer) {
        lock.lock();
        try {
            return permissions.containsKey(peer);
        } finally {
            lock.unlock();
        }
    }

    /// {@return the channel bound to `peer`, or an empty optional when none is}
    ///
    /// @param peer the peer's address
    public OptionalInt channel(InetSocketAddress peer) {
        var channel = channelsByPeer.get(peer);
        return channel == null ? OptionalInt.empty() : OptionalInt.of(channel);
    }

    /// Installs a permission for one peer IP address; see [#createPermissions(Collection,Duration)].
    ///
    /// @param peer    the peer's IP address
    /// @param timeout the longest time the request may take
    /// @throws TurnException        if the server refused the permission (403 Forbidden, 443 family mismatch)
    /// @throws IOException          if the server did not answer or the allocation is no longer active
    /// @throws InterruptedException if the calling thread is interrupted
    public void createPermission(InetAddress peer, Duration timeout) throws IOException, InterruptedException {
        createPermissions(List.of(peer), timeout);
    }

    /// Installs permissions for peer IP addresses with one CreatePermission request, blocking until the server
    /// answers.
    ///
    /// Installed permissions are refreshed every four minutes for as long as the allocation lives. Installing a
    /// permission that already exists refreshes it.
    ///
    /// @param peers   the peers' IP addresses, at least one
    /// @param timeout the longest time the request may take
    /// @throws TurnException            if the server refused the permissions
    /// @throws IOException              if the server did not answer or the allocation is no longer active
    /// @throws InterruptedException     if the calling thread is interrupted
    /// @throws IllegalArgumentException if `peers` is empty
    public void createPermissions(Collection<InetAddress> peers, Duration timeout) throws IOException, InterruptedException {
        Objects.requireNonNull(peers, "peers cannot be null");
        Objects.requireNonNull(timeout, "timeout cannot be null");
        if (peers.isEmpty()) {
            throw new IllegalArgumentException("no peer");
        }
        ensureActive();
        var attributes = new ArrayList<StunAttribute>(peers.size());
        for (var peer : peers) {
            attributes.add(new XorPeerAddress(new InetSocketAddress(Objects.requireNonNull(peer, "peer cannot be null"), 0)));
        }
        var response = client.transact(StunMethod.CREATE_PERMISSION, attributes, timeout);
        requireSuccess(response, "CreatePermission");
        lock.lock();
        try {
            var due = clock.nanos() + timers.permissionRefresh().toNanos();
            peers.forEach(peer -> permissions.put(peer, due));
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Binds a channel to a peer, blocking until the server answers, and returns the channel number.
    ///
    /// The binding also installs a permission for the peer's IP address. From now on [#send(ByteBuffer,InetSocketAddress)]
    /// sends to the peer as ChannelData, four bytes of overhead instead of a Send indication's thirty-six or more.
    /// The binding is refreshed every nine minutes. Binding an already bound peer returns its channel at once.
    ///
    /// @param peer    the peer's address
    /// @param timeout the longest time the request may take
    /// @return the channel number, `0x4000..0x4FFF`
    /// @throws TurnException        if the server refused the binding, or every channel number is used
    /// @throws IOException          if the server did not answer or the allocation is no longer active
    /// @throws InterruptedException if the calling thread is interrupted
    public int bindChannel(InetSocketAddress peer, Duration timeout) throws IOException, InterruptedException {
        Objects.requireNonNull(peer, "peer cannot be null");
        Objects.requireNonNull(timeout, "timeout cannot be null");
        ensureActive();
        var existing = channelsByPeer.get(peer);
        if (existing != null) {
            return existing;
        }
        int channel;
        lock.lock();
        try {
            if (nextChannel > ChannelData.MAX_CHANNEL) {
                throw new TurnException("every channel number is bound");
            }
            channel = nextChannel++;
        } finally {
            lock.unlock();
        }
        sendChannelBind(channel, peer, timeout);
        lock.lock();
        try {
            var now = clock.nanos();
            channelRefreshes.put(channel, now + timers.channelRefresh().toNanos());
            permissions.put(peer.getAddress(), now + timers.permissionRefresh().toNanos());
            peersByChannel.put(channel, peer);
            channelsByPeer.put(peer, channel);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        return channel;
    }

    /// Relays one datagram to a peer.
    ///
    /// The datagram is the buffer's remaining bytes. It goes out as ChannelData when a channel is bound to the peer,
    /// and as a Send indication otherwise. The server drops it unless a permission for the peer's IP address is
    /// installed.
    ///
    /// @param data the datagram
    /// @param peer the peer's address
    /// @throws IOException if the allocation is no longer active or the connection to the server failed
    public void send(ByteBuffer data, InetSocketAddress peer) throws IOException {
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(peer, "peer cannot be null");
        ensureActive();
        var channel = channelsByPeer.get(peer);
        if (channel != null) {
            client.sendRaw(ChannelData.encode(channel, data, client.isStream()));
            return;
        }
        var attributes = options.dontFragment()
                ? List.<StunAttribute>of(new XorPeerAddress(peer), new StunAttribute.DontFragment(),
                new StunAttribute.Data(data))
                : List.<StunAttribute>of(new XorPeerAddress(peer), new StunAttribute.Data(data));
        client.sendRaw(StunMessage.indication(StunMethod.SEND, attributes).encode(false));
    }

    /// Sets the receiver of datagrams relayed from peers, replacing the previous one.
    ///
    /// @param receiver the receiver
    /// @deprecated give the receiver to [TurnAllocationOptions#receiver(TurnDataReceiver)]; datagrams relayed before
    /// this call are dropped
    @Deprecated(forRemoval = true)
    public void setReceiver(TurnDataReceiver receiver) {
        // TODO: remove once ice.IceAgent passes the receiver in its TurnAllocationOptions (cross-group).
        this.receiver = Objects.requireNonNull(receiver, "receiver cannot be null");
    }

    /// Deletes the allocation and closes the client it belongs to; see [TurnClient#close()].
    @Override
    public void close() {
        client.close();
    }

    /// Delivers a ChannelData message from the server.
    void onChannelData(ByteBuffer packet, long arrival) {
        var peer = peersByChannel.get(ChannelData.channel(packet));
        var current = receiver;
        if (peer != null && current != null) {
            deliver(current, peer, ChannelData.payload(packet), arrival);
        }
    }

    /// Delivers a Data indication from the server.
    void onDataIndication(StunMessage indication, long arrival) {
        var peer = indication.attribute(XorPeerAddress.class);
        var data = indication.attribute(StunAttribute.Data.class);
        var current = receiver;
        if (peer.isPresent() && data.isPresent() && current != null) {
            deliver(current, peer.get().address(), data.get().value(), arrival);
        }
    }

    /// Hands a datagram to the receiver, logging what it throws.
    private void deliver(TurnDataReceiver current, InetSocketAddress peer, ByteBuffer data, long arrival) {
        try {
            current.receive(peer, data, arrival);
        } catch (RuntimeException exception) {
            if (LOGGER.isLoggable(Level.WARNING)) {
                LOGGER.log(Level.WARNING, "the TURN data receiver failed", exception);
            }
        }
    }

    /// Marks the allocation unusable and wakes the refresh timer so it ends.
    void markFailed() {
        active = false;
        lock.lock();
        try {
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Deletes the allocation on the server with a zero-lifetime Refresh, waiting at most the close timeout.
    void deallocate() {
        if (!active) {
            return;
        }
        markFailed();
        try {
            client.transact(StunMethod.REFRESH, List.of(new StunAttribute.Lifetime(Duration.ZERO)), timers.closeTimeout());
        } catch (IOException _) {
            // The server deletes the allocation when its lifetime runs out anyway.
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
        }
    }

    /// Runs the refresh timer until the allocation fails or is closed.
    void refreshLoop() {
        while (isActive()) {
            List<InetAddress> duePermissions;
            List<Integer> dueChannels;
            boolean dueAllocation;
            lock.lock();
            try {
                var now = clock.nanos();
                var next = refreshAt;
                for (var due : permissions.values()) {
                    next = Math.min(next, due);
                }
                for (var due : channelRefreshes.values()) {
                    next = Math.min(next, due);
                }
                if (next - now > 0) {
                    changed.awaitNanos(next - now);
                    continue;
                }
                dueAllocation = refreshAt - now <= 0;
                duePermissions = permissions.entrySet().stream().filter(entry -> entry.getValue() - now <= 0).map(Map.Entry::getKey).toList();
                dueChannels = channelRefreshes.entrySet().stream().filter(entry -> entry.getValue() - now <= 0).map(Map.Entry::getKey).toList();
            } catch (InterruptedException exception) {
                return;
            } finally {
                lock.unlock();
            }
            try {
                if (dueAllocation) {
                    refreshAllocation();
                }
                if (!duePermissions.isEmpty()) {
                    refreshPermissions(duePermissions);
                }
                for (var channel : dueChannels) {
                    refreshChannel(channel);
                }
            } catch (InterruptedException exception) {
                return;
            }
        }
    }

    /// Refreshes the allocation, failing it when the server reports it gone or it expired unrefreshed.
    private void refreshAllocation() throws InterruptedException {
        try {
            var attributes = options.lifetime()
                    .<List<StunAttribute>>map(value -> List.of(new StunAttribute.Lifetime(value)))
                    .orElse(List.of());
            var response = client.transact(StunMethod.REFRESH, attributes, REFRESH_TIMEOUT);
            requireSuccess(response, "Refresh");
            var granted = response.attribute(StunAttribute.Lifetime.class).map(StunAttribute.Lifetime::lifetime).orElse(lifetime());
            setLifetime(granted);
        } catch (TurnException exception) {
            if (exception.errorCode().orElse(0) == ErrorCode.ALLOCATION_MISMATCH) {
                markFailed();
                return;
            }
            retryOrFail(exception);
        } catch (IOException exception) {
            retryOrFail(exception);
        }
    }

    /// Schedules another refresh soon, or fails the allocation if it already expired.
    private void retryOrFail(IOException exception) {
        if (LOGGER.isLoggable(Level.DEBUG)) {
            LOGGER.log(Level.DEBUG, "TURN allocation refresh failed", exception);
        }
        lock.lock();
        try {
            var now = clock.nanos();
            if (expiresAt - now <= 0) {
                active = false;
                return;
            }
            refreshAt = now + Math.min(RETRY_NANOS, expiresAt - now);
        } finally {
            lock.unlock();
        }
    }

    /// Refreshes permissions, dropping the ones the server refuses.
    private void refreshPermissions(List<InetAddress> peers) throws InterruptedException {
        try {
            createPermissions(peers, REFRESH_TIMEOUT);
        } catch (IOException exception) {
            lock.lock();
            try {
                var due = clock.nanos() + RETRY_NANOS;
                peers.forEach(peer -> permissions.computeIfPresent(peer, (_, _) -> due));
            } finally {
                lock.unlock();
            }
        }
    }

    /// Refreshes one channel binding, retrying soon when it fails.
    private void refreshChannel(int channel) throws InterruptedException {
        var peer = peersByChannel.get(channel);
        if (peer == null) {
            return;
        }
        long due;
        try {
            sendChannelBind(channel, peer, REFRESH_TIMEOUT);
            due = clock.nanos() + timers.channelRefresh().toNanos();
        } catch (IOException exception) {
            due = clock.nanos() + RETRY_NANOS;
        }
        lock.lock();
        try {
            channelRefreshes.put(channel, due);
        } finally {
            lock.unlock();
        }
    }

    /// Sends a ChannelBind request and fails unless it succeeds.
    private void sendChannelBind(int channel, InetSocketAddress peer, Duration timeout) throws IOException, InterruptedException {
        var response = client.transact(StunMethod.CHANNEL_BIND,
                List.of(new StunAttribute.ChannelNumber(channel), new XorPeerAddress(peer)), timeout);
        requireSuccess(response, "ChannelBind");
    }

    /// Records a granted lifetime and schedules the next refresh.
    private void setLifetime(Duration granted) {
        lock.lock();
        try {
            var now = clock.nanos();
            lifetime = granted;
            expiresAt = now + granted.toNanos();
            var margin = timers.allocationMargin().toNanos();
            var lead = granted.toNanos() > 2 * margin ? granted.toNanos() - margin : granted.toNanos() / 2;
            refreshAt = now + Math.max(1, lead);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /// Fails unless the allocation is active.
    private void ensureActive() throws IOException {
        if (!isActive()) {
            throw new TurnException("the TURN allocation is no longer active");
        }
    }

    /// Fails unless `response` is a success response, with the error code of an error response.
    private static void requireSuccess(StunMessage response, String request) throws TurnException {
        if (response.messageClass() == StunClass.SUCCESS_RESPONSE) {
            return;
        }
        var error = response.errorCode();
        if (error.isPresent()) {
            throw new TurnException(request + " failed: " + error.get().code() + " " + error.get().reason(), error.get().code());
        }
        throw new TurnException(request + " failed without an error code");
    }

    /// {@return the relayed address and the server}
    @Override
    public String toString() {
        return "TurnAllocation[relayed=" + relayedAddress + ", server=" + client.server().host() + ", active=" + isActive() + "]";
    }
}
