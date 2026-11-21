package com.github.auties00.parley.ice;

import com.github.auties00.parley.mdns.MemoryMdnsLink;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.turn.TestCertificates;
import com.github.auties00.parley.turn.TestTurnServer;
import com.github.auties00.parley.turn.TurnTransport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;

import static com.github.auties00.parley.ice.IceTestPeers.loopbackBuilder;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Runs pairs of ICE agents against each other over real sockets on the loopback interface: full and lite agents,
/// role conflicts, ICE-TCP, TURN relays over UDP, TCP and TLS, mDNS candidates, candidate pools, ICE restarts,
/// failure and statistics.
@DisplayName("IceAgent over loopback")
@Timeout(60)
class IceAgentTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private static void exchange(IceAgent from, IceAgent to) throws Exception {
        var inbox = new IceTestPeers.Inbox();
        to.setReceiver(inbox);
        var payload = ("hello " + System.nanoTime()).getBytes(StandardCharsets.UTF_8);
        byte[] received = null;
        for (var attempt = 0; attempt < 20 && received == null; attempt++) {
            from.send(ByteBuffer.wrap(payload));
            received = inbox.next(Duration.ofMillis(250));
        }
        assertArrayEquals(payload, received);
    }

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out waiting for " + what);
            }
            Thread.sleep(10);
        }
    }

    @Test
    @DisplayName("connects two full agents over UDP, exchanges data both ways and completes")
    void fullAgents() throws Exception {
        try (var peers = new IceTestPeers(loopbackBuilder().role(IceRole.CONTROLLING), loopbackBuilder().role(IceRole.CONTROLLED),
                candidate -> true, candidate -> true)) {
            peers.gather();
            peers.awaitConnected(TIMEOUT);
            exchange(peers.first, peers.second);
            exchange(peers.second, peers.first);
            await(() -> peers.first.state() == IceTransportState.COMPLETED, "the controlling agent to complete");
            await(() -> peers.second.state() == IceTransportState.COMPLETED, "the controlled agent to complete");
            var firstPair = peers.first.selectedPair().orElseThrow();
            var secondPair = peers.second.selectedPair().orElseThrow();
            assertEquals(firstPair.local().port(), secondPair.remote().port());
            assertEquals(IceRole.CONTROLLING, peers.first.role());
            assertTrue(peers.firstEvents.stream().anyMatch(event -> event instanceof IceEvent.SelectedPairChanged));
            assertTrue(peers.secondEvents.contains(new IceEvent.GatheringStateChanged(IceGatheringState.COMPLETE)));
            var statistics = peers.first.statistics();
            assertTrue(statistics.packetsSent() >= 1);
            assertTrue(statistics.pairs().stream().anyMatch(pair -> pair.selected() && pair.nominated()
                    && pair.requestsSent() > 0 && pair.responsesReceived() > 0 && pair.currentRoundTripTime().isPresent()));
            assertTrue(peers.first.maxDatagramSize() > 1400);
            assertFalse(peers.first.localCandidates().isEmpty());
            assertTrue(peers.first.localCandidates().stream().allMatch(candidate ->
                    candidate.usernameFragment().equals(Optional.of(peers.first.localParameters().usernameFragment()))));
        }
    }

    @ParameterizedTest
    @EnumSource(IceRole.class)
    @DisplayName("resolves a role conflict when both agents claim the same role")
    void roleConflict(IceRole role) throws Exception {
        try (var peers = new IceTestPeers(loopbackBuilder().role(role), loopbackBuilder().role(role), candidate -> true, candidate -> true)) {
            peers.gather();
            peers.awaitConnected(TIMEOUT);
            await(() -> peers.first.role() != peers.second.role(), "the roles to differ");
            exchange(peers.first, peers.second);
        }
    }

    @Test
    @DisplayName("connects a full agent to a lite agent, which never sends checks")
    void liteAgent() throws Exception {
        try (var peers = new IceTestPeers(loopbackBuilder().role(IceRole.CONTROLLED), loopbackBuilder().lite(true),
                candidate -> true, candidate -> true)) {
            assertTrue(peers.second.localParameters().lite());
            assertEquals(IceRole.CONTROLLED, peers.second.role());
            assertEquals(IceRole.CONTROLLING, peers.first.role());
            peers.gather();
            peers.awaitConnected(TIMEOUT);
            exchange(peers.first, peers.second);
            exchange(peers.second, peers.first);
            var liteStatistics = peers.second.statistics();
            assertTrue(liteStatistics.pairs().stream().allMatch(pair -> pair.requestsSent() == 0));
            assertTrue(liteStatistics.pairs().stream().anyMatch(pair -> pair.requestsReceived() > 0));
        }
    }

    @Test
    @DisplayName("connects over ICE-TCP when only TCP candidates are signalled (RFC 6544 framing)")
    void iceTcp() throws Exception {
        var tcpOnly = (java.util.function.Predicate<IceCandidate>) candidate -> candidate.protocol() == IceProtocol.TCP;
        try (var peers = new IceTestPeers(loopbackBuilder().role(IceRole.CONTROLLING), loopbackBuilder().role(IceRole.CONTROLLED),
                tcpOnly, tcpOnly)) {
            peers.gather();
            peers.awaitConnected(TIMEOUT);
            assertEquals(IceProtocol.TCP, peers.first.selectedPair().orElseThrow().local().protocol());
            exchange(peers.first, peers.second);
            exchange(peers.second, peers.first);
            var large = new byte[1300];
            new java.util.Random(1).nextBytes(large);
            var inbox = new IceTestPeers.Inbox();
            peers.second.setReceiver(inbox);
            peers.first.send(ByteBuffer.wrap(large));
            assertArrayEquals(large, inbox.next(Duration.ofSeconds(5)));
        }
    }

    @ParameterizedTest
    @EnumSource(TurnTransport.class)
    @DisplayName("relays through TURN under the relay-only policy")
    void relayOnly(TurnTransport transport) throws Exception {
        try (var server = TestTurnServer.start()) {
            var stack = NetworkStack.system(Thread.ofVirtual().name("relay-", 0).factory(), TestCertificates.clientContext());
            var turn = new IceServer(List.of(server.turnUri(transport)), Optional.of(TestTurnServer.USERNAME), Optional.of(TestTurnServer.PASSWORD));
            var relayed = loopbackBuilder().networkStack(stack).iceServers(List.of(turn)).transportPolicy(IceTransportPolicy.RELAY)
                    .role(IceRole.CONTROLLING);
            try (var peers = new IceTestPeers(relayed, loopbackBuilder().role(IceRole.CONTROLLED), candidate -> true, candidate -> true)) {
                peers.gather();
                peers.awaitConnected(TIMEOUT);
                assertTrue(peers.firstEvents.stream().allMatch(event -> !(event instanceof IceEvent.CandidateGathered(var candidate, var source))
                        || candidate.type() == IceCandidateType.RELAY));
                assertEquals(IceCandidateType.RELAY, peers.first.selectedPair().orElseThrow().local().type());
                exchange(peers.first, peers.second);
                exchange(peers.second, peers.first);
                await(() -> server.channelBinds() >= 1, "the relayed pair to bind a channel");
                exchange(peers.first, peers.second);
                exchange(peers.second, peers.first);
                assertTrue(peers.first.maxDatagramSize() < 1500);
            }
            await(() -> server.deallocations() >= 1, "the allocation to be deleted on close");
        }
    }

    @Test
    @DisplayName("hides host candidates behind mDNS names, resolves them, and sends srflx with raddr 0.0.0.0 rport 0")
    void mdnsCandidates() throws Exception {
        try (var server = TestTurnServer.start()) {
            var link = new MemoryMdnsLink();
            var stun = IceServer.of(server.stunUri().toString());
            var hidden = loopbackBuilder().hostCandidatePolicy(HostCandidatePolicy.MDNS).mdnsFactory(IceTestPeers.memoryMdns(link, "10.0.0.1"))
                    .iceServers(List.of(stun)).tcpCandidates(false).role(IceRole.CONTROLLING);
            var other = loopbackBuilder().mdnsFactory(IceTestPeers.memoryMdns(link, "10.0.0.2")).tcpCandidates(false).role(IceRole.CONTROLLED);
            try (var peers = new IceTestPeers(hidden, other, candidate -> candidate.type() == IceCandidateType.HOST, candidate -> true)) {
                peers.gather();
                peers.awaitConnected(TIMEOUT);
                var gathered = peers.firstEvents.stream()
                        .flatMap(event -> event instanceof IceEvent.CandidateGathered(var candidate, var source) ? java.util.stream.Stream.of(candidate) : java.util.stream.Stream.empty())
                        .toList();
                assertTrue(gathered.stream().filter(candidate -> candidate.type() == IceCandidateType.HOST).allMatch(IceCandidate::isMdns));
                var reflexive = gathered.stream().filter(candidate -> candidate.type() == IceCandidateType.SERVER_REFLEXIVE).findFirst().orElseThrow();
                assertEquals(Optional.of(new InetSocketAddress(InetAddress.ofLiteral("0.0.0.0"), 0)), reflexive.relatedAddress());
                assertTrue(peers.second.remoteCandidates().stream().anyMatch(IceCandidate::isMdns));
                exchange(peers.first, peers.second);
            }
        }
    }

    @Test
    @DisplayName("holds pooled candidates back until gather() and then reports them")
    void candidatePool() throws Exception {
        var events = new java.util.concurrent.CopyOnWriteArrayList<IceEvent>();
        try (var agent = loopbackBuilder().candidatePoolSize(1).eventListener(events::add).build()) {
            await(() -> agent.gatheringState() == IceGatheringState.COMPLETE, "the pool to fill");
            Thread.sleep(100);
            assertTrue(events.stream().noneMatch(event -> event instanceof IceEvent.CandidateGathered));
            assertTrue(agent.localCandidates().isEmpty());
            agent.gather();
            await(() -> events.contains(new IceEvent.GatheringStateChanged(IceGatheringState.COMPLETE)), "the pooled events");
            assertTrue(events.stream().anyMatch(event -> event instanceof IceEvent.CandidateGathered));
            assertFalse(agent.localCandidates().isEmpty());
        }
    }

    @Test
    @DisplayName("keeps media flowing during an ICE restart and selects a pair of the new generation")
    void restart() throws Exception {
        try (var peers = new IceTestPeers(loopbackBuilder().role(IceRole.CONTROLLING).tcpCandidates(false),
                loopbackBuilder().role(IceRole.CONTROLLED).tcpCandidates(false), candidate -> true, candidate -> true)) {
            peers.gather();
            peers.awaitConnected(TIMEOUT);
            var changesBefore = peers.first.statistics().selectedCandidatePairChanges();
            var firstNew = IceParameters.generate();
            var secondNew = IceParameters.generate();
            peers.first.restart(firstNew);
            exchange(peers.first, peers.second);
            peers.second.restart(secondNew);
            peers.first.setRemoteParameters(secondNew);
            peers.second.setRemoteParameters(firstNew);
            // Signalling delivers the new descriptions before the candidates of the new generation.
            peers.first.localCandidates().forEach(peers.second::addRemoteCandidate);
            peers.second.localCandidates().forEach(peers.first::addRemoteCandidate);
            peers.first.endOfRemoteCandidates();
            peers.second.endOfRemoteCandidates();
            exchange(peers.first, peers.second);
            exchange(peers.second, peers.first);
            await(() -> peers.first.statistics().selectedCandidatePairChanges() > changesBefore, "a pair of the new generation");
            assertEquals(firstNew.usernameFragment(), peers.first.localParameters().usernameFragment());
            assertTrue(peers.first.localCandidates().stream().allMatch(candidate ->
                    candidate.usernameFragment().equals(Optional.of(firstNew.usernameFragment()))));
            exchange(peers.first, peers.second);
            assertThrows(IllegalArgumentException.class, () -> peers.first.restart(firstNew));
        }
    }

    @Test
    @DisplayName("fails when every pair fails after the end of candidates, and refuses to send")
    void failure() throws Exception {
        var timers = new IceTimers(Duration.ofMillis(20), new com.github.auties00.parley.stun.StunRetransmission(Duration.ofMillis(50), 3, 2, false),
                Duration.ofSeconds(1), Duration.ofMillis(100), Duration.ofSeconds(5), Duration.ofSeconds(10), Duration.ofSeconds(30),
                Duration.ofSeconds(1), Duration.ofSeconds(1));
        try (var agent = loopbackBuilder().timers(timers).tcpCandidates(false).build()) {
            assertThrows(IceException.class, () -> agent.send(ByteBuffer.wrap(new byte[1])));
            agent.gather();
            agent.setRemoteParameters(IceParameters.generate());
            agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 udp 2130706431 127.0.0.1 9 typ host"));
            agent.addRemoteCandidate(IceCandidate.parse("candidate:2 1 udp 2130706431 dead.example 9 typ host"));
            agent.endOfRemoteCandidates();
            assertThrows(IceException.class, () -> agent.awaitConnected(TIMEOUT));
            assertEquals(IceTransportState.FAILED, agent.state());
            assertEquals(1, agent.remoteCandidates().size());
        }
    }

    @Test
    @DisplayName("ignores candidates of another generation or component and times out without a peer")
    void ignoredCandidates() throws Exception {
        try (var agent = loopbackBuilder().tcpCandidates(false).build()) {
            var remote = IceParameters.generate();
            agent.setRemoteParameters(remote);
            agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 udp 1 127.0.0.1 9 typ host ufrag other"));
            agent.addRemoteCandidate(IceCandidate.parse("candidate:1 2 udp 1 127.0.0.1 9 typ host"));
            agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 tcp 1 127.0.0.1 9 typ host tcptype so"));
            assertTrue(agent.remoteCandidates().isEmpty());
            assertFalse(agent.awaitConnected(Duration.ofMillis(200)));
            agent.close();
            assertEquals(IceTransportState.CLOSED, agent.state());
            assertThrows(IllegalStateException.class, agent::gather);
            assertThrows(IceException.class, () -> agent.awaitConnected(Duration.ofMillis(10)));
        }
    }

    @Test
    @DisplayName("learns a peer-reflexive remote candidate from a check that arrives before signalling")
    void peerReflexive() throws Exception {
        try (var peers = new IceTestPeers(loopbackBuilder().role(IceRole.CONTROLLING).tcpCandidates(false),
                loopbackBuilder().role(IceRole.CONTROLLED).tcpCandidates(false), candidate -> true, candidate -> false)) {
            peers.gather();
            peers.awaitConnected(TIMEOUT);
            assertTrue(peers.first.remoteCandidates().stream().anyMatch(candidate -> candidate.type() == IceCandidateType.PEER_REFLEXIVE));
            exchange(peers.first, peers.second);
            assertNotEquals(Optional.empty(), peers.first.selectedPair());
        }
    }

    @Test
    @DisplayName("reports a STUN server it cannot reach as a candidate error")
    void candidateError() throws Exception {
        var timers = new IceTimers(Duration.ofMillis(50), com.github.auties00.parley.stun.StunRetransmission.UDP, Duration.ofSeconds(1),
                Duration.ofMillis(500), Duration.ofSeconds(5), Duration.ofSeconds(10), Duration.ofSeconds(30), Duration.ofMillis(600),
                Duration.ofSeconds(1));
        var events = new java.util.concurrent.CopyOnWriteArrayList<IceEvent>();
        try (var silent = java.nio.channels.DatagramChannel.open().bind(new InetSocketAddress(IceTestPeers.loopback(), 0))) {
            var url = URI.create("stun:127.0.0.1:" + ((InetSocketAddress) silent.getLocalAddress()).getPort());
            try (var agent = loopbackBuilder().timers(timers).tcpCandidates(false).eventListener(events::add)
                    .iceServers(List.of(new IceServer(List.of(url), Optional.empty(), Optional.empty()))).build()) {
                agent.gather();
                await(() -> agent.gatheringState() == IceGatheringState.COMPLETE, "gathering to end");
                await(() -> events.stream().anyMatch(event -> event instanceof IceEvent.CandidateError error
                        && error.server().equals(url) && error.errorCode() == IceEvent.CandidateError.UNREACHABLE
                        && error.localAddress().isPresent()), "the candidate error with its local address");
                assertTrue(events.contains(new IceEvent.CandidateError(url,
                        events.stream().filter(IceEvent.CandidateError.class::isInstance).map(IceEvent.CandidateError.class::cast)
                                .findFirst().orElseThrow().localAddress(), IceEvent.CandidateError.UNREACHABLE,
                        events.stream().filter(IceEvent.CandidateError.class::isInstance).map(IceEvent.CandidateError.class::cast)
                                .map(IceEvent.CandidateError::reason).findFirst().orElse(""))));
            }
        }
    }
}
