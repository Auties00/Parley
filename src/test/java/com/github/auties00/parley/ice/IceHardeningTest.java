package com.github.auties00.parley.ice;

import com.github.auties00.parley.mdns.MdnsResolver;
import com.github.auties00.parley.mdns.MdnsResponder;
import com.github.auties00.parley.mdns.MemoryMdnsLink;
import com.github.auties00.parley.net.NetworkStack;
import com.github.auties00.parley.stun.StunAddressFamily;
import com.github.auties00.parley.turn.TestCertificates;
import com.github.auties00.parley.turn.TestTurnServer;
import com.github.auties00.parley.turn.TurnTransport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

import static com.github.auties00.parley.ice.IceTestPeers.loopbackBuilder;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Regression tests for untrusted remote candidates (the per-generation cap, bounded and deduplicated mDNS
/// resolution), the privacy and priority of reflexive and relayed candidates, the W3C members of candidate events,
/// `stuns:` gathering, an unavailable mDNS responder, and the builder-registered receiver.
@DisplayName("IceAgent hardening")
@Timeout(60)
class IceHardeningTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out waiting for " + what);
            }
            Thread.sleep(10);
        }
    }

    private static List<IceEvent.CandidateGathered> gathered(List<IceEvent> events) {
        return events.stream().filter(IceEvent.CandidateGathered.class::isInstance)
                .map(IceEvent.CandidateGathered.class::cast).toList();
    }

    @Test
    @DisplayName("keeps at most 100 remote candidates per generation and counts the rest")
    void remoteCandidateCap() throws Exception {
        try (var agent = loopbackBuilder().tcpCandidates(false).build()) {
            agent.setRemoteParameters(IceParameters.generate());
            for (var index = 0; index < 120; index++) {
                agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 udp 2130706431 127.0.0.1 " + (20000 + index)
                        + " typ host"));
            }
            assertEquals(IceAgent.MAX_REMOTE_CANDIDATES, agent.remoteCandidates().size());
            assertEquals(20, agent.statistics().remoteCandidatesDropped());
            agent.setRemoteParameters(IceParameters.generate());
            agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 udp 2130706431 127.0.0.1 30000 typ host"));
            assertEquals(1, agent.remoteCandidates().size(), "a new generation starts a new budget");
        }
    }

    @Test
    @DisplayName("queues at most 32 .local names, resolving each name once")
    void boundedResolutions() throws Exception {
        var link = new MemoryMdnsLink();
        var timers = new IceTimers(Duration.ofMillis(50), com.github.auties00.parley.stun.StunRetransmission.UDP,
                Duration.ofSeconds(1), Duration.ofMillis(500), Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(30), Duration.ofSeconds(1), Duration.ofSeconds(5));
        try (var agent = loopbackBuilder().tcpCandidates(false).timers(timers)
                .mdnsFactory(IceTestPeers.memoryMdns(link, "10.0.0.9")).build()) {
            agent.setRemoteParameters(IceParameters.generate());
            for (var index = 0; index < 40; index++) {
                var name = UUID.randomUUID() + ".local";
                agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 udp 2130706431 " + name + " 9 typ host"));
                agent.addRemoteCandidate(IceCandidate.parse("candidate:2 1 udp 2130706431 " + name + " 10 typ host"));
            }
            assertTrue(agent.pendingResolutionCount() <= IceAgent.MAX_PENDING_RESOLUTIONS,
                    "pending: " + agent.pendingResolutionCount());
            assertTrue(agent.statistics().remoteCandidatesDropped() >= 2 * (40 - IceAgent.MAX_PENDING_RESOLUTIONS) - 2,
                    "dropped: " + agent.statistics().remoteCandidatesDropped());
        }
    }

    @Test
    @DisplayName("resolves a .local name carried by two candidates once and pairs both")
    void deduplicatedResolution() throws Exception {
        var link = new MemoryMdnsLink();
        var responder = new MdnsResponder(link.channel("10.0.0.2", 5353), Thread.ofVirtual().factory());
        try (responder; var agent = loopbackBuilder().tcpCandidates(false)
                .mdnsFactory(IceTestPeers.memoryMdns(link, "10.0.0.9")).build()) {
            var name = responder.register(InetAddress.ofLiteral("127.0.0.1"));
            agent.setRemoteParameters(IceParameters.generate());
            agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 udp 2130706431 " + name + " 40000 typ host"));
            agent.addRemoteCandidate(IceCandidate.parse("candidate:2 1 udp 2130706431 " + name + " 40001 typ host"));
            await(() -> agent.remoteCandidates().size() == 2, "both candidates resolved");
            assertEquals(0, agent.pendingResolutionCount());
        }
    }

    @Test
    @DisplayName("gives every relayed candidate a unique local preference, UDP above TCP above TLS")
    void relayLocalPreference() {
        var seen = new HashSet<Integer>();
        for (var index = 0; index < 50; index++) {
            for (var family : StunAddressFamily.values()) {
                for (var protocol : IceProtocol.values()) {
                    var preference = IceAgent.relayLocalPreference(index, family, protocol);
                    assertTrue(preference >= 0 && preference <= 0xFFFF);
                    assertTrue(seen.add(preference), "duplicate " + preference);
                }
            }
        }
        assertTrue(IceAgent.relayLocalPreference(5, StunAddressFamily.IPV4, IceProtocol.UDP)
                > IceAgent.relayLocalPreference(0, StunAddressFamily.IPV6, IceProtocol.TCP));
        assertTrue(IceAgent.relayLocalPreference(0, StunAddressFamily.IPV4, IceProtocol.TCP)
                > IceAgent.relayLocalPreference(0, StunAddressFamily.IPV4, IceProtocol.TLS));
        assertTrue(IceAgent.relayLocalPreference(0, StunAddressFamily.IPV4, IceProtocol.UDP)
                > IceAgent.relayLocalPreference(1, StunAddressFamily.IPV4, IceProtocol.UDP));
    }

    @Test
    @DisplayName("signals relayed and reflexive candidates with their server, relay protocol and a hidden raddr")
    void relayedCandidateMembers() throws Exception {
        try (var server = TestTurnServer.start()) {
            var turn = new IceServer(List.of(server.turnUri(TurnTransport.UDP), server.stunUri()),
                    Optional.of(TestTurnServer.USERNAME), Optional.of(TestTurnServer.PASSWORD));
            for (var policy : List.of(HostCandidatePolicy.MDNS, HostCandidatePolicy.EXPOSE)) {
                var events = new CopyOnWriteArrayList<IceEvent>();
                try (var agent = loopbackBuilder().tcpCandidates(false).iceServers(List.of(turn)).hostCandidatePolicy(policy)
                        .mdnsFactory(IceTestPeers.memoryMdns(new MemoryMdnsLink(), "10.0.0.1"))
                        .eventListener(events::add).build()) {
                    agent.gather();
                    await(() -> agent.gatheringState() == IceGatheringState.COMPLETE, "gathering to end");
                    await(() -> gathered(events).stream().anyMatch(event -> event.candidate().type() == IceCandidateType.RELAY),
                            "the relayed candidate");
                    var relay = gathered(events).stream().filter(event -> event.candidate().type() == IceCandidateType.RELAY)
                            .findFirst().orElseThrow();
                    assertEquals(Optional.of(server.turnUri(TurnTransport.UDP)), relay.server());
                    assertEquals(Optional.of(IceProtocol.UDP), relay.candidate().relayProtocol());
                    var reflexive = gathered(events).stream()
                            .filter(event -> event.candidate().type() == IceCandidateType.SERVER_REFLEXIVE).findFirst();
                    reflexive.ifPresent(event -> assertEquals(Optional.of(server.stunUri()), event.server()));
                    var hidden = new InetSocketAddress(InetAddress.ofLiteral("0.0.0.0"), 0);
                    if (policy == HostCandidatePolicy.MDNS) {
                        assertEquals(Optional.of(hidden), relay.candidate().relatedAddress());
                        reflexive.ifPresent(event -> assertEquals(Optional.of(hidden), event.candidate().relatedAddress()));
                    } else {
                        assertFalse(relay.candidate().relatedAddress().orElseThrow().equals(hidden));
                    }
                    assertTrue(gathered(events).stream().filter(event -> event.candidate().type() == IceCandidateType.HOST)
                            .allMatch(event -> event.server().isEmpty()));
                }
            }
        }
    }

    @Test
    @DisplayName("gathers an active TCP server-reflexive candidate from a stuns: server")
    void secureStun() throws Exception {
        try (var server = TestTurnServer.start()) {
            var stack = NetworkStack.system(Thread.ofVirtual().name("stuns-", 0).factory(), TestCertificates.clientContext());
            var url = URI.create("stuns:localhost:" + server.tlsAddress().getPort());
            var events = new CopyOnWriteArrayList<IceEvent>();
            try (var agent = loopbackBuilder().networkStack(stack).iceServers(List.of(IceServer.of(url.toString())))
                    .eventListener(events::add).build()) {
                agent.gather();
                await(() -> agent.gatheringState() == IceGatheringState.COMPLETE, "gathering to end");
                var reflexive = gathered(events).stream()
                        .filter(event -> event.candidate().type() == IceCandidateType.SERVER_REFLEXIVE).findFirst()
                        .orElseThrow(() -> new AssertionError("no reflexive candidate in " + events));
                assertEquals(IceProtocol.TCP, reflexive.candidate().protocol());
                assertEquals(Optional.of(IceTcpType.ACTIVE), reflexive.candidate().tcpType());
                assertEquals(9, reflexive.candidate().port());
                assertEquals(Optional.of(url), reflexive.server());
                assertTrue(events.stream().noneMatch(IceEvent.CandidateError.class::isInstance), events.toString());
            }
        }
    }

    @Test
    @DisplayName("withholds host candidates and reports an error when the mDNS responder cannot open")
    void responderUnavailable() throws Exception {
        var events = new CopyOnWriteArrayList<IceEvent>();
        var failing = new IceAgent.MdnsFactory() {
            @Override
            public MdnsResponder openResponder() throws IOException {
                throw new IOException("port 5353 is taken");
            }

            @Override
            public MdnsResolver openResolver() throws IOException {
                throw new IOException("no resolver either");
            }
        };
        try (var agent = loopbackBuilder().tcpCandidates(false).hostCandidatePolicy(HostCandidatePolicy.MDNS)
                .mdnsFactory(failing).eventListener(events::add).build()) {
            agent.gather();
            await(() -> agent.gatheringState() == IceGatheringState.COMPLETE, "gathering to end");
            await(() -> events.stream().anyMatch(IceEvent.CandidateError.class::isInstance), "the candidate error");
            assertTrue(gathered(events).stream().noneMatch(event -> event.candidate().type() == IceCandidateType.HOST),
                    "a host candidate nobody can resolve was signalled: " + events);
            var error = events.stream().filter(IceEvent.CandidateError.class::isInstance)
                    .map(IceEvent.CandidateError.class::cast).findFirst().orElseThrow();
            assertEquals(IceAgent.MDNS_SERVER, error.server());
            assertTrue(error.localAddress().isPresent());
            assertEquals(IceEvent.CandidateError.UNREACHABLE, error.errorCode());
        }
    }

    @Test
    @DisplayName("delivers datagrams to the receiver set in the builder, before any setReceiver call")
    void builderReceiver() throws Exception {
        var inbox = new IceTestPeers.Inbox();
        try (var peers = new IceTestPeers(loopbackBuilder().role(IceRole.CONTROLLING).tcpCandidates(false),
                loopbackBuilder().role(IceRole.CONTROLLED).tcpCandidates(false).receiver(inbox),
                candidate -> true, candidate -> true)) {
            peers.gather();
            peers.awaitConnected(TIMEOUT);
            var payload = "first".getBytes(StandardCharsets.UTF_8);
            byte[] received = null;
            for (var attempt = 0; attempt < 20 && received == null; attempt++) {
                peers.first.send(ByteBuffer.wrap(payload));
                received = inbox.next(Duration.ofMillis(250));
            }
            assertArrayEquals(payload, received);
        }
    }

    @Test
    @DisplayName("validates the DSCP value of setTrafficClass")
    void trafficClass() {
        try (var agent = loopbackBuilder().build()) {
            assertThrows(IllegalArgumentException.class, () -> agent.setTrafficClass(64));
            assertThrows(IllegalArgumentException.class, () -> agent.setTrafficClass(-1));
            assertFalse(agent.setTrafficClass(46));
        }
    }

    @Test
    @DisplayName("returns false from awaitConnected on a timeout and throws only once failed or closed")
    void awaitConnectedSemantics() throws Exception {
        var agent = loopbackBuilder().tcpCandidates(false).build();
        assertFalse(agent.awaitConnected(Duration.ofMillis(50)));
        agent.close();
        assertThrows(IceException.class, () -> agent.awaitConnected(Duration.ofMillis(50)));
    }
}
