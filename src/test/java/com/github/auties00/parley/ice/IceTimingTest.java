package com.github.auties00.parley.ice;

import com.github.auties00.parley.net.MemoryNetworkStack;
import com.github.auties00.parley.net.NetworkInterfaceAddress;
import com.github.auties00.parley.stun.StunAttribute;
import com.github.auties00.parley.stun.StunClass;
import com.github.auties00.parley.stun.StunFormatException;
import com.github.auties00.parley.stun.StunMessage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Checks the timers of the ICE agent in simulated time over an in-memory network: `Ta` pacing and check
/// retransmission (RFC 8445 sections 6.1.4 and 14), and consent freshness (RFC 7675).
@DisplayName("IceAgent timers")
@Timeout(60)
class IceTimingTest {
    private static NetworkInterfaceAddress address(String ip) {
        return new NetworkInterfaceAddress("eth0", InetAddress.ofLiteral(ip), 24, false, false, false);
    }

    private static List<StunMessage> bindingRequestsTo(MemoryNetworkStack.Network network, String ip) {
        return network.sent().stream()
                .filter(sent -> sent.to().getAddress().getHostAddress().equals(ip))
                .map(sent -> {
                    try {
                        return StunMessage.decode(sent.buffer());
                    } catch (StunFormatException exception) {
                        throw new AssertionError(exception);
                    }
                })
                .filter(message -> message.messageClass() == StunClass.REQUEST)
                .toList();
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        var deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out");
            }
            Thread.sleep(5);
        }
    }

    @Test
    @DisplayName("paces checks Ta = 50 ms apart and retransmits after RTO = 500 ms")
    void pacing() throws Exception {
        var time = new ManualTime();
        var network = new MemoryNetworkStack.Network();
        var events = new CopyOnWriteArrayList<IceEvent>();
        try (var agent = IceAgent.builder()
                .networkStack(new MemoryNetworkStack(network, List.of(address("10.0.0.1"))))
                .clock(time).scheduler(time.scheduler()).tcpCandidates(false).eventListener(events::add)
                .build()) {
            agent.gather();
            await(() -> events.contains(new IceEvent.GatheringStateChanged(IceGatheringState.COMPLETE)));
            agent.setRemoteParameters(IceParameters.generate());
            agent.addRemoteCandidate(IceCandidate.parse("candidate:1 1 udp 2130706431 10.0.0.2 9000 typ host"));
            agent.addRemoteCandidate(IceCandidate.parse("candidate:2 1 udp 2130706175 10.0.0.3 9000 typ host"));
            agent.addRemoteCandidate(IceCandidate.parse("candidate:3 1 udp 1694498815 10.0.0.4 9000 typ srflx raddr 10.0.0.9 rport 1"));
            time.advance(Duration.ZERO);
            assertEquals(1, network.sent().size());
            assertEquals(1, bindingRequestsTo(network, "10.0.0.2").size());
            time.advance(Duration.ofMillis(50));
            assertEquals(2, network.sent().size());
            assertEquals(1, bindingRequestsTo(network, "10.0.0.3").size());
            time.advance(Duration.ofMillis(50));
            assertEquals(3, network.sent().size());
            time.advance(Duration.ofMillis(399));
            assertEquals(3, network.sent().size());
            time.advance(Duration.ofMillis(1));
            assertEquals(4, network.sent().size());
            assertEquals(2, bindingRequestsTo(network, "10.0.0.2").size());
            var first = bindingRequestsTo(network, "10.0.0.2");
            assertEquals(first.get(0).transactionId(), first.get(1).transactionId());
            assertTrue(first.getFirst().has(StunAttribute.IceControlling.class));
            assertTrue(first.getFirst().has(StunAttribute.Priority.class));
            assertEquals(IceTransportState.CHECKING, agent.state());
        }
    }

    @Test
    @DisplayName("turns DISCONNECTED after 10 s and FAILED after 30 s without consent responses")
    void consent() throws Exception {
        var time = new ManualTime();
        var network = new MemoryNetworkStack.Network();
        var first = IceAgent.builder().networkStack(new MemoryNetworkStack(network, List.of(address("10.0.0.1"))))
                .clock(time).scheduler(time.scheduler()).tcpCandidates(false).role(IceRole.CONTROLLING);
        var second = IceAgent.builder().networkStack(new MemoryNetworkStack(network, List.of(address("10.0.0.2"))))
                .clock(time).scheduler(time.scheduler()).tcpCandidates(false).role(IceRole.CONTROLLED);
        try (var peers = new IceTestPeers(first, second, candidate -> true, candidate -> true)) {
            peers.gather();
            await(() -> peers.first.localCandidates().size() == 1 && peers.second.localCandidates().size() == 1
                    && !peers.first.remoteCandidates().isEmpty() && !peers.second.remoteCandidates().isEmpty());
            for (var step = 0; step < 400 && peers.first.state() != IceTransportState.COMPLETED; step++) {
                time.advanceSlowly(Duration.ofMillis(10), Duration.ofMillis(10));
            }
            assertEquals(IceTransportState.COMPLETED, peers.first.state(), () -> peers.first.statistics() + " / " + peers.second.statistics());
            var consentBefore = consentChecks(peers.first);
            time.advanceSlowly(Duration.ofSeconds(7), Duration.ofMillis(100));
            assertTrue(consentChecks(peers.first) > consentBefore, "consent checks are sent every 4 to 6 seconds");
            assertEquals(IceTransportState.COMPLETED, peers.first.state());
            network.drop(sent -> sent.from().getAddress().getHostAddress().equals("10.0.0.2"));
            time.advanceSlowly(Duration.ofSeconds(14), Duration.ofMillis(100));
            assertEquals(IceTransportState.DISCONNECTED, peers.first.state());
            time.advanceSlowly(Duration.ofSeconds(25), Duration.ofMillis(100));
            assertEquals(IceTransportState.FAILED, peers.first.state());
            assertTrue(peers.first.selectedPair().isEmpty());
            assertTrue(peers.firstEvents.contains(new IceEvent.StateChanged(IceTransportState.DISCONNECTED)));
        }
    }

    private static long consentChecks(IceAgent agent) {
        return agent.statistics().pairs().stream().mapToLong(IceCandidatePairStatistics::consentRequestsSent).sum();
    }

    @Test
    @DisplayName("answers a check with XOR-MAPPED-ADDRESS signed by the local password, and 401 to a forged one")
    void answersChecks() throws Exception {
        var time = new ManualTime();
        var network = new MemoryNetworkStack.Network();
        var events = new CopyOnWriteArrayList<IceEvent>();
        var local = IceParameters.generate();
        var remote = IceParameters.generate();
        try (var agent = IceAgent.builder().networkStack(new MemoryNetworkStack(network, List.of(address("10.0.0.1"))))
                .clock(time).scheduler(time.scheduler()).tcpCandidates(false).localParameters(local).role(IceRole.CONTROLLED)
                .eventListener(events::add).build()) {
            agent.gather();
            await(() -> events.contains(new IceEvent.GatheringStateChanged(IceGatheringState.COMPLETE)));
            agent.setRemoteParameters(remote);
            var host = agent.localCandidates().getFirst().socketAddress().orElseThrow();
            var peerStack = new MemoryNetworkStack(network, List.of(address("10.0.0.5")));
            try (var peer = peerStack.bindUdp(new InetSocketAddress(InetAddress.ofLiteral("10.0.0.5"), 7000))) {
                var check = StunMessage.request(com.github.auties00.parley.stun.StunMethod.BINDING, List.of(
                        new StunAttribute.Username(local.usernameFragment() + ":" + remote.usernameFragment()),
                        new StunAttribute.Priority(1845501695L), new StunAttribute.IceControlling(1L)));
                peer.send(check.encode(local.key(), com.github.auties00.parley.stun.StunIntegrity.HMAC_SHA1, true), host);
                var buffer = java.nio.ByteBuffer.allocate(1500);
                peer.receive(buffer);
                var response = StunMessage.decode(buffer.flip());
                assertEquals(StunClass.SUCCESS_RESPONSE, response.messageClass());
                assertEquals(check.transactionId(), response.transactionId());
                assertEquals(new InetSocketAddress(InetAddress.ofLiteral("10.0.0.5"), 7000),
                        response.attribute(StunAttribute.XorMappedAddress.class).orElseThrow().address());
                assertTrue(response.verifyIntegrity(local.key()));
                assertTrue(agent.remoteCandidates().stream().anyMatch(candidate -> candidate.type() == IceCandidateType.PEER_REFLEXIVE
                        && candidate.priority() == 1845501695L));

                var forged = StunMessage.request(com.github.auties00.parley.stun.StunMethod.BINDING, List.of(
                        new StunAttribute.Username(local.usernameFragment() + ":" + remote.usernameFragment())));
                peer.send(forged.encode(remote.key(), com.github.auties00.parley.stun.StunIntegrity.HMAC_SHA1, true), host);
                buffer.clear();
                peer.receive(buffer);
                var rejection = StunMessage.decode(buffer.flip());
                assertEquals(401, rejection.errorCode().orElseThrow().code());

                var conflicting = StunMessage.request(com.github.auties00.parley.stun.StunMethod.BINDING, List.of(
                        new StunAttribute.Username(local.usernameFragment() + ":" + remote.usernameFragment()),
                        new StunAttribute.Priority(1L), new StunAttribute.IceControlled(0L)));
                peer.send(conflicting.encode(local.key(), com.github.auties00.parley.stun.StunIntegrity.HMAC_SHA1, true), host);
                buffer.clear();
                peer.receive(buffer);
                var conflictAnswer = StunMessage.decode(buffer.flip());
                assertTrue(conflictAnswer.messageClass() == StunClass.SUCCESS_RESPONSE
                        ? agent.role() == IceRole.CONTROLLING
                        : conflictAnswer.errorCode().orElseThrow().code() == 487);
            }
        }
    }
}
