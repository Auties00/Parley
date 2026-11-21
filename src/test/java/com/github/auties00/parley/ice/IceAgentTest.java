package com.github.auties00.parley.ice;

import com.github.auties00.parley.stun.StunMessage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Drives the controlling [IceAgent] against an in-process `ice-lite` responder, which answers only checks that
/// carry the right credentials.
@DisplayName("IceAgent")
class IceAgentTest {
    private static final InetSocketAddress LOCAL = new InetSocketAddress("192.0.2.10", 50000);
    private static final InetSocketAddress LITE = new InetSocketAddress("198.51.100.7", 3480);
    private static final InetSocketAddress DEAD = new InetSocketAddress("198.51.100.8", 3480);

    @Test
    @DisplayName("nominates the candidate an ice-lite peer answers, with USE-CANDIDATE and valid integrity")
    void nominatesLitePeer() throws Exception {
        var local = IceCredentials.generate();
        var remote = IceCredentials.generate();
        var checks = new AtomicInteger();
        var agent = new IceAgent[1];
        agent[0] = new IceAgent(local, remote, true, (data, target) -> {
            if (!target.equals(LITE)) {
                return;
            }
            var request = StunMessage.decode(data, 0, data.length);
            assertEquals(StunMessage.BINDING_REQUEST, request.type());
            assertTrue(request.verifyIntegrity(remote.key()));
            assertTrue(request.has(StunMessage.USE_CANDIDATE));
            assertTrue(request.has(StunMessage.ICE_CONTROLLING));
            assertEquals(remote.ufrag() + ":" + local.ufrag(), request.stringAttribute(StunMessage.USERNAME).orElseThrow());
            checks.incrementAndGet();
            var response = StunMessage.response(StunMessage.BINDING_SUCCESS, request).addXorMappedAddress(LOCAL);
            var encoded = response.encode(remote.key(), true);
            Thread.ofVirtual().start(() -> agent[0].handle(StunMessage.decode(encoded, 0, encoded.length), LITE));
        });
        var selected = agent[0].nominate(List.of(DEAD, LITE), Duration.ofSeconds(5));
        assertEquals(LITE, selected);
        assertTrue(checks.get() >= 1);
        assertTrue(agent[0].lastConsentNanos() != 0);
    }

    @Test
    @DisplayName("ignores a response whose integrity does not verify and times out")
    void rejectsForgedResponse() {
        var local = IceCredentials.generate();
        var remote = IceCredentials.generate();
        var agent = new IceAgent[1];
        agent[0] = new IceAgent(local, remote, true, (data, target) -> {
            var request = StunMessage.decode(data, 0, data.length);
            var forged = StunMessage.response(StunMessage.BINDING_SUCCESS, request)
                    .encode("wrong-password".getBytes(StandardCharsets.UTF_8), true);
            agent[0].handle(StunMessage.decode(forged, 0, forged.length), target);
        });
        assertThrows(IceException.class, () -> agent[0].nominate(List.of(LITE), Duration.ofMillis(400)));
        assertTrue(agent[0].selected().isEmpty());
    }

    @Test
    @DisplayName("answers a peer's check with its mapped address under the local password")
    void answersChecks() {
        var local = IceCredentials.generate();
        var remote = IceCredentials.generate();
        var sent = new StunMessage[1];
        var agent = new IceAgent(local, remote, true, (data, target) -> sent[0] = StunMessage.decode(data, 0, data.length));
        var request = StunMessage.create(StunMessage.BINDING_REQUEST)
                .add(StunMessage.USERNAME, local.ufrag() + ":" + remote.ufrag())
                .encode(local.key(), true);
        assertTrue(agent.handle(StunMessage.decode(request, 0, request.length), LITE));
        assertEquals(StunMessage.BINDING_SUCCESS, sent[0].type());
        assertEquals(LITE, sent[0].xorMappedAddress().orElseThrow());

        var stranger = StunMessage.create(StunMessage.BINDING_REQUEST)
                .add(StunMessage.USERNAME, "someone:else")
                .encode(local.key(), true);
        assertFalse(agent.handle(StunMessage.decode(stranger, 0, stranger.length), LITE));
    }

    @Test
    @DisplayName("parses and formats a host candidate with extension attributes")
    void candidate() {
        var candidate = IceCandidate.parse("1775469887 1 udp 2122260223 203.0.113.35 3480 typ host generation 0 network-cost 50");
        assertEquals("203.0.113.35", candidate.host());
        assertEquals(3480, candidate.port());
        assertEquals("host", candidate.type());
        assertEquals("1775469887 1 udp 2122260223 203.0.113.35 3480 typ host", candidate.value());
    }
}
