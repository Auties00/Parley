package com.github.auties00.parley.stun;

import com.github.auties00.parley.net.MonotonicClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers client transactions (retransmission over UDP, a single send over a reliable transport, authentication of
/// responses), the RFC 8489 schedule arithmetic, and `stun:` URIs.
@DisplayName("STUN client transactions")
class StunClientTransactionsTest {
    private static final StunRetransmission FAST = new StunRetransmission(Duration.ofMillis(10), 4, 2, false);

    @Test
    @DisplayName("retransmits an unanswered request Rc times and then times out")
    void retransmitsAndTimesOut() {
        var transactions = new StunClientTransactions(MonotonicClock.system());
        var sends = new AtomicInteger();
        var request = StunMessage.request(StunMethod.BINDING, List.of());
        assertThrows(StunTimeoutException.class, () -> transactions.execute(request, sends::incrementAndGet, FAST, _ -> true));
        assertEquals(4, sends.get());
        assertFalse(transactions.isPending(request.transactionId()));
    }

    @Test
    @DisplayName("returns the response that answers a transmission")
    void answers() throws Exception {
        var transactions = new StunClientTransactions(MonotonicClock.system());
        var request = StunMessage.request(StunMethod.BINDING, List.of());
        var sends = new AtomicInteger();
        var response = transactions.execute(request, () -> {
            if (sends.incrementAndGet() == 2) {
                var reply = request.successResponse(List.of(new StunAttribute.Software("server")));
                Thread.ofVirtual().start(() -> {
                    try {
                        transactions.complete(StunMessage.decode(reply.encode(true)));
                    } catch (StunFormatException exception) {
                        throw new AssertionError(exception);
                    }
                });
            }
        }, FAST, _ -> true);
        assertTrue(response.isSuccess());
        assertEquals("server", response.message().attribute(StunAttribute.Software.class).orElseThrow().value());
        assertTrue(response.transmissions() >= 2);
    }

    @Test
    @DisplayName("keeps retransmitting past an unauthentic response over UDP and reports the integrity failure")
    void unauthenticUdp() {
        var transactions = new StunClientTransactions(MonotonicClock.system());
        var request = StunMessage.request(StunMethod.BINDING, List.of());
        var sends = new AtomicInteger();
        var key = StunKey.shortTerm("right");
        assertThrows(StunIntegrityException.class, () -> transactions.execute(request, () -> {
            sends.incrementAndGet();
            var forged = request.successResponse(List.of()).encode(StunKey.shortTerm("wrong"), StunIntegrity.HMAC_SHA1, true);
            try {
                transactions.complete(StunMessage.decode(forged));
            } catch (StunFormatException exception) {
                throw new AssertionError(exception);
            }
        }, FAST, message -> message.verifyIntegrity(key)));
        assertEquals(4, sends.get());
    }

    @Test
    @DisplayName("sends once over a reliable transport and fails at the first unauthentic response")
    void reliable() {
        var transactions = new StunClientTransactions(MonotonicClock.system());
        var request = StunMessage.request(StunMethod.BINDING, List.of());
        var sends = new AtomicInteger();
        assertThrows(StunIntegrityException.class, () -> transactions.execute(request, () -> {
            sends.incrementAndGet();
            Thread.ofVirtual().start(() -> {
                try {
                    transactions.complete(StunMessage.decode(request.successResponse(List.of()).encode(true)));
                } catch (StunFormatException exception) {
                    throw new AssertionError(exception);
                }
            });
        }, StunRetransmission.reliable(Duration.ofSeconds(5)), _ -> false));
        assertEquals(1, sends.get());
    }

    @Test
    @DisplayName("discards a response with an unknown comprehension-required attribute")
    void unknownAttributeResponse() {
        var transactions = new StunClientTransactions(MonotonicClock.system());
        var request = StunMessage.request(StunMethod.BINDING, List.of());
        assertThrows(StunIntegrityException.class, () -> transactions.execute(request, () -> {
            var reply = request.successResponse(List.of(new StunAttribute.Unknown(0x0777, java.nio.ByteBuffer.allocate(4))));
            try {
                transactions.complete(StunMessage.decode(reply.encode(true)));
            } catch (StunFormatException exception) {
                throw new AssertionError(exception);
            }
        }, FAST, _ -> true));
    }

    @Test
    @DisplayName("fails waiting transactions when closed")
    void close() throws Exception {
        var transactions = new StunClientTransactions(MonotonicClock.system());
        var request = StunMessage.request(StunMethod.BINDING, List.of());
        var failure = new IOException[1];
        var waiter = Thread.ofVirtual().start(() -> {
            try {
                transactions.execute(request, () -> {
                }, StunRetransmission.reliable(Duration.ofSeconds(30)), _ -> true);
            } catch (IOException exception) {
                failure[0] = exception;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        });
        while (!transactions.isPending(request.transactionId())) {
            Thread.onSpinWait();
        }
        transactions.close();
        waiter.join(Duration.ofSeconds(5));
        assertTrue(failure[0] != null);
        assertThrows(IOException.class, () -> transactions.execute(StunMessage.request(StunMethod.BINDING, List.of()), () -> {
        }, FAST, _ -> true));
    }

    @Test
    @DisplayName("follows the RFC 8489 section 6.2.1 schedule: sends at 0, 500, 1500 ... 31500 ms, fails at 39500 ms")
    void rfcSchedule() {
        var schedule = StunRetransmission.UDP;
        var sendTimes = new long[schedule.maxTransmissions()];
        var elapsed = 0L;
        for (var i = 0; i < schedule.maxTransmissions(); i++) {
            sendTimes[i] = elapsed;
            elapsed += schedule.waitAfter(i).toMillis();
        }
        assertEquals(List.of(0L, 500L, 1500L, 3500L, 7500L, 15500L, 31500L), java.util.Arrays.stream(sendTimes).boxed().toList());
        assertEquals(39_500, schedule.totalTimeout().toMillis());
        assertEquals(39_500, StunRetransmission.RELIABLE.totalTimeout().toMillis());
    }

    @Test
    @DisplayName("truncates a schedule to a total time")
    void truncation() {
        var truncated = StunRetransmission.UDP.truncatedTo(Duration.ofSeconds(5));
        assertTrue(truncated.totalTimeout().compareTo(Duration.ofSeconds(5)) <= 0);
        assertEquals(3, truncated.maxTransmissions());
        assertEquals(StunRetransmission.UDP, StunRetransmission.UDP.truncatedTo(Duration.ofMinutes(1)));
        assertEquals(1, StunRetransmission.UDP.truncatedTo(Duration.ofMillis(100)).maxTransmissions());
        assertEquals(Duration.ofSeconds(2), StunRetransmission.RELIABLE.truncatedTo(Duration.ofSeconds(2)).totalTimeout());
    }

    @Test
    @DisplayName("parses stun: and stuns: URIs per RFC 7064")
    void stunUris() {
        assertEquals(new StunServer("stun.example.org", 3478, false), StunServer.parse(URI.create("stun:stun.example.org")));
        assertEquals(new StunServer("192.0.2.1", 19302, false), StunServer.parse(URI.create("stun:192.0.2.1:19302")));
        assertEquals(new StunServer("2001:db8::1", 3478, false), StunServer.parse(URI.create("stun:[2001:db8::1]:3478")));
        assertEquals(new StunServer("stun.example.org", 5349, true), StunServer.parse(URI.create("stuns:stun.example.org")));
        assertEquals(URI.create("stun:[2001:db8::1]:3478"), new StunServer("2001:db8::1", 3478, false).toUri());
        assertThrows(IllegalArgumentException.class, () -> StunServer.parse(URI.create("turn:example.org")));
        assertThrows(IllegalArgumentException.class, () -> StunServer.parse(URI.create("stun:example.org:99999")));
        assertThrows(IllegalArgumentException.class, () -> StunServer.parse(URI.create("stun:example.org?transport=udp")));
    }
}
