package com.github.auties00.parley.mdns;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Regression tests for answers a resolver must not trust (unsolicited, off-link) and the bound of its cache, and for
/// resolution over the IPv6 group.
@DisplayName("mDNS hardening")
class MdnsHardeningTest {
    private static final ThreadFactory THREADS = Thread.ofVirtual().name("mdns-hardening-", 0).factory();

    /// Sends an unsolicited multicast answer for a name from a channel.
    private static void announce(MdnsChannel channel, String name, String address) throws Exception {
        var answer = new MdnsMessage(0, true, List.of(), List.of(
                MdnsMessage.Answer.address(name, InetAddress.ofLiteral(address), 120, true)));
        channel.send(answer.encode(), MdnsChannel.IPV4_GROUP);
    }

    @Test
    @DisplayName("ignores unsolicited answers for names nobody looks up, so they are never cached")
    void unsolicitedAnswers() throws Exception {
        var hub = new MemoryMdnsLink();
        try (var resolver = new MdnsResolver(hub.channel("10.0.0.3", 5353), THREADS)) {
            var attacker = hub.channel("10.0.0.66", 5353);
            for (var index = 0; index < 50; index++) {
                announce(attacker, UUID.randomUUID() + ".local", "10.6.6.6");
            }
            var deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (resolver.rejectedAnswers() < 50 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            assertEquals(50, resolver.rejectedAnswers());
            assertEquals(0, resolver.cachedNames());
        }
    }

    @Test
    @DisplayName("ignores answers from sources that are not on the local link")
    void offLinkAnswers() throws Exception {
        var hub = new MemoryMdnsLink();
        var name = UUID.randomUUID() + ".local";
        var channel = hub.channel("10.0.0.3", 50000);
        try (var resolver = new MdnsResolver(List.of(channel), THREADS, address -> !address.equals(InetAddress.ofLiteral("10.0.0.66")))) {
            var attacker = hub.channel("10.0.0.66", 5353);
            Thread.ofVirtual().start(() -> {
                try {
                    var buffer = ByteBuffer.allocate(MdnsMessage.MAX_LENGTH);
                    var source = attacker.receive(buffer);
                    var answer = new MdnsMessage(0, true, List.of(), List.of(
                            MdnsMessage.Answer.address(name, InetAddress.ofLiteral("10.6.6.6"), 120, true)));
                    attacker.send(answer.encode(), source);
                } catch (Exception exception) {
                    // The test ended.
                }
            });
            assertEquals(Optional.empty(), resolver.resolve(name, Duration.ofMillis(600)));
            assertTrue(resolver.rejectedAnswers() >= 1);
        }
    }

    @Test
    @DisplayName("caches at most 256 names, evicting the least recently used")
    void boundedCache() throws Exception {
        var hub = new MemoryMdnsLink();
        var responderChannel = hub.channel("10.0.0.2", 5353);
        try (var responder = new MdnsResponder(responderChannel, THREADS);
             var resolver = new MdnsResolver(hub.channel("10.0.0.3", 50000), THREADS)) {
            var names = new ArrayList<String>();
            for (var index = 0; index < MdnsResolver.CACHE_CAPACITY + 20; index++) {
                names.add(responder.register(InetAddress.ofLiteral("192.168." + (index / 250) + "." + (index % 250 + 1))));
            }
            for (var name : names) {
                assertTrue(resolver.resolve(name, Duration.ofSeconds(3)).isPresent(), name);
            }
            assertEquals(MdnsResolver.CACHE_CAPACITY, resolver.cachedNames());
        }
    }

    @Test
    @DisplayName("resolves a name over the IPv6 group when the responder answers there")
    void ipv6Group() throws Exception {
        var hub = new MemoryMdnsLink();
        try (var responder = new MdnsResponder(List.of(hub.channel("10.0.0.2", 5353),
                hub.channel("fe80::2", 5353, MdnsChannel.IPV6_GROUP)), THREADS);
             var resolver = new MdnsResolver(List.of(hub.channel("fe80::3", 50000, MdnsChannel.IPV6_GROUP)), THREADS,
                     InetAddress::isLinkLocalAddress)) {
            var address = InetAddress.ofLiteral("fd00::44");
            var name = responder.register(address);
            assertEquals(Optional.of(address), resolver.resolve(name, Duration.ofSeconds(3)));
        }
    }
}
