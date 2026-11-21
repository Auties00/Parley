package com.github.auties00.parley.ice;

import com.github.auties00.parley.net.NetworkInterfaceAddress;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the ICE value types: candidates (browser samples, round trips, fuzzing), parameters, servers, pair
/// priorities and the RFC 8421 host address order.
@DisplayName("ICE value types")
class IceCandidateTest {
    @ParameterizedTest
    @ValueSource(strings = {
            "candidate:1775469887 1 udp 2122260223 192.0.2.10 54400 typ host generation 0 ufrag EsAw network-id 1",
            "candidate:842163049 1 udp 1686052607 203.0.113.35 3480 typ srflx raddr 192.0.2.10 rport 54400 generation 0",
            "candidate:3 1 udp 41885439 198.51.100.4 50000 typ relay raddr 203.0.113.35 rport 3480",
            "candidate:2 1 tcp 1518280447 6b7e9d1c-6c5b-4a36-9a8c-2f2d1c1e3f40.local 9 typ host tcptype active",
            "a=candidate:4 1 TCP 1518214911 2001:db8::5 443 typ host tcptype passive",
            "1 1 UDP 2130706431 10.0.0.1 8998 typ host"})
    @DisplayName("parses browser candidates and writes them back")
    void browserSamples(String sample) {
        var candidate = IceCandidate.parse(sample);
        assertEquals(candidate, IceCandidate.parse(candidate.toSdp()));
        assertTrue(candidate.toSdp().startsWith("candidate:"));
    }

    @Test
    @DisplayName("reads every field of a server-reflexive candidate")
    void fields() {
        var candidate = IceCandidate.parse("candidate:842163049 1 udp 1686052607 203.0.113.35 3480 typ srflx raddr 0.0.0.0 rport 9 ufrag abcd");
        assertEquals("842163049", candidate.foundation());
        assertEquals(IceProtocol.UDP, candidate.protocol());
        assertEquals(IceCandidateType.SERVER_REFLEXIVE, candidate.type());
        assertEquals(Optional.of(new InetSocketAddress(InetAddress.ofLiteral("0.0.0.0"), 9)), candidate.relatedAddress());
        assertEquals(Optional.of("abcd"), candidate.usernameFragment());
        assertEquals(Optional.of(new InetSocketAddress(InetAddress.ofLiteral("203.0.113.35"), 3480)), candidate.socketAddress());
        assertFalse(candidate.isMdns());
    }

    @Test
    @DisplayName("keeps .local addresses unresolved")
    void mdnsCandidate() {
        var candidate = IceCandidate.parse("candidate:2 1 udp 2122260223 6B7E9D1C-6C5B-4A36-9A8C-2F2D1C1E3F40.local 9000 typ host");
        assertTrue(candidate.isMdns());
        assertEquals(Optional.empty(), candidate.socketAddress());
        var ipv6 = IceCandidate.parse("candidate:4 1 udp 1 2001:db8::5 443 typ host");
        assertTrue(ipv6.socketAddress().orElseThrow().getAddress() instanceof Inet6Address);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "candidate:1 1 udp", "candidate:1 1 udp 1 1.2.3.4 5 nottyp host",
            "candidate:1 x udp 1 1.2.3.4 5 typ host", "candidate:1 1 sctp 1 1.2.3.4 5 typ host",
            "candidate:1 1 udp 1 1.2.3.4 70000 typ host", "candidate:1 1 udp 1 1.2.3.4 5 typ bogus",
            "candidate:1 0 udp 1 1.2.3.4 5 typ host", "candidate:1 1 udp 99999999999 1.2.3.4 5 typ host",
            "candidate:1 1 tcp 1 1.2.3.4 5 typ host tcptype sideways"})
    @DisplayName("refuses malformed candidates with IllegalArgumentException")
    void malformed(String value) {
        assertThrows(IllegalArgumentException.class, () -> IceCandidate.parse(value));
    }

    @Test
    @DisplayName("throws only IllegalArgumentException for random token soup")
    void fuzz() {
        var random = new Random(5);
        var tokens = List.of("candidate:1", "1", "udp", "tcp", "2122260223", "10.0.0.1", "::1", "x.local", "9", "typ", "host",
                "srflx", "relay", "prflx", "raddr", "rport", "tcptype", "active", "passive", "so", "ufrag", "-1", "65536", "");
        for (var i = 0; i < 20_000; i++) {
            var builder = new StringBuilder();
            var count = random.nextInt(14);
            for (var j = 0; j < count; j++) {
                builder.append(tokens.get(random.nextInt(tokens.size()))).append(' ');
            }
            try {
                var candidate = IceCandidate.parse(builder.toString());
                assertEquals(candidate, IceCandidate.parse(candidate.toSdp()));
            } catch (IllegalArgumentException expected) {
                // Malformed input fails this way only.
            }
        }
    }

    @Test
    @DisplayName("computes RFC 8445 candidate and pair priorities")
    void priorities() {
        assertEquals(2130706431L, IceCandidate.priority(126, 65535, 1));
        var host = IceCandidate.parse("candidate:1 1 udp 2130706431 10.0.0.1 1 typ host");
        var relay = IceCandidate.parse("candidate:2 1 udp 16777215 10.0.0.2 2 typ relay");
        var pair = new IceCandidatePair(host, relay);
        var g = 2130706431L;
        var d = 16777215L;
        assertEquals((d << 32) + 2 * g + 1, pair.priority(IceRole.CONTROLLING));
        assertEquals((d << 32) + 2 * g, pair.priority(IceRole.CONTROLLED));
        assertThrows(IllegalArgumentException.class, () -> IceCandidate.priority(127, 0, 1));
    }

    @Test
    @DisplayName("generates parameters from the ice-char alphabet and hides the password")
    void parameters() {
        var parameters = IceParameters.generate();
        assertEquals(4, parameters.usernameFragment().length());
        assertEquals(24, parameters.password().length());
        assertFalse(parameters.toString().contains(parameters.password()));
        assertTrue(IceParameters.generate(true).lite());
        assertThrows(IllegalArgumentException.class, () -> new IceParameters("bad frag", "password", false));
        assertTrue(parameters.sameCredentials(new IceParameters(parameters.usernameFragment(), parameters.password(), true)));
    }

    @Test
    @DisplayName("validates ICE server URLs and splits them into STUN and TURN servers")
    void servers() {
        var stun = IceServer.of("stun:stun.example.org:19302");
        assertEquals(1, stun.stunServers().size());
        var turn = new IceServer(List.of(URI.create("turn:turn.example.org"), URI.create("turns:turn.example.org:443?transport=tcp"),
                URI.create("stuns:turn.example.org")), Optional.of("user"), Optional.of("secret"));
        assertEquals(2, turn.turnServers().size());
        assertEquals(1, turn.stunServers().size());
        assertTrue(turn.stunServers().getFirst().secure());
        assertFalse(turn.toString().contains("secret"));
        assertThrows(IllegalArgumentException.class, () -> IceServer.of("turn:turn.example.org"));
        assertThrows(IllegalArgumentException.class, () -> IceServer.of("http://example.org"));
    }

    @Test
    @DisplayName("interleaves IPv6 and IPv4 host addresses and ranks virtual and loopback ones last (RFC 8421)")
    void hostAddressOrder() {
        var addresses = List.of(
                new NetworkInterfaceAddress("eth0", InetAddress.ofLiteral("192.168.1.2"), 24, false, false, false),
                new NetworkInterfaceAddress("eth0", InetAddress.ofLiteral("2001:db8::2"), 64, false, false, false),
                new NetworkInterfaceAddress("eth0", InetAddress.ofLiteral("fe80::2"), 64, false, true, false),
                new NetworkInterfaceAddress("tun0", InetAddress.ofLiteral("10.8.0.2"), 24, false, false, true),
                new NetworkInterfaceAddress("wlan0", InetAddress.ofLiteral("2001:db8::3"), 64, false, false, false),
                new NetworkInterfaceAddress("lo", InetAddress.ofLiteral("127.0.0.1"), 8, true, false, false));
        var chosen = HostAddresses.choose(addresses, false, false, true, _ -> true).stream()
                .map(ranked -> ranked.address().address().getHostAddress())
                .toList();
        assertEquals(List.of("2001:db8:0:0:0:0:0:2", "192.168.1.2", "2001:db8:0:0:0:0:0:3", "10.8.0.2"), chosen);
        var ranked = HostAddresses.choose(addresses, false, false, true, _ -> true);
        assertTrue(ranked.get(0).localPreference() > ranked.get(1).localPreference());
        var onlyLoopback = HostAddresses.choose(addresses, false, false, false, address -> address.loopback());
        assertEquals(1, onlyLoopback.size());
        assertEquals(5, HostAddresses.choose(addresses, true, true, false, _ -> true).size());
    }
}
