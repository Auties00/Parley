package com.github.auties00.parley.ice;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/// One ICE candidate, as an `a=candidate` attribute or a trickled W3C `RTCIceCandidate` carries it.
///
/// ```text
/// candidate:1775469887 1 udp 2122260223 192.0.2.10 54400 typ host ufrag EsAw
/// candidate:842163049 1 udp 1686052607 203.0.113.35 3480 typ srflx raddr 192.0.2.10 rport 54400
/// candidate:2 1 tcp 1518280447 6b7e9d1c-6c5b-4a36-9a8c-2f2d1c1e3f40.local 9 typ host tcptype active
/// ```
///
/// [#parse(String)] reads the base fields and the `raddr`, `rport`, `tcptype` and `ufrag` extensions and skips
/// every other extension (`generation`, `network-id`, `network-cost`); [#toSdp()] writes the same fields back. The
/// address may be an IP literal or, for a candidate hidden by multicast DNS, a `<uuid>.local` name; it is never
/// resolved by this record.
///
/// @param foundation       the foundation, 1 to 32 `ice-char` characters; candidates with the same foundation share
///                         type, base and server
/// @param component        the component id, `1` for RTP (and RTCP, which WebRTC multiplexes)
/// @param protocol         the transport protocol
/// @param priority         the priority, an unsigned 32-bit value
/// @param address          the address, an IP literal or a `.local` name
/// @param port             the port, `0..65535`; `9` for an active TCP candidate
/// @param type             the candidate type
/// @param tcpType          the connection direction of a TCP candidate, absent for UDP
/// @param relatedAddress   the related address and port (`raddr` and `rport`): the base of a reflexive candidate,
///                         the mapped address of a relayed one
/// @param usernameFragment the ICE username fragment the candidate belongs to (`ufrag`), which tells candidates of an
///                         ICE restart apart from older ones
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
/// @spec https://www.rfc-editor.org/rfc/rfc6544.html RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8840.html RFC 8840: A Session Initiation Protocol (SIP) Usage for Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (Trickle ICE)
public record IceCandidate(String foundation, int component, IceProtocol protocol, long priority, String address,
                           int port, IceCandidateType type, Optional<IceTcpType> tcpType,
                           Optional<InetSocketAddress> relatedAddress, Optional<String> usernameFragment) {
    /// Creates a candidate.
    ///
    /// @param foundation       the foundation
    /// @param component        the component id
    /// @param protocol         the transport protocol
    /// @param priority         the priority
    /// @param address          the address
    /// @param port             the port
    /// @param type             the candidate type
    /// @param tcpType          the TCP direction
    /// @param relatedAddress   the related address
    /// @param usernameFragment the username fragment
    /// @throws IllegalArgumentException if the foundation is empty or longer than 32 characters, the component is
    ///                                  outside `1..256`, the priority is not an unsigned 32-bit value, the port is
    ///                                  outside `0..65535`, the address is empty or contains a space, or a TCP
    ///                                  candidate has no TCP type
    public IceCandidate {
        Objects.requireNonNull(foundation, "foundation cannot be null");
        Objects.requireNonNull(protocol, "protocol cannot be null");
        Objects.requireNonNull(address, "address cannot be null");
        Objects.requireNonNull(type, "type cannot be null");
        Objects.requireNonNull(tcpType, "tcpType cannot be null");
        Objects.requireNonNull(relatedAddress, "relatedAddress cannot be null");
        Objects.requireNonNull(usernameFragment, "usernameFragment cannot be null");
        if (foundation.isEmpty() || foundation.length() > 32 || foundation.indexOf(' ') >= 0) {
            throw new IllegalArgumentException("invalid foundation: " + foundation);
        }
        if (component < 1 || component > 256) {
            throw new IllegalArgumentException("component out of range: " + component);
        }
        if (priority < 0 || priority > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("priority out of range: " + priority);
        }
        if (port < 0 || port > 0xFFFF) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
        if (address.isEmpty() || address.indexOf(' ') >= 0) {
            throw new IllegalArgumentException("invalid address: " + address);
        }
        if (protocol == IceProtocol.TCP && tcpType.isEmpty()) {
            throw new IllegalArgumentException("a TCP candidate needs a tcptype");
        }
        if (protocol == IceProtocol.UDP && tcpType.isPresent()) {
            throw new IllegalArgumentException("a UDP candidate has no tcptype");
        }
    }

    /// Parses a candidate.
    ///
    /// @param value the candidate as the `a=candidate` attribute value (`<foundation> <component> ...`), with or
    ///              without the `candidate:` prefix a trickled candidate carries, and with or without `a=`
    /// @return the candidate
    /// @throws IllegalArgumentException if the value has fewer than eight tokens, its seventh token is not `typ`, a
    ///                                  number, the transport, the type or an extension value is malformed
    public static IceCandidate parse(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        var text = value.strip();
        if (text.startsWith("a=")) {
            text = text.substring(2);
        }
        if (text.startsWith("candidate:")) {
            text = text.substring("candidate:".length());
        }
        var tokens = text.split("[ \t]+");
        if (tokens.length < 8 || !tokens[6].equals("typ")) {
            throw new IllegalArgumentException("malformed candidate: " + value);
        }
        try {
            var protocol = IceProtocol.ofToken(tokens[2]);
            var type = IceCandidateType.ofToken(tokens[7].toLowerCase(Locale.ROOT));
            String relatedHost = null;
            var relatedPort = -1;
            IceTcpType tcpType = null;
            String ufrag = null;
            for (var i = 8; i + 1 < tokens.length; i += 2) {
                var name = tokens[i];
                var extension = tokens[i + 1];
                switch (name) {
                    case "raddr" -> relatedHost = extension;
                    case "rport" -> relatedPort = Integer.parseInt(extension);
                    case "tcptype" -> tcpType = IceTcpType.ofToken(extension);
                    case "ufrag" -> ufrag = extension;
                    default -> {
                    }
                }
            }
            if (protocol == IceProtocol.TCP && tcpType == null) {
                tcpType = IceTcpType.PASSIVE;
            }
            if (protocol == IceProtocol.UDP) {
                tcpType = null;
            }
            Optional<InetSocketAddress> related = Optional.empty();
            if (relatedHost != null && relatedPort >= 0 && relatedPort <= 0xFFFF) {
                related = Optional.of(socketAddress(relatedHost, relatedPort));
            }
            return new IceCandidate(tokens[0], Integer.parseInt(tokens[1]), protocol, Long.parseLong(tokens[3]),
                    tokens[4], Integer.parseInt(tokens[5]), type, Optional.ofNullable(tcpType), related,
                    Optional.ofNullable(ufrag));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("malformed candidate: " + value, exception);
        }
    }

    /// {@return the priority of a candidate, `2^24 * typePreference + 2^8 * localPreference + (256 - component)`}
    ///
    /// @param typePreference  the type preference, `0..126`
    /// @param localPreference the local preference, `0..65535`
    /// @param component       the component id, `1..256`
    /// @throws IllegalArgumentException if a value is out of range
    /// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
    public static long priority(int typePreference, int localPreference, int component) {
        if (typePreference < 0 || typePreference > 126 || localPreference < 0 || localPreference > 0xFFFF
                || component < 1 || component > 256) {
            throw new IllegalArgumentException("priority input out of range");
        }
        return ((long) typePreference << 24) + ((long) localPreference << 8) + (256 - component);
    }

    /// {@return whether the address is an mDNS name, ending in `.local`}
    public boolean isMdns() {
        return address.toLowerCase(Locale.ROOT).endsWith(".local");
    }

    /// {@return the transport address of the candidate when its address is an IP literal, or an empty optional for a
    /// name; never performs a lookup}
    public Optional<InetSocketAddress> socketAddress() {
        try {
            return Optional.of(new InetSocketAddress(InetAddress.ofLiteral(stripBrackets(address)), port));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    /// {@return a copy of this candidate with another username fragment}
    ///
    /// @param usernameFragment the username fragment
    public IceCandidate withUsernameFragment(String usernameFragment) {
        return new IceCandidate(foundation, component, protocol, priority, address, port, type, tcpType,
                relatedAddress, Optional.of(usernameFragment));
    }

    /// {@return the candidate as a W3C candidate string, `candidate:<foundation> <component> <transport> <priority>
    /// <address> <port> typ <type>` followed by `raddr`, `rport`, `tcptype` and `ufrag` when present}
    ///
    /// Prefixed with `a=`, the string is the session description attribute.
    public String toSdp() {
        var builder = new StringBuilder("candidate:")
                .append(foundation).append(' ')
                .append(component).append(' ')
                .append(protocol.token()).append(' ')
                .append(priority).append(' ')
                .append(address).append(' ')
                .append(port).append(" typ ")
                .append(type.token());
        relatedAddress.ifPresent(related -> builder.append(" raddr ").append(hostString(related))
                .append(" rport ").append(related.getPort()));
        tcpType.ifPresent(direction -> builder.append(" tcptype ").append(direction.token()));
        usernameFragment.ifPresent(ufrag -> builder.append(" ufrag ").append(ufrag));
        return builder.toString();
    }

    /// {@return the candidate as [#toSdp()] writes it}
    @Override
    public String toString() {
        return toSdp();
    }

    /// {@return a socket address for a literal, resolved, or for a name, unresolved}
    private static InetSocketAddress socketAddress(String host, int port) {
        try {
            return new InetSocketAddress(InetAddress.ofLiteral(stripBrackets(host)), port);
        } catch (IllegalArgumentException exception) {
            return InetSocketAddress.createUnresolved(host, port);
        }
    }

    /// {@return the host of a socket address as an IP literal without a scope, or its name when unresolved}
    static String hostString(InetSocketAddress address) {
        if (address.isUnresolved()) {
            return address.getHostString();
        }
        var text = address.getAddress().getHostAddress();
        var scope = text.indexOf('%');
        return scope < 0 ? text : text.substring(0, scope);
    }

    /// {@return `host` without the brackets of an IPv6 literal}
    private static String stripBrackets(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }
}
