package com.github.auties00.parley.ice;

import java.net.InetSocketAddress;
import java.util.Locale;
import java.util.Objects;

/// One ICE candidate, as an `a=candidate` attribute carries it.
///
/// ```text
/// a=candidate:1775469887 1 udp 2122260223 203.0.113.35 3480 typ host generation 0 network-cost 50
/// ```
///
/// Extension attributes after the type (`generation`, `network-cost`, the related address of a reflexive candidate)
/// are ignored on parse and not written by [#value()].
///
/// @param foundation the foundation
/// @param component  the component id, `1` for RTP (and RTCP when multiplexed)
/// @param transport  the transport, such as `udp` or `tcp`, lower-cased by the constructor
/// @param priority   the candidate priority, an unsigned 32-bit value
/// @param host       the address as written, an IP literal or a hostname such as an mDNS `.local` name
/// @param port       the port, `0..65535`
/// @param type       the candidate type, such as `host`, `srflx`, `prflx` or `relay`
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
public record IceCandidate(String foundation, int component, String transport, long priority,
                           String host, int port, String type) {
    /// The type preference RFC 8445 section 5.1.2.2 recommends for host candidates.
    private static final int HOST_TYPE_PREFERENCE = 126;

    /// Creates a candidate.
    ///
    /// @param foundation the foundation
    /// @param component  the component id
    /// @param transport  the transport
    /// @param priority   the candidate priority
    /// @param host       the address as written
    /// @param port       the port
    /// @param type       the candidate type
    /// @throws IllegalArgumentException if `port` is outside `0..65535`
    public IceCandidate {
        Objects.requireNonNull(foundation, "foundation cannot be null");
        transport = Objects.requireNonNull(transport, "transport cannot be null").toLowerCase(Locale.ROOT);
        Objects.requireNonNull(host, "host cannot be null");
        Objects.requireNonNull(type, "type cannot be null");
        if (port < 0 || port > 0xFFFF) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
    }

    /// Parses the value of an `a=candidate` attribute.
    ///
    /// @param value the text after `a=candidate:`; a leading `candidate:`, as a trickled candidate carries it, is
    ///              accepted too
    /// @return the candidate
    /// @throws IllegalArgumentException if the value has fewer than eight tokens, its seventh token is not `typ`, or
    ///                                  a number is malformed
    public static IceCandidate parse(String value) {
        Objects.requireNonNull(value, "value cannot be null");
        var text = value.trim();
        if (text.startsWith("candidate:")) {
            text = text.substring("candidate:".length());
        }
        var tokens = text.split(" +");
        if (tokens.length < 8 || !tokens[6].equals("typ")) {
            throw new IllegalArgumentException("malformed candidate: " + value);
        }
        try {
            return new IceCandidate(tokens[0], Integer.parseInt(tokens[1]), tokens[2], Long.parseLong(tokens[3]),
                    tokens[4], Integer.parseInt(tokens[5]), tokens[7]);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("malformed candidate: " + value, exception);
        }
    }

    /// {@return a UDP host candidate for component `1`, with the priority RFC 8445 section 5.1.2 gives it}
    ///
    /// @param foundation      the foundation
    /// @param address         the local address and port; it must be resolved
    /// @param localPreference the local preference, `0..65535`, higher for a preferred interface
    /// @throws NullPointerException if `address` is unresolved
    public static IceCandidate host(String foundation, InetSocketAddress address, int localPreference) {
        return new IceCandidate(foundation, 1, "udp", priority(HOST_TYPE_PREFERENCE, localPreference, 1),
                address.getAddress().getHostAddress(), address.getPort(), "host");
    }

    /// {@return the priority of a candidate, `2^24 * typePreference + 2^8 * localPreference + (256 - component)`}
    ///
    /// @param typePreference  the type preference, `0..126`
    /// @param localPreference the local preference, `0..65535`
    /// @param component       the component id, `1..256`
    /// @spec https://www.rfc-editor.org/rfc/rfc8445.html RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
    public static long priority(int typePreference, int localPreference, int component) {
        return ((long) typePreference << 24) + ((long) localPreference << 8) + (256 - component);
    }

    /// {@return the priority a peer-reflexive candidate of component `1` gets, which is what the `PRIORITY` attribute
    /// of a check carries (RFC 8445 section 7.1.1)}
    ///
    /// @param localPreference the local preference, `0..65535`
    public static long peerReflexivePriority(int localPreference) {
        return priority(110, localPreference, 1);
    }

    /// {@return the socket address of the candidate, unresolved when [#host()] is not an IP literal and cannot be
    /// resolved}
    ///
    /// This method may perform a blocking name lookup when [#host()] is a hostname.
    public InetSocketAddress address() {
        return new InetSocketAddress(host, port);
    }

    /// {@return the `a=candidate` value of the candidate, `<foundation> <component> <transport> <priority> <host>
    /// <port> typ <type>`}
    public String value() {
        return foundation + " " + component + " " + transport + " " + priority + " " + host + " " + port + " typ " + type;
    }
}
