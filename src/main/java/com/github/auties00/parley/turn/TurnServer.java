package com.github.auties00.parley.turn;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Locale;
import java.util.Objects;

/// A TURN server named by a `turn:` or `turns:` URI.
///
/// ```text
/// turn:turn.example.org                     UDP, port 3478
/// turn:turn.example.org:3479?transport=tcp  TCP
/// turns:turn.example.org                    TLS over TCP, port 5349
/// turns:[2001:db8::1]:443?transport=tcp     TLS, IPv6 literal
/// ```
///
/// `turns:` with `?transport=udp` (TURN over DTLS) is not supported.
///
/// @param host      the host name or IP literal, without brackets; also the name a TLS certificate must match
/// @param port      the port, `1..65535`
/// @param transport the transport to the server
/// @spec https://www.rfc-editor.org/rfc/rfc7065.html RFC 7065: Traversal Using Relays around NAT (TURN) Uniform Resource Identifiers
public record TurnServer(String host, int port, TurnTransport transport) {
    /// The default port of `turn:`.
    public static final int DEFAULT_PORT = 3478;

    /// The default port of `turns:`.
    public static final int DEFAULT_SECURE_PORT = 5349;

    /// Creates a server.
    ///
    /// @param host      the host name or IP literal
    /// @param port      the port
    /// @param transport the transport
    /// @throws IllegalArgumentException if `host` is empty or `port` is outside `1..65535`
    public TurnServer {
        Objects.requireNonNull(host, "host cannot be null");
        Objects.requireNonNull(transport, "transport cannot be null");
        if (host.isEmpty() || port < 1 || port > 0xFFFF) {
            throw new IllegalArgumentException("invalid TURN server " + host + ":" + port);
        }
    }

    /// Parses a `turn:` or `turns:` URI.
    ///
    /// @param uri the URI
    /// @return the server
    /// @throws IllegalArgumentException if the scheme is not `turn` or `turns`, the host, port or query is malformed,
    ///                                  or the URI asks for TURN over DTLS
    public static TurnServer parse(URI uri) {
        Objects.requireNonNull(uri, "uri cannot be null");
        var scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        var secure = switch (scheme) {
            case "turn" -> false;
            case "turns" -> true;
            default -> throw new IllegalArgumentException("not a turn: or turns: URI: " + uri);
        };
        var part = uri.getRawSchemeSpecificPart();
        if (part == null || part.isEmpty() || part.contains("/")) {
            throw new IllegalArgumentException("malformed TURN URI: " + uri);
        }
        var query = "";
        var question = part.indexOf('?');
        if (question >= 0) {
            query = part.substring(question + 1);
            part = part.substring(0, question);
        }
        var transportName = secure ? "tcp" : "udp";
        if (!query.isEmpty()) {
            var equals = query.indexOf('=');
            if (equals < 0 || !query.substring(0, equals).equalsIgnoreCase("transport") || query.contains("&")) {
                throw new IllegalArgumentException("malformed TURN URI query: " + uri);
            }
            transportName = query.substring(equals + 1).toLowerCase(Locale.ROOT);
        }
        var transport = switch (transportName) {
            case "udp" -> {
                if (secure) {
                    throw new IllegalArgumentException("TURN over DTLS is not supported: " + uri);
                }
                yield TurnTransport.UDP;
            }
            case "tcp" -> secure ? TurnTransport.TLS : TurnTransport.TCP;
            default -> throw new IllegalArgumentException("unknown TURN transport " + transportName + ": " + uri);
        };
        String host;
        String rest;
        if (part.startsWith("[")) {
            var close = part.indexOf(']');
            if (close < 0) {
                throw new IllegalArgumentException("unterminated IPv6 literal: " + uri);
            }
            host = part.substring(1, close);
            rest = part.substring(close + 1);
        } else {
            var colon = part.indexOf(':');
            host = colon < 0 ? part : part.substring(0, colon);
            rest = colon < 0 ? "" : part.substring(colon);
        }
        var port = secure ? DEFAULT_SECURE_PORT : DEFAULT_PORT;
        if (!rest.isEmpty()) {
            if (!rest.startsWith(":") || rest.length() == 1) {
                throw new IllegalArgumentException("malformed port: " + uri);
            }
            try {
                port = Integer.parseInt(rest.substring(1));
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("malformed port: " + uri, exception);
            }
        }
        return new TurnServer(host, port, transport);
    }

    /// {@return the address of the server, unresolved, for a [com.github.auties00.parley.net.NetworkStack] to
    /// resolve}
    public InetSocketAddress unresolvedAddress() {
        return InetSocketAddress.createUnresolved(host, port);
    }

    /// {@return the server as a URI}
    public URI toUri() {
        var formatted = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        return switch (transport) {
            case UDP -> URI.create("turn:" + formatted + ":" + port);
            case TCP -> URI.create("turn:" + formatted + ":" + port + "?transport=tcp");
            case TLS -> URI.create("turns:" + formatted + ":" + port + "?transport=tcp");
        };
    }
}
