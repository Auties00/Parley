package com.github.auties00.parley.stun;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Locale;
import java.util.Objects;

/// A STUN server named by a `stun:` or `stuns:` URI.
///
/// ```text
/// stun:stun.example.org          host, default port 3478
/// stun:192.0.2.1:19302           IPv4 literal and port
/// stun:[2001:db8::1]:3478        IPv6 literal in brackets
/// stuns:stun.example.org         STUN over TLS, default port 5349
/// ```
///
/// @param host   the host name or IP literal, without brackets
/// @param port   the port, `1..65535`
/// @param secure whether the URI is `stuns:`, STUN over TLS
/// @spec https://www.rfc-editor.org/rfc/rfc7064.html RFC 7064: URI Scheme for the Session Traversal Utilities for NAT (STUN) Protocol
public record StunServer(String host, int port, boolean secure) {
    /// The default port of `stun:`.
    public static final int DEFAULT_PORT = 3478;

    /// The default port of `stuns:`.
    public static final int DEFAULT_SECURE_PORT = 5349;

    /// Creates a server.
    ///
    /// @param host   the host name or IP literal
    /// @param port   the port
    /// @param secure whether the server speaks TLS
    /// @throws IllegalArgumentException if `host` is empty or `port` is outside `1..65535`
    public StunServer {
        Objects.requireNonNull(host, "host cannot be null");
        if (host.isEmpty() || port < 1 || port > 0xFFFF) {
            throw new IllegalArgumentException("invalid STUN server " + host + ":" + port);
        }
    }

    /// Parses a `stun:` or `stuns:` URI.
    ///
    /// @param uri the URI
    /// @return the server
    /// @throws IllegalArgumentException if the scheme is not `stun` or `stuns`, or the host or port is malformed
    public static StunServer parse(URI uri) {
        Objects.requireNonNull(uri, "uri cannot be null");
        var scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        var secure = switch (scheme) {
            case "stun" -> false;
            case "stuns" -> true;
            default -> throw new IllegalArgumentException("not a stun: or stuns: URI: " + uri);
        };
        var part = uri.getRawSchemeSpecificPart();
        if (part == null || part.contains("?") || part.contains("/")) {
            throw new IllegalArgumentException("malformed STUN URI: " + uri);
        }
        var hostPort = HostPort.parse(part, secure ? DEFAULT_SECURE_PORT : DEFAULT_PORT);
        return new StunServer(hostPort.host(), hostPort.port(), secure);
    }

    /// {@return the address of the server, unresolved, for a [com.github.auties00.parley.net.NetworkStack] to resolve}
    public InetSocketAddress unresolvedAddress() {
        return InetSocketAddress.createUnresolved(host, port);
    }

    /// {@return the server as a URI, with brackets around an IPv6 literal}
    public URI toUri() {
        return URI.create((secure ? "stuns:" : "stun:") + HostPort.format(host) + ":" + port);
    }

    /// A host and port parsed from the scheme-specific part of a STUN or TURN URI.
    ///
    /// @param host the host, without brackets
    /// @param port the port
    record HostPort(String host, int port) {
        /// Parses `host[:port]` or `[ipv6][:port]`.
        ///
        /// @throws IllegalArgumentException if the text is malformed
        static HostPort parse(String text, int defaultPort) {
            String host;
            String rest;
            if (text.startsWith("[")) {
                var close = text.indexOf(']');
                if (close < 0) {
                    throw new IllegalArgumentException("unterminated IPv6 literal: " + text);
                }
                host = text.substring(1, close);
                rest = text.substring(close + 1);
            } else {
                var colon = text.indexOf(':');
                host = colon < 0 ? text : text.substring(0, colon);
                rest = colon < 0 ? "" : text.substring(colon);
            }
            if (host.isEmpty()) {
                throw new IllegalArgumentException("empty host: " + text);
            }
            var port = defaultPort;
            if (!rest.isEmpty()) {
                if (!rest.startsWith(":") || rest.length() == 1) {
                    throw new IllegalArgumentException("malformed port: " + text);
                }
                try {
                    port = Integer.parseInt(rest.substring(1));
                } catch (NumberFormatException exception) {
                    throw new IllegalArgumentException("malformed port: " + text, exception);
                }
            }
            if (port < 1 || port > 0xFFFF) {
                throw new IllegalArgumentException("port out of range: " + text);
            }
            return new HostPort(host, port);
        }

        /// {@return `host` with brackets when it is an IPv6 literal}
        static String format(String host) {
            return host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        }
    }
}
