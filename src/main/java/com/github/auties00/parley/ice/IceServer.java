package com.github.auties00.parley.ice;

import com.github.auties00.parley.stun.StunServer;
import com.github.auties00.parley.turn.TurnCredentials;
import com.github.auties00.parley.turn.TurnServer;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/// A STUN or TURN server an ICE agent gathers candidates from, as the W3C `RTCIceServer` describes it.
///
/// Every URL of one server shares the credentials. `stun:` URLs yield server-reflexive candidates and `turn:` and
/// `turns:` URLs relayed candidates; `stuns:` URLs are accepted but not used, since a TLS mapping gives no UDP
/// candidate. [#toString()] leaves the credential out.
///
/// {@snippet lang = java :
/// var servers = List.of(
///         IceServer.of("stun:stun.example.org"),
///         IceServer.of("turns:turn.example.org:443?transport=tcp", "user", "secret"));
/// }
///
/// @param urls       the `stun:`, `stuns:`, `turn:` and `turns:` URLs, at least one
/// @param username   the TURN username, required by `turn:` and `turns:` URLs
/// @param credential the TURN password
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc7064.html RFC 7064: URI Scheme for the Session Traversal Utilities for NAT (STUN) Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc7065.html RFC 7065: Traversal Using Relays around NAT (TURN) Uniform Resource Identifiers
public record IceServer(List<URI> urls, Optional<String> username, Optional<String> credential) {
    /// Creates a server, validating every URL.
    ///
    /// @param urls       the URLs, copied
    /// @param username   the TURN username
    /// @param credential the TURN password
    /// @throws IllegalArgumentException if `urls` is empty, a URL has another scheme or is malformed, or a TURN URL
    ///                                  lacks a username or credential
    public IceServer {
        urls = List.copyOf(urls);
        Objects.requireNonNull(username, "username cannot be null");
        Objects.requireNonNull(credential, "credential cannot be null");
        if (urls.isEmpty()) {
            throw new IllegalArgumentException("an ICE server needs at least one URL");
        }
        for (var url : urls) {
            switch (scheme(url)) {
                case "stun", "stuns" -> StunServer.parse(url);
                case "turn", "turns" -> {
                    TurnServer.parse(url);
                    if (username.isEmpty() || credential.isEmpty()) {
                        throw new IllegalArgumentException("a TURN URL needs a username and a credential: " + url);
                    }
                }
                default -> throw new IllegalArgumentException("not a STUN or TURN URL: " + url);
            }
        }
    }

    /// {@return a server without credentials, typically a STUN server}
    ///
    /// @param url the URL
    /// @throws IllegalArgumentException if the URL is malformed or is a TURN URL
    public static IceServer of(String url) {
        return new IceServer(List.of(URI.create(url)), Optional.empty(), Optional.empty());
    }

    /// {@return a server with credentials, typically a TURN server}
    ///
    /// @param url        the URL
    /// @param username   the username
    /// @param credential the password
    /// @throws IllegalArgumentException if the URL is malformed
    public static IceServer of(String url, String username, String credential) {
        return new IceServer(List.of(URI.create(url)), Optional.of(username), Optional.of(credential));
    }

    /// {@return the STUN servers among the URLs, `stun:` ones only}
    public List<StunServer> stunServers() {
        return urls.stream()
                .filter(url -> scheme(url).equals("stun"))
                .map(StunServer::parse)
                .toList();
    }

    /// {@return the TURN servers among the URLs}
    public List<TurnServer> turnServers() {
        return urls.stream()
                .filter(url -> scheme(url).startsWith("turn"))
                .map(TurnServer::parse)
                .toList();
    }

    /// {@return the TURN credentials, or an empty optional when the server has none}
    public Optional<TurnCredentials> turnCredentials() {
        if (username.isEmpty() || credential.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new TurnCredentials(username.get(), credential.get()));
    }

    /// {@return the lower-cased scheme of a URL, or an empty string}
    private static String scheme(URI url) {
        return url.getScheme() == null ? "" : url.getScheme().toLowerCase(Locale.ROOT);
    }

    /// {@return the URLs and the username, without the credential}
    @Override
    public String toString() {
        return "IceServer[urls=" + urls + ", username=" + username.orElse("") + "]";
    }
}
