/// Provides a TURN client: [TurnClient] connects to a [TurnServer] over UDP, TCP or TLS and creates a
/// [TurnAllocation], a relayed transport address that peers reach through the server.
///
/// The client authenticates with the long-term credential mechanism of STUN (including the SHA-256 password
/// algorithm and username anonymity of RFC 8489), keeps the allocation, its permissions and its channel bindings
/// alive, and relays data with Send and Data indications or ChannelData. It opens its connection through a
/// [com.github.auties00.parley.net.NetworkStack], so an application can route TURN over TCP or TLS through its own
/// proxy. TURN over DTLS (RFC 7350) and TCP allocations (RFC 6062) are not supported.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8656.html RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc7065.html RFC 7065: Traversal Using Relays around NAT (TURN) Uniform Resource Identifiers
package com.github.auties00.parley.turn;
