package com.github.auties00.parley.stun;

/// The message integrity attribute a message is signed with.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public enum StunIntegrity {
    /// `MESSAGE-INTEGRITY`, a 20-byte HMAC-SHA1, the one every STUN agent understands and ICE uses.
    HMAC_SHA1,

    /// `MESSAGE-INTEGRITY-SHA256`, a 32-byte HMAC-SHA256, which a long-term credential server asks for by offering
    /// `PASSWORD-ALGORITHMS`.
    HMAC_SHA256
}
