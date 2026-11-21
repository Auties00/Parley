/// Provides [StunMessage], the STUN message format of RFC 8489 with the attributes Interactive Connectivity
/// Establishment uses, the short-term credential `MESSAGE-INTEGRITY` and the `FINGERPRINT` that tells STUN apart
/// from other protocols sharing a port.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
package com.github.auties00.parley.stun;
