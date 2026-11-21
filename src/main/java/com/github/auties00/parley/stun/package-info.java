/// Provides the STUN protocol of RFC 8489: the [StunMessage] codec with its [StunAttribute] hierarchy, the
/// short-term and long-term [StunKey]s that sign message integrity, and the [StunClientTransactions] that retransmit
/// requests and match their responses.
///
/// The codec decodes without copying ([StunMessage#decode(java.nio.ByteBuffer)]) and covers the attributes of STUN,
/// of the long-term credential mechanism (`REALM`, `NONCE`, `PASSWORD-ALGORITHMS`, `USERHASH`), of ICE (`PRIORITY`,
/// `USE-CANDIDATE`, `ICE-CONTROLLING`, `ICE-CONTROLLED`) and of TURN, with `MESSAGE-INTEGRITY`,
/// `MESSAGE-INTEGRITY-SHA256` and `FINGERPRINT`. Unknown attributes are kept as [StunAttribute.Unknown], so a server
/// can report the comprehension-required ones.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
/// @spec https://www.rfc-editor.org/rfc/rfc5769.html RFC 5769: Test Vectors for Session Traversal Utilities for NAT (STUN)
package com.github.auties00.parley.stun;
