package com.github.auties00.parley.stun;

/// Signals that a STUN client transaction received responses but none was authentic: their message integrity did
/// not verify under the request's key.
///
/// Over an unreliable transport the transaction keeps retransmitting after a bad response and raises this exception
/// only when it ends without an authentic one; over a reliable transport it raises it at the first bad response, as
/// RFC 8489 section 9.2.5 requires.
///
/// @see StunClientTransactions
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public final class StunIntegrityException extends StunException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public StunIntegrityException(String message) {
        super(message);
    }
}
