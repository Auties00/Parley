package com.github.auties00.parley.stun;

/// Signals that a STUN client transaction ended without a response: every retransmission went unanswered.
///
/// @see StunClientTransactions
public final class StunTimeoutException extends StunException {
    /// Creates the exception.
    ///
    /// @param message the detail message
    public StunTimeoutException(String message) {
        super(message);
    }
}
