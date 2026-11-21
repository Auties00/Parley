package com.github.auties00.parley.stun;

/// The class of a STUN message, the two class bits interleaved in its message type.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8489.html RFC 8489: Session Traversal Utilities for NAT (STUN)
public enum StunClass {
    /// A request, which expects a success or error response with the same transaction id.
    REQUEST(0b00),

    /// An indication, which expects no response.
    INDICATION(0b01),

    /// A success response.
    SUCCESS_RESPONSE(0b10),

    /// An error response, which carries an `ERROR-CODE` attribute.
    ERROR_RESPONSE(0b11);

    /// The two class bits, `C1` then `C0`.
    private final int bits;

    /// Creates a class.
    StunClass(int bits) {
        this.bits = bits;
    }

    /// {@return the two class bits, `C1` in bit 1 and `C0` in bit 0}
    public int bits() {
        return bits;
    }

    /// {@return whether this class is a success or an error response}
    public boolean isResponse() {
        return this == SUCCESS_RESPONSE || this == ERROR_RESPONSE;
    }

    /// {@return the class whose bits are `bits`}
    ///
    /// @param bits the two class bits, `0..3`
    /// @throws IllegalArgumentException if `bits` is outside `0..3`
    public static StunClass ofBits(int bits) {
        return switch (bits) {
            case 0b00 -> REQUEST;
            case 0b01 -> INDICATION;
            case 0b10 -> SUCCESS_RESPONSE;
            case 0b11 -> ERROR_RESPONSE;
            default -> throw new IllegalArgumentException("class bits out of range: " + bits);
        };
    }
}
