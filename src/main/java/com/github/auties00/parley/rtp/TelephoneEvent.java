package com.github.auties00.parley.rtp;

import java.util.Optional;

/// One `telephone-event` payload: a DTMF event, its end flag, its volume and its duration so far.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A sender repeats the payload for as long as the event lasts, every packet carrying the RTP timestamp of the
/// event's start and the duration so far, and sets the end flag on the last ones.
///
/// @param event    the event code: `0..9` for the digits, `10` for `*`, `11` for `#`, `12..15` for `A..D`; codes
///                 above `15` name the other tones of the RFC 4733 registry
/// @param end      whether this is a final packet of the event
/// @param volume   the power level in -dBm0, `0..63`; only the low six bits are encoded
/// @param duration the duration so far, in units of the payload format's clock; values above `65535` are encoded
///                 as `65535`
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
public record TelephoneEvent(int event, boolean end, int volume, int duration) {
    /// The characters of events `0..15`.
    private static final String SYMBOLS = "0123456789*#ABCD";

    /// {@return the event code of a DTMF character, or an empty optional for any other character}
    ///
    /// @param symbol a digit, `*`, `#`, or a letter `A..D` in either case
    public static Optional<Integer> eventOf(char symbol) {
        var index = SYMBOLS.indexOf(Character.toUpperCase(symbol));
        return index < 0 ? Optional.empty() : Optional.of(index);
    }

    /// Decodes a payload.
    ///
    /// @param payload the RTP payload; bytes after the first four are ignored
    /// @return the event
    /// @throws IllegalArgumentException if the payload is shorter than four bytes
    public static TelephoneEvent decode(byte[] payload) {
        if (payload.length < 4) {
            throw new IllegalArgumentException("telephone-event payload too short");
        }
        return new TelephoneEvent(payload[0] & 0xFF, (payload[1] & 0x80) != 0, payload[1] & 0x3F,
                (payload[2] & 0xFF) << 8 | (payload[3] & 0xFF));
    }

    /// {@return the DTMF character of the event, or an empty optional for an event outside `0..15`}
    public Optional<Character> symbol() {
        return event >= 0 && event < SYMBOLS.length() ? Optional.of(SYMBOLS.charAt(event)) : Optional.empty();
    }

    /// {@return the four-byte payload of the event}
    public byte[] encode() {
        var clamped = Math.min(duration, 0xFFFF);
        return new byte[]{
                (byte) event,
                (byte) ((end ? 0x80 : 0) | (volume & 0x3F)),
                (byte) (clamped >>> 8),
                (byte) clamped
        };
    }
}
