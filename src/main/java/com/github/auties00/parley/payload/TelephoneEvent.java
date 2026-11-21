package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/// One event block of a `telephone-event` payload: an event code, its end flag, its volume and its duration so far.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A sender repeats the block for as long as the event lasts, every packet carrying the RTP timestamp of the event's
/// start and the duration so far, and sets the end flag on the last ones; [DtmfToneSequence] produces that schedule.
///
/// @param event    the event code, `0..255`: `0..9` for the digits, `10` for `*`, `11` for `#`, `12..15` for `A..D`,
///                 `16` for a hook flash, higher codes for the other tones of the RFC 4733 registry
/// @param end      whether this is a final packet of the event
/// @param volume   the power level in -dBm0, `0..63`
/// @param duration the duration so far, in units of the payload format's clock, `0..65535`
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
public record TelephoneEvent(int event, boolean end, int volume, int duration) {
    /// The size of one event block.
    public static final int SIZE = 4;

    /// The event code of a hook flash.
    public static final int FLASH = 16;

    /// The characters of events `0..15`.
    private static final String SYMBOLS = "0123456789*#ABCD";

    /// Creates an event block.
    ///
    /// @param event    the event code
    /// @param end      the end flag
    /// @param volume   the volume
    /// @param duration the duration so far
    /// @throws IllegalArgumentException if a value is outside its range
    public TelephoneEvent {
        if (event < 0 || event > 255) {
            throw new IllegalArgumentException("event out of range: " + event);
        }
        if (volume < 0 || volume > 63) {
            throw new IllegalArgumentException("volume out of range: " + volume);
        }
        if (duration < 0 || duration > 0xFFFF) {
            throw new IllegalArgumentException("duration out of range: " + duration);
        }
    }

    /// {@return the event code of a DTMF character, or an empty optional for any other character}
    ///
    /// @param symbol a digit, `*`, `#`, or a letter `A..D` in either case
    public static OptionalInt eventOf(char symbol) {
        var index = SYMBOLS.indexOf(Character.toUpperCase(symbol));
        return index < 0 ? OptionalInt.empty() : OptionalInt.of(index);
    }

    /// Parses the first event block of a payload.
    ///
    /// @param payload the payload, from position to limit; its position does not change, and bytes after the first
    ///                block are ignored
    /// @return the event
    /// @throws PayloadFormatException if the payload is shorter than one block
    public static TelephoneEvent parse(ByteBuffer payload) throws PayloadFormatException {
        if (payload.remaining() < SIZE) {
            throw new PayloadFormatException("telephone-event payload shorter than " + SIZE + " bytes");
        }
        return read(payload, payload.position());
    }

    /// Parses every event block of a payload, which RFC 4733 lets a sender pack several of.
    ///
    /// @param payload the payload, from position to limit; its position does not change
    /// @return the events, in order
    /// @throws PayloadFormatException if the payload is empty or not a whole number of blocks
    /// @spec https://www.rfc-editor.org/rfc/rfc4733.html#section-2.5.1.5 RFC 4733 section 2.5.1.5: Packing Multiple Events into One Packet
    public static List<TelephoneEvent> parseAll(ByteBuffer payload) throws PayloadFormatException {
        if (!payload.hasRemaining() || payload.remaining() % SIZE != 0) {
            throw new PayloadFormatException("telephone-event payload is not a whole number of blocks");
        }
        var result = new ArrayList<TelephoneEvent>(payload.remaining() / SIZE);
        for (var offset = payload.position(); offset < payload.limit(); offset += SIZE) {
            result.add(read(payload, offset));
        }
        return List.copyOf(result);
    }

    /// {@return the block at an absolute offset}
    private static TelephoneEvent read(ByteBuffer payload, int offset) {
        return new TelephoneEvent(payload.get(offset) & 0xFF, (payload.get(offset + 1) & 0x80) != 0,
                payload.get(offset + 1) & 0x3F, (payload.getShort(offset + 2) & 0xFFFF));
    }

    /// {@return the DTMF character of the event, or an empty optional for an event outside `0..15`}
    public Optional<Character> symbol() {
        return event < SYMBOLS.length() ? Optional.of(SYMBOLS.charAt(event)) : Optional.empty();
    }

    /// Writes the block at the position of a buffer, advancing it by {@value #SIZE}.
    ///
    /// @param destination the buffer
    /// @throws java.nio.BufferOverflowException if fewer than {@value #SIZE} bytes remain
    /// @throws java.nio.ReadOnlyBufferException if the buffer is read-only
    public void writeTo(ByteBuffer destination) {
        destination.put((byte) event)
                .put((byte) ((end ? 0x80 : 0) | volume))
                .putShort((short) duration);
    }

    /// {@return the block as a new buffer of {@value #SIZE} bytes, positioned at zero}
    public ByteBuffer toBuffer() {
        var buffer = ByteBuffer.allocate(SIZE);
        writeTo(buffer);
        return buffer.flip();
    }
}
