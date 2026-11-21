package com.github.auties00.parley.dtls;

/// The anti-replay window of one read epoch: a 64-record sliding bitmap whose right edge is the highest sequence
/// number authenticated so far.
///
/// [#isFresh(long)] is checked after a record authenticates and [#mark(long)] records it, so a forged record never
/// moves the window.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html#section-4.1.2.6 RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc4303.html#section-3.4.3 RFC 4303: IP Encapsulating Security Payload (ESP)
final class ReplayWindow {
    /// The window width in records.
    static final int WIDTH = 64;

    /// The highest sequence number marked, or `-1` before any.
    private long highest = -1;

    /// Bit `i` is set when `highest - i` was marked.
    private long bitmap;

    /// {@return whether a sequence number was not marked yet and is not left of the window}
    ///
    /// @param sequence the sequence number
    boolean isFresh(long sequence) {
        if (sequence > highest) {
            return true;
        }
        var offset = highest - sequence;
        return offset < WIDTH && (bitmap & (1L << offset)) == 0;
    }

    /// Marks a sequence number as received, sliding the window when it is the new highest.
    ///
    /// @param sequence the sequence number
    void mark(long sequence) {
        if (sequence > highest) {
            var shift = sequence - highest;
            bitmap = shift >= WIDTH ? 1 : (bitmap << shift) | 1;
            highest = sequence;
        } else {
            var offset = highest - sequence;
            if (offset < WIDTH) {
                bitmap |= 1L << offset;
            }
        }
    }

    /// {@return the highest sequence number marked, or `-1` before any}
    long highest() {
        return highest;
    }
}
