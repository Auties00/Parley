package com.github.auties00.parley.dtls;

import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/// Rebuilds handshake messages from DTLS fragments and releases them in message sequence order.
///
/// Fragments may overlap, repeat and arrive in any order; a message is released once every byte of it arrived and
/// every earlier message was released. Messages before the next expected one are reported as old, so the caller can
/// treat them as a retransmission by the peer; messages too far ahead are dropped rather than buffered.
///
/// Instances are not thread-safe.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
final class HandshakeReassembler {
    /// The largest handshake message accepted, which bounds the memory a peer can make this side hold.
    static final int MAX_MESSAGE_LENGTH = 1 << 17;

    /// How many messages beyond the next expected one are buffered.
    static final int MAX_LOOKAHEAD = 16;

    /// The partial messages, by message sequence number.
    private final Map<Integer, Partial> partials = new HashMap<>();

    /// The next message sequence number to release.
    private int nextReceiveSeq;

    /// What happened to an offered fragment.
    enum Result {
        /// The fragment belongs to the next expected message or a buffered later one.
        ACCEPTED,

        /// The fragment belongs to an already released message.
        OLD,

        /// The fragment was dropped: too far ahead, or inconsistent with earlier fragments.
        DROPPED
    }

    /// {@return the next message sequence number to release}
    int nextReceiveSeq() {
        return nextReceiveSeq;
    }

    /// Sets the next message sequence number, dropping every buffered fragment before it.
    ///
    /// @param messageSeq the number
    void expect(int messageSeq) {
        nextReceiveSeq = messageSeq;
        partials.keySet().removeIf(seq -> seq < messageSeq);
    }

    /// Offers one fragment.
    ///
    /// @param type           the handshake type
    /// @param length         the full message length
    /// @param messageSeq     the message sequence number
    /// @param fragmentOffset the fragment offset
    /// @param fragment       the fragment bytes
    /// @param epoch          the epoch of the record that carried the fragment; a fragment in a higher epoch than
    ///                       those buffered for its message replaces them, one in a lower epoch is dropped
    /// @return what happened to the fragment
    /// @throws DtlsException if the fragment is malformed or the message exceeds [#MAX_MESSAGE_LENGTH]
    Result offer(int type, int length, int messageSeq, int fragmentOffset, byte[] fragment, long epoch)
            throws DtlsException {
        if (length > MAX_MESSAGE_LENGTH) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "handshake message of " + length + " bytes");
        }
        if (fragmentOffset + fragment.length > length) {
            throw new DtlsException(DtlsAlert.DECODE_ERROR, "handshake fragment beyond its message");
        }
        if (messageSeq < nextReceiveSeq) {
            return Result.OLD;
        }
        if (messageSeq >= nextReceiveSeq + MAX_LOOKAHEAD) {
            return Result.DROPPED;
        }
        var partial = partials.get(messageSeq);
        if (partial != null && partial.epoch < epoch) {
            partial = null;
        }
        if (partial == null) {
            partial = new Partial(type, length, epoch);
            partials.put(messageSeq, partial);
        } else if (partial.type != type || partial.body.length != length || partial.epoch != epoch) {
            return Result.DROPPED;
        }
        partial.add(fragmentOffset, fragment);
        return Result.ACCEPTED;
    }

    /// {@return the next complete message in order, removing it, or an empty optional when it is not complete yet}
    Optional<Received> poll() {
        var partial = partials.get(nextReceiveSeq);
        if (partial == null || !partial.complete()) {
            return Optional.empty();
        }
        partials.remove(nextReceiveSeq);
        return Optional.of(new Received(new HandshakeMessage(partial.type, nextReceiveSeq++, partial.body), partial.epoch));
    }

    /// A released message with the epoch its fragments arrived in.
    ///
    /// @param message the message
    /// @param epoch   the epoch
    record Received(HandshakeMessage message, long epoch) {
    }

    /// {@return whether a fragment of the next expected message, or of a later one, is buffered}
    boolean hasPending() {
        return !partials.isEmpty();
    }

    /// A message being reassembled.
    private static final class Partial {
        /// The handshake type.
        private final int type;

        /// The epoch of the fragments.
        private final long epoch;

        /// The body being filled.
        private final byte[] body;

        /// Which body bytes have arrived.
        private final BitSet received;

        /// Creates an empty partial message.
        private Partial(int type, int length, long epoch) {
            this.type = type;
            this.epoch = epoch;
            this.body = new byte[length];
            this.received = new BitSet(length);
        }

        /// Copies a fragment into place; overlapping bytes are overwritten with the same values a correct peer sends.
        private void add(int offset, byte[] fragment) {
            System.arraycopy(fragment, 0, body, offset, fragment.length);
            received.set(offset, offset + fragment.length);
        }

        /// {@return whether every byte arrived}
        private boolean complete() {
            return received.cardinality() == body.length;
        }

        /// {@return a description for debugging}
        @Override
        public String toString() {
            return "Partial[type=" + type + ", received=" + received.cardinality() + "/" + body.length + ", head="
                    + Arrays.toString(Arrays.copyOf(body, Math.min(4, body.length))) + "]";
        }
    }
}
